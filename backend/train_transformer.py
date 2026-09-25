"""Fine-tune a small transformer as the ML detector (Stage 2).

WHY FINE-TUNING, NOT FROZEN EMBEDDINGS
--------------------------------------
Frozen sentence embeddings (all-MiniLM-L6-v2 with a linear or MLP head) were
tried first and generalised worse than TF-IDF: trained on all public datasets
but one and scored on the one left out, mean AUC 0.84 against TF-IDF's 0.90.
A general-purpose embedding encodes what a sentence is about, not whether it
tries to override instructions. Fine-tuning the same network on the task
changes what it encodes.

WHAT THIS DOES
--------------
1. Loads exactly the rows train_detector.py trains on (collect_rows()).
2. Splits off 20% as a calibration set, grouped so generated variants of one
   question stay together.
3. Fine-tunes sentence-transformers/all-MiniLM-L6-v2 (22M parameters, mean
   pooling + a linear head) on the other 80%, on CPU.
4. Exports to ONNX and quantizes to int8 (~23 MB). Production runs that file
   with ONNX Runtime; PyTorch is needed only here.
5. Chooses the block threshold on the calibration set with the same rule as
   train_detector.py (per-source false-positive budget + zero in-domain false
   positives), using the int8 model's scores — the model that ships.
6. Averages it with a TF-IDF model trained on the same 80% (--no-ensemble
   to skip). On datasets left out of training entirely, the average caught
   more attacks at 1% false positives than either model alone (54% vs 50%
   fine-tuned, 36% TF-IDF), and TF-IDF's continuous scores keep the
   fine-tuned model's saturated ones from tying at the threshold.
7. Reports on every held-out and external evaluation set, and saves the
   bundle that ml_detector.py loads.

The shipped model is the one trained on 80%. Retraining on 100% would leave
the threshold calibrated for a different model.

Usage:
    pip install -r requirements-train.txt        # includes torch (CPU) + transformers
    python fetch_datasets.py
    python train_transformer.py                  # ~20-30 min on 4 CPU cores
    python train_transformer.py --no-ensemble    # fine-tuned model alone
    python train_transformer.py --reuse-model    # recalibrate, skip fine-tuning
    python train_transformer.py --epochs 1 --out /tmp/try.joblib
"""

import argparse
import json
import math
import os
import random
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import numpy as np
import sklearn
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

import train_detector as td
from transformer_classifier import (AveragedClassifier, MAX_LENGTH,
                                    TransformerClassifier, encode,
                                    load_tokenizer, pad_batch)

HERE = os.path.dirname(os.path.abspath(__file__))

BASE_REPO = "sentence-transformers/all-MiniLM-L6-v2"
BASE_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
BASE_LICENCE = "Apache-2.0"
MODEL_DIR = os.path.join("models", "transformer", "minilm-l6-ft")  # rel. to backend/

EPOCHS = 2
BATCH_SIZE = 32
LEARNING_RATE = 5e-5
WARMUP = 0.06
SEED = 20260925


def _torch_model():
    import torch
    from torch import nn
    from transformers import AutoModel

    class MeanPoolClassifier(nn.Module):
        """MiniLM encoder, mean pooling (as it was pre-trained), linear head."""

        def __init__(self):
            super().__init__()
            self.encoder = AutoModel.from_pretrained(BASE_REPO, revision=BASE_REVISION)
            self.dropout = nn.Dropout(0.1)
            self.head = nn.Linear(self.encoder.config.hidden_size, 2)

        def forward(self, input_ids, attention_mask):
            hidden = self.encoder(input_ids=input_ids,
                                  attention_mask=attention_mask).last_hidden_state
            mask = attention_mask.unsqueeze(-1).to(hidden.dtype)
            pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
            return self.head(self.dropout(pooled))

    return MeanPoolClassifier()


def _batches(seqs, labels, batch_size, pad_id, shuffle, rng):
    """Length-bucketed batches: similar lengths pad to similar widths."""
    import torch

    order = sorted(range(len(seqs)), key=lambda i: len(seqs[i]))
    chunks = [order[i:i + batch_size] for i in range(0, len(order), batch_size)]
    if shuffle:
        rng.shuffle(chunks)
    for idx in chunks:
        ids, mask = pad_batch([seqs[i] for i in idx], pad_id)
        y = torch.tensor([labels[i] for i in idx]) if labels is not None else None
        yield idx, torch.from_numpy(ids), torch.from_numpy(mask), y


def fine_tune(texts, labels, tokenizer, epochs):
    import torch
    from torch import nn

    torch.manual_seed(SEED)
    rng = random.Random(SEED)
    pad_id = tokenizer.token_to_id("[PAD]") or 0
    seqs = encode(tokenizer, texts, MAX_LENGTH)

    model = _torch_model()
    opt = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    steps = epochs * math.ceil(len(seqs) / BATCH_SIZE)
    warm = max(1, int(WARMUP * steps))
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / warm) * max(0.0, (steps - s) / max(1, steps - warm)))
    loss_fn = nn.CrossEntropyLoss()

    step, started = 0, time.perf_counter()
    for epoch in range(epochs):
        model.train()
        for _, ids, mask, y in _batches(seqs, labels, BATCH_SIZE, pad_id, True, rng):
            loss = loss_fn(model(ids, mask), y)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            step += 1
            if step % 200 == 0 or step == steps:
                rate = (time.perf_counter() - started) / step
                print(f"  epoch {epoch + 1}/{epochs}  step {step}/{steps}  "
                      f"loss {loss.item():.3f}  ~{rate * (steps - step) / 60:.0f} min left",
                      flush=True)
    model.eval()
    return model


def torch_scores(model, texts, tokenizer):
    import torch

    pad_id = tokenizer.token_to_id("[PAD]") or 0
    seqs = encode(tokenizer, texts, MAX_LENGTH)
    out = np.zeros(len(seqs))
    with torch.no_grad():
        for idx, ids, mask, _ in _batches(seqs, None, 64, pad_id, False, None):
            out[idx] = torch.softmax(model(ids, mask), -1)[:, 1].numpy()
    return out


def export_int8(model, out_dir, tokenizer_path):
    """ONNX export (fp32), then dynamic int8 quantization into out_dir."""
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic

    os.makedirs(out_dir, exist_ok=True)
    ids = torch.ones((2, 16), dtype=torch.long)
    mask = torch.ones((2, 16), dtype=torch.long)
    with tempfile.TemporaryDirectory() as tmp:
        fp32 = os.path.join(tmp, "model_fp32.onnx")
        torch.onnx.export(
            model, (ids, mask), fp32,
            input_names=["input_ids", "attention_mask"], output_names=["logits"],
            dynamic_axes={"input_ids": {0: "batch", 1: "seq"},
                          "attention_mask": {0: "batch", 1: "seq"},
                          "logits": {0: "batch"}},
            opset_version=17, dynamo=False)
        quantize_dynamic(fp32, os.path.join(out_dir, "model.onnx"),
                         weight_type=QuantType.QInt8)
    shutil.copyfile(tokenizer_path, os.path.join(out_dir, "tokenizer.json"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--epochs", type=int, default=EPOCHS)
    ap.add_argument("--no-ensemble", action="store_true",
                    help="ship the fine-tuned model alone, without TF-IDF")
    ap.add_argument("--reuse-model", action="store_true",
                    help="skip fine-tuning and reuse the ONNX model in "
                         "--model-dir (must come from the same split)")
    ap.add_argument("--target-fpr", type=float, default=td.DEFAULT_TARGET_FPR)
    ap.add_argument("--out", default=td.DEFAULT_OUT)
    ap.add_argument("--model-dir", default=MODEL_DIR,
                    help="where the ONNX model goes, relative to backend/")
    args = ap.parse_args()

    from huggingface_hub import hf_hub_download

    rows, external_eval = td.collect_rows()
    texts = [r["text"] for r in rows]
    labels = np.array([r["label"] for r in rows])
    sources = np.array([r.get("source", "unknown") for r in rows])
    groups = [r.get("group") or f"row:{i}" for i, r in enumerate(rows)]

    split = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=td.RANDOM_STATE)
    train_idx, cal_idx = next(split.split(texts, labels, groups))
    print(f"  split: {len(train_idx)} train / {len(cal_idx)} calibration "
          f"(grouped, stratified)")
    train_texts = [texts[i] for i in train_idx]
    cal_texts = [texts[i] for i in cal_idx]

    tokenizer_path = hf_hub_download(BASE_REPO, "tokenizer.json", revision=BASE_REVISION)
    tokenizer = load_tokenizer(tokenizer_path)

    out_dir = os.path.join(HERE, args.model_dir)
    config_path = os.path.join(out_dir, "config.json")
    transformer = TransformerClassifier(args.model_dir)
    if args.reuse_model:
        with open(config_path, encoding="utf-8") as fh:
            previous = json.load(fh)
        if previous.get("train_rows") != len(train_idx):
            raise SystemExit(f"--reuse-model: {args.model_dir} was trained on "
                             f"{previous.get('train_rows')} rows, this split has "
                             f"{len(train_idx)}. Retrain without --reuse-model.")
        args.epochs = previous["epochs"]
        size_mb = os.path.getsize(os.path.join(out_dir, "model.onnx")) / 1e6
        print(f"\nReusing {args.model_dir} ({size_mb:.1f} MB, "
              f"{args.epochs} epoch(s), trained {previous['trained_at']})")
    else:
        print(f"\nFine-tuning {BASE_REPO} ({args.epochs} epoch(s), CPU)")
        started = time.perf_counter()
        net = fine_tune(train_texts, labels[train_idx].tolist(), tokenizer, args.epochs)
        print(f"  trained in {(time.perf_counter() - started) / 60:.1f} min")

        print("\nExporting to ONNX (int8)")
        export_int8(net, out_dir, tokenizer_path)
        size_mb = os.path.getsize(os.path.join(out_dir, "model.onnx")) / 1e6
        print(f"  {args.model_dir}/model.onnx  {size_mb:.1f} MB")

        cal_torch = torch_scores(net, cal_texts, tokenizer)
        cal_onnx = transformer.predict_proba(cal_texts)[:, 1]
        print(f"  calibration AUC  torch fp32 {roc_auc_score(labels[cal_idx], cal_torch):.4f}"
              f"  |  onnx int8 {roc_auc_score(labels[cal_idx], cal_onnx):.4f}")
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump({"base_repo": BASE_REPO, "base_revision": BASE_REVISION,
                       "licence": BASE_LICENCE, "max_length": MAX_LENGTH,
                       "epochs": args.epochs, "train_rows": len(train_idx),
                       "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                      fh, indent=2)

    model, kind = transformer, "transformer"
    if not args.no_ensemble:
        print("\nTraining the TF-IDF member on the same split")
        tfidf = td.build_pipeline().fit(train_texts, labels[train_idx])
        model, kind = AveragedClassifier([tfidf, transformer]), "ensemble"

    cal_scores = model.predict_proba(cal_texts)[:, 1]
    threshold, detail = td.choose_threshold(
        cal_scores, labels[cal_idx], sources[cal_idx], args.target_fpr)
    print(f"\nCalibration ({kind}): AUC {roc_auc_score(labels[cal_idx], cal_scores):.4f}"
          f"   block threshold {threshold}")
    print(f"    FP budget {args.target_fpr:.1%} per source -> {detail['budget']:.3f}")
    print(f"    zero FP on in-domain benign -> {detail['in_domain_guard']:.3f}")
    cal_report = {}
    for source in sorted(set(sources[cal_idx])):
        m = sources[cal_idx] == source
        r = td._rates(cal_scores[m] >= threshold, labels[cal_idx][m])
        cal_report[source] = r
        print(f"    {source:<34} {int(m.sum()):>6}  {td._fmt(r)}")

    metrics = {"threshold": threshold, "threshold_detail": detail,
               "calibration": {"auc": float(roc_auc_score(labels[cal_idx], cal_scores)),
                               "per_source": cal_report}}
    metrics.update(td.report_all(model, threshold, external_eval))

    sample = ["How should we store API keys securely?"]
    model.predict_proba(sample)
    started = time.perf_counter()
    for _ in range(50):
        model.predict_proba(sample)
    per_call = (time.perf_counter() - started) / 50 * 1000
    print(f"\n  inference: {per_call:.1f} ms per single prompt")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({
        "pipeline": model,
        "kind": kind,
        "threshold": threshold,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_rows": len(train_idx),
        "sources": sorted(set(sources.tolist())),
        "metrics": metrics,
        "model_dir": args.model_dir,
        "sklearn_version": sklearn.__version__,
    }, args.out, compress=3)
    print(f"\nSaved {args.out} ({os.path.getsize(args.out) / 1e6:.2f} MB)"
          f" + {args.model_dir}/ ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
