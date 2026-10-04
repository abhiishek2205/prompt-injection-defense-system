"""Benchmark Meta's Llama Prompt Guard 2 against the shipped ML detector.

Prompt Guard 2 (22M English, 86M multilingual) is a classifier trained by Meta
to flag explicit prompt attacks. Before it gets a place in Layer 2 it has to
earn one on the same evidence as everything else here: the project's held-out
prompts and other datasets' test splits, never trained on.

For each evaluation set this prints AUC and recall / false positives for:

    ML        the shipped detector (models/detector.joblib) at its threshold
    PG@0.5    Prompt Guard at Meta's default cut-off
    PG@cal    Prompt Guard at a threshold calibrated like the ML tier's:
              train_detector.choose_threshold() on the benign *training* rows
              (at most 0.5% flagged per source; no test set involved)
    regex+PG  the pipeline if Prompt Guard could block next to the regex tier

READING IT FAIRLY
-----------------
The ML detector was trained on the training splits of deepset, jackhhao,
PromptShield, SLABS and Gandalf, so their test splits are in-distribution for
it and out-of-distribution for Prompt Guard. Prompt Guard may in turn have
seen some public sets in Meta's training. NotInject (benign prompts full of
trigger words) and the project's own held-out sets are the neutral ground.

Long prompts are split into 512-token segments (Meta's guidance); a prompt
scores as its highest segment. On CPU that is slow for big sets, so any
evaluation set or calibration source over --cap prompts is replaced by a fixed
random sample of that size (seed 0) — the same sample for every model and for
the ML column. Scores are cached per model in
data/prompt_guard_cache/ (gitignored), so a rerun is free.

Usage (the weights are gated: accept the licence on Hugging Face, then set
HF_TOKEN, or pass a local directory):
    python benchmark_prompt_guard.py --model meta-llama/Llama-Prompt-Guard-2-22M
    python benchmark_prompt_guard.py --model /path/to/Llama-Prompt-Guard-2-86M
"""

import argparse
import contextlib
import hashlib
import io
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import numpy as np

import train_detector as td

CACHE_DIR = os.path.join(HERE, "data", "prompt_guard_cache")
MAX_TOKENS = 512
MAX_SEGMENTS = 16            # 8k tokens; longer prompts keep head and tail
TARGET_FPR = td.DEFAULT_TARGET_FPR


class PromptGuard:
    """predict_proba() over Prompt Guard 2, with segmenting and a disk cache."""

    def __init__(self, model, batch_size=32, threads=None):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        if threads:
            torch.set_num_threads(threads)
        token = os.environ.get("HF_TOKEN")
        self.name = os.path.basename(model.rstrip("/"))
        self.tokenizer = AutoTokenizer.from_pretrained(model, token=token)
        self.model = AutoModelForSequenceClassification.from_pretrained(model, token=token).eval()
        self.batch_size = batch_size
        self.cache_path = os.path.join(CACHE_DIR, f"{self.name}.json")
        self.cache = {}
        if os.path.exists(self.cache_path):
            with open(self.cache_path) as fh:
                self.cache = json.load(fh)

    @staticmethod
    def _key(text):
        return hashlib.sha1(text.encode("utf-8", "surrogatepass")).hexdigest()

    def _segments(self, text):
        ids = self.tokenizer(text, add_special_tokens=False)["input_ids"] or [self.tokenizer.unk_token_id]
        room = MAX_TOKENS - 2
        chunks = [ids[i:i + room] for i in range(0, len(ids), room)]
        if len(chunks) > MAX_SEGMENTS:
            half = MAX_SEGMENTS // 2
            chunks = chunks[:half] + chunks[-half:]
        return chunks

    def _score_segments(self, segments):
        import torch

        cls, sep, pad = (self.tokenizer.cls_token_id, self.tokenizer.sep_token_id,
                         self.tokenizer.pad_token_id)
        order = sorted(range(len(segments)), key=lambda i: len(segments[i]))
        out = np.zeros(len(segments))
        for start in range(0, len(order), self.batch_size):
            idx = order[start:start + self.batch_size]
            seqs = [[cls] + segments[i] + [sep] for i in idx]
            width = max(map(len, seqs))
            ids = torch.full((len(seqs), width), pad, dtype=torch.long)
            mask = torch.zeros((len(seqs), width), dtype=torch.long)
            for row, seq in enumerate(seqs):
                ids[row, :len(seq)] = torch.tensor(seq)
                mask[row, :len(seq)] = 1
            with torch.inference_mode():
                logits = self.model(input_ids=ids, attention_mask=mask).logits.double()
            out[idx] = torch.softmax(logits, dim=-1)[:, 1].numpy()
        return out

    def predict_proba(self, texts, label=""):
        texts = list(texts)
        keys = [self._key(t) for t in texts]
        todo = sorted({k: t for k, t in zip(keys, texts) if k not in self.cache}.items())
        if todo:
            started = time.perf_counter()
            segments, owner = [], []
            for n, (key, text) in enumerate(todo):
                for seg in self._segments(text):
                    segments.append(seg)
                    owner.append(n)
            scores = self._score_segments(segments)
            best = np.zeros(len(todo))
            np.maximum.at(best, np.asarray(owner), scores)
            for (key, _), score in zip(todo, best):
                self.cache[key] = float(score)
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(self.cache_path, "w") as fh:
                json.dump(self.cache, fh)
            print(f"    scored {len(todo)} {label} prompts ({len(segments)} segments) "
                  f"in {time.perf_counter() - started:.0f}s", flush=True)
        p = np.array([self.cache[k] for k in keys])
        return np.stack([1 - p, p], axis=1)


def rates(flags, labels):
    flags, labels = np.asarray(flags, bool), np.asarray(labels)
    pos, neg = labels == 1, labels == 0
    return (flags[pos].mean() if pos.any() else None,
            int((flags & neg).sum()), int(neg.sum()))


def fmt(r):
    recall, fp, n_neg = r
    rec = f"{recall:6.1%}" if recall is not None else "     -"
    fpr = f"{fp:>4} ({fp / n_neg:5.1%})" if n_neg else "           -"
    return f"{rec} {fpr}"


def auc(labels, scores):
    from sklearn.metrics import roc_auc_score
    labels = np.asarray(labels)
    return roc_auc_score(labels, scores) if 0 < labels.sum() < len(labels) else None


def sample(items, cap, seed=0):
    """items unchanged if short enough, else a fixed random subset."""
    if cap is None or len(items) <= cap:
        return items
    keep = np.random.default_rng(seed).choice(len(items), cap, replace=False)
    return [items[i] for i in sorted(keep)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="Hugging Face id or local directory")
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--cap", type=int, default=3000,
                    help="sample sets and calibration sources larger than this (default 3000)")
    ap.add_argument("--json", help="write the numbers here as well")
    args = ap.parse_args()

    import joblib
    from defense import local_pattern_detector, sanitize_input
    td._quiet_streamlit()

    guard = PromptGuard(args.model, threads=args.threads)
    bundle = joblib.load(os.path.join(HERE, "models", "detector.joblib"))
    ml_model, ml_threshold = bundle["pipeline"], float(bundle["threshold"])
    print(f"Prompt Guard: {guard.name}    ML detector threshold: {ml_threshold:.3f}")

    # Calibrate on the benign training rows, as the ML tier was.
    with contextlib.redirect_stdout(io.StringIO()):
        rows, external = td.collect_rows()
    benign = []
    for source in sorted({r["source"] for r in rows}):
        benign += sample([r for r in rows if r["label"] == 0 and r["source"] == source], args.cap)
    print(f"\nCalibrating on {len(benign)} benign training rows (at most {args.cap} per source)")
    b_scores = guard.predict_proba([sanitize_input(r["text"]) for r in benign], "training")[:, 1]
    cal, detail = td.choose_threshold(
        b_scores, np.zeros(len(benign), dtype=int),
        np.array([r["source"] for r in benign]), TARGET_FPR)
    print(f"  calibrated threshold {cal:.4f}  (per-source budget {detail['budget']:.3f})")

    import evaluation
    sys.path.insert(0, os.path.join(HERE, "tests"))
    import test_generalization as tg
    sets = {
        "evaluation.py": ([c["prompt"] for c in evaluation.TEST_CASES],
                          [1 if c["label"] == "MALICIOUS" else 0 for c in evaluation.TEST_CASES]),
        "holdout SAFE": (list(tg.SAFE_HOLDOUT), [0] * len(tg.SAFE_HOLDOUT)),
        "holdout MALICIOUS": (list(tg.MALICIOUS_HOLDOUT), [1] * len(tg.MALICIOUS_HOLDOUT)),
        **external,
    }

    head = (f"  {'set':<28} {'n':>6}  {'AUC ML':>6} {'AUC PG':>6}  "
            f"{'ML':<19}  {'PG@0.5':<19}  {'PG@cal':<19}  {'regex+ML':<19}  {'regex+PG@cal':<19}")
    print("\nrecall, then false positives (rate)\n" + head)
    results = {"model": guard.name, "calibrated_threshold": cal, "ml_threshold": ml_threshold, "sets": {}}
    for name, (texts, labels) in sets.items():
        if len(texts) > args.cap:
            pairs = sample(list(zip(texts, labels)), args.cap)
            texts, labels = [t for t, _ in pairs], [l for _, l in pairs]
            name = f"{name} (sample)"
        cleaned = [sanitize_input(t) for t in texts]
        labels = np.asarray(labels)
        ml = ml_model.predict_proba(cleaned)[:, 1]
        pg = guard.predict_proba(cleaned, name)[:, 1]
        regex = np.array([local_pattern_detector(c)["is_malicious"] for c in cleaned])
        row = {
            "n": len(labels), "auc_ml": auc(labels, ml), "auc_pg": auc(labels, pg),
            "ml": rates(ml >= ml_threshold, labels),
            "pg_default": rates(pg >= 0.5, labels),
            "pg_cal": rates(pg >= cal, labels),
            "regex_ml": rates(regex | (ml >= ml_threshold), labels),
            "regex_pg": rates(regex | (pg >= cal), labels),
        }
        results["sets"][name] = row
        a = lambda x: f"{x:6.3f}" if x is not None else "     -"
        print(f"  {name:<28} {len(labels):>6}  {a(row['auc_ml'])} {a(row['auc_pg'])}  "
              f"{fmt(row['ml'])}  {fmt(row['pg_default'])}  {fmt(row['pg_cal'])}  "
              f"{fmt(row['regex_ml'])}  {fmt(row['regex_pg'])}", flush=True)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2, default=lambda o: None)


if __name__ == "__main__":
    main()
