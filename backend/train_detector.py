"""Train the Stage 1 ML detector: TF-IDF (word + char n-grams) -> LogisticRegression.

WHY THIS MODEL
--------------
It is the explainable baseline. It trains in seconds on CPU, the artifact is a
few MB, and inference is well under a millisecond, so it can sit in the request
path in front of the LLM call. Character n-grams matter here: they pick up
"1gn0r3" and "I.g.n.o.r.e" as a side effect of the representation, which the
regex layer only handles because sanitize_input() de-obfuscates by hand.

It is also a floor to beat. Report it alongside any transformer you train
later; "the simple baseline scored X, the transformer scored Y" is a far
stronger result than one number on its own.

DATA
----
Real data comes from fetch_datasets.py, which downloads public prompt-injection
datasets at pinned revisions: training splits into data/external/, test splits
into data/eval/. See that file for what is included, what is left out, and why.
The bundled data/seed_corpus.jsonl (build_seed_corpus.py) is still mixed in by
default; on its own it is a scaffold, not a research result.

Whatever the source, oversample HARD NEGATIVES: legitimate security and IT
questions containing attack vocabulary. Public sets pair attacks against
generic benign chat, and a model trained on that learns "mentions passwords ->
attack" — the trigger-word bias measured by InjecGuard (arXiv:2410.22770).

THE TEST SETS ARE NOT TRAINING DATA
-----------------------------------
evaluation.py's TEST_CASES and the held-out prompts in
tests/test_generalization.py are held out permanently. This script refuses to
run if any training row appears in either, and reports against them at the end.

The external test splits in data/eval/ are held out too. Public datasets copy
from each other, so a few of one set's test prompts appear in another's
training split; those rows are dropped from training (and counted), and every
set in data/eval/ is reported at the end.

LOCAL DATASET FILES
-------------------
Anything dropped into data/external/ is picked up automatically: .csv, .tsv,
.jsonl, .json or .parquet. Text and label columns are detected by name, so
downloaded files work as they come; a file whose columns are not recognised is
reported with its actual column names and skipped.

Usage:
    python fetch_datasets.py                # download public datasets once
    python train_detector.py                # seed corpus + data/external/
    python train_detector.py --hf           # fetch anything missing, then train
    python train_detector.py --no-seed      # data/external/ only
    python train_detector.py --out models/detector.joblib
"""

import argparse
import json
import os
import re
import sys
import time
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import numpy as np

import fetch_datasets
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
SEED_CORPUS = os.path.join(HERE, "data", "seed_corpus.jsonl")
EXTERNAL_DIR = os.path.join(HERE, "data", "external")
EVAL_DIR = os.path.join(HERE, "data", "eval")

# Column names seen across public prompt-injection datasets. The loader picks
# the first match rather than making you rename columns, because every set
# names these differently.
TEXT_COLUMNS = ["text", "prompt", "input", "sentence", "content", "message",
                "query", "instruction", "user_input", "question"]
LABEL_COLUMNS = ["label", "labels", "type", "class", "category", "target", "y",
                 "is_injection", "injection", "jailbreak", "malicious",
                 "is_malicious", "toxic", "attack"]

# Label values that mean "attack". Anything else counts as benign, so an
# unfamiliar value fails safe (a mislabelled attack costs recall; a mislabelled
# benign would cost precision, which is the thing this project protects).
MALICIOUS_VALUES = {"1", "true", "yes", "jailbreak", "injection", "malicious",
                    "attack", "prompt_injection", "unsafe", "harmful", "bad",
                    "positive", "spam"}
DEFAULT_OUT = os.path.join(HERE, "models", "detector.joblib")
RANDOM_STATE = 20260921


def _normalize(text):
    """Key for duplicate and contamination checks — not used for training.

    Unicode-aware on purpose. An ASCII-only key ([^a-z0-9]) maps every
    Chinese, Russian or Arabic prompt to "", so non-Latin rows were all
    discarded as empty and contamination between them went unseen.
    """
    text = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"[\W_]+", " ", text).strip()


# =============================================================================
# Data
# =============================================================================

def load_seed():
    rows = []
    with open(SEED_CORPUS, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _read_table(path):
    """Read one dataset file into a DataFrame. Returns None if unsupported."""
    import pandas as pd

    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        return pd.read_csv(path)
    if ext in (".tsv", ".tab"):
        return pd.read_csv(path, sep="\t")
    if ext == ".jsonl":
        return pd.read_json(path, lines=True)
    if ext == ".json":
        return pd.read_json(path)
    if ext == ".parquet":
        return pd.read_parquet(path)
    return None


def _pick(columns, candidates):
    lowered = {str(c).lower(): c for c in columns}
    for name in candidates:
        if name in lowered:
            return lowered[name]
    return None


def _to_label(value):
    """Map a dataset's label value onto 0/1, or None if it is unusable."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        if value != value:  # NaN
            return None
        return 1 if float(value) >= 0.5 else 0
    return 1 if str(value).strip().lower() in MALICIOUS_VALUES else 0


def load_local():
    """Load every dataset file dropped into data/external/.

    Formats: .csv .tsv .jsonl .json .parquet. Text and label columns are
    detected by name, so downloaded files can be used as they come. Files that
    cannot be understood are reported and skipped, never fatal.
    """
    if not os.path.isdir(EXTERNAL_DIR):
        return []

    paths = sorted(
        os.path.join(EXTERNAL_DIR, name)
        for name in os.listdir(EXTERNAL_DIR)
        if not name.startswith(".") and name.lower().endswith(
            (".csv", ".tsv", ".tab", ".jsonl", ".json", ".parquet"))
    )
    if not paths:
        print(f"  data/external/: no dataset files found")
        return []

    rows = []
    for path in paths:
        name = os.path.basename(path)
        try:
            frame = _read_table(path)
        except Exception as exc:
            print(f"  {name}: unreadable ({type(exc).__name__}: {exc}) — skipped")
            continue
        if frame is None or frame.empty:
            print(f"  {name}: empty — skipped")
            continue

        columns = list(frame.columns)
        text_col = _pick(columns, TEXT_COLUMNS)
        label_col = _pick(columns, LABEL_COLUMNS)
        if text_col is None or label_col is None:
            missing = "text" if text_col is None else "label"
            print(f"  {name}: no {missing} column recognised. Columns are "
                  f"{columns}.\n      Rename one, or add it to "
                  f"{'TEXT_COLUMNS' if text_col is None else 'LABEL_COLUMNS'} "
                  f"in train_detector.py — skipped")
            continue

        added = skipped = 0
        for text, raw in zip(frame[text_col], frame[label_col]):
            if not isinstance(text, str) or not text.strip():
                skipped += 1
                continue
            label = _to_label(raw)
            if label is None:
                skipped += 1
                continue
            rows.append({"text": text.strip(), "label": label,
                         "source": f"external/{name}"})
            added += 1

        distinct = sorted({str(v) for v in frame[label_col].head(200)})[:6]
        n_mal = sum(1 for r in rows[-added:] if r["label"] == 1) if added else 0
        print(f"  {name}: {added} rows "
              f"({n_mal} malicious, {added - n_mal} benign) "
              f"via {text_col!r}/{label_col!r}"
              + (f", {skipped} skipped" if skipped else ""))
        if added and (n_mal == 0 or n_mal == added):
            print(f"      ! single-class file — label values seen: {distinct}")
            print(f"        check MALICIOUS_VALUES covers this set's vocabulary")
    return rows


def held_out_texts():
    """Every prompt that must never be trained on."""
    out = set()

    import evaluation
    for case in evaluation.TEST_CASES:
        out.add(_normalize(case["prompt"]))

    try:
        sys.path.insert(0, os.path.join(HERE, "tests"))
        import test_generalization as tg
        for name in ("SAFE_HOLDOUT", "MALICIOUS_HOLDOUT"):
            for prompt in getattr(tg, name, []):
                out.add(_normalize(prompt))
    except Exception as exc:
        print(f"  ! could not load tests/test_generalization.py ({type(exc).__name__}) — "
              f"contamination check covers evaluation.py only")

    return out


def load_eval():
    """External evaluation sets written by fetch_datasets.py into data/eval/.

    Returns {name: (texts, labels)}. These are other people's test splits;
    they are reported on and never trained on.
    """
    if not os.path.isdir(EVAL_DIR):
        return {}
    import pandas as pd

    sets = {}
    for name in sorted(os.listdir(EVAL_DIR)):
        if not name.endswith(".parquet"):
            continue
        frame = pd.read_parquet(os.path.join(EVAL_DIR, name))
        sets[name[:-len(".parquet")]] = (frame["text"].tolist(),
                                         frame["label"].astype(int).tolist())
    return sets


def prepare(rows, forbidden, reserved=frozenset()):
    """Deduplicate and keep every held-out prompt out of training.

    forbidden: the project's own test sets. In the seed corpus or a file
    dropped in by hand, a hit means someone put a test prompt into training
    data, so refuse outright. In a file fetch_datasets.py downloaded, a hit is
    a common phrase ("Debug mode") that the public set happens to share —
    drop it and list it.

    reserved: external evaluation splits. Public datasets copy from each
    other, so a few of one set's test prompts turn up in another's training
    split. That is nobody's mistake here — drop those rows and say how many.
    """
    fetched_prefix = f"external/{fetch_datasets.TRAIN_PREFIX}"
    seen, clean, leaked, shared = set(), [], [], []
    dropped = 0
    for row in rows:
        key = _normalize(row["text"])
        if not key or key in seen:
            continue
        seen.add(key)
        if key in forbidden:
            if row.get("source", "").startswith(fetched_prefix):
                shared.append(row["text"])
            else:
                leaked.append(row["text"])
            continue
        if key in reserved:
            dropped += 1
            continue
        clean.append(row)

    if dropped:
        print(f"  dropped {dropped} training row(s) that appear in an "
              f"external evaluation set")
    if shared:
        print(f"  dropped {len(shared)} downloaded row(s) that match a project "
              f"held-out prompt:")
        for text in shared[:10]:
            print(f"      {text!r}")

    if leaked:
        print(f"\nCONTAMINATION: {len(leaked)} training row(s) appear in a held-out set.")
        for text in leaked[:10]:
            print(f"    {text!r}")
        raise SystemExit(
            "Refusing to train. A model trained on its own test set produces a "
            "number that means nothing. Remove these rows and re-run."
        )
    return clean


# =============================================================================
# Model
# =============================================================================

def build_pipeline():
    """Word n-grams carry phrasing; char n-grams survive obfuscation."""
    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                analyzer="word", ngram_range=(1, 2), min_df=1,
                sublinear_tf=True, lowercase=True, strip_accents="unicode")),
            ("char", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5), min_df=1,
                sublinear_tf=True, lowercase=True, strip_accents="unicode")),
        ])),
        ("clf", LogisticRegression(
            max_iter=2000, C=4.0,
            class_weight="balanced",       # benign is the smaller class here
            random_state=RANDOM_STATE)),
    ])


def choose_threshold(pipe, X_val, y_val):
    """Lowest threshold that yields zero false positives on validation.

    Precision first, deliberately. This layer can block a request outright, and
    a local block is never reviewed by the LLM behind it — so a false positive
    is unrecoverable at runtime, while a miss still gets a second opinion.
    """
    probs = pipe.predict_proba(X_val)[:, 1]
    best = 0.95
    for threshold in np.arange(0.50, 0.96, 0.01):
        predicted = probs >= threshold
        false_pos = int(((predicted == 1) & (np.array(y_val) == 0)).sum())
        if false_pos == 0:
            best = float(threshold)
            break
    return round(max(0.50, min(best, 0.95)), 2)


def report_against(pipe, threshold, name, prompts, labels):
    probs = pipe.predict_proba(prompts)[:, 1]
    predicted = (probs >= threshold).astype(int)
    labels = np.array(labels)
    fp = int(((predicted == 1) & (labels == 0)).sum())
    fn = int(((predicted == 0) & (labels == 1)).sum())
    correct = int((predicted == labels).sum())
    n_pos, n_neg = int(labels.sum()), int((labels == 0).sum())
    rates = []
    if n_pos:
        rates.append(f"recall={1 - fn / n_pos:.1%}")
    if n_neg:
        rates.append(f"FPR={fp / n_neg:.1%}")
    print(f"  {name:<34} {correct}/{len(labels)}   FP={fp}  FN={fn}   "
          + "  ".join(rates))
    return {"total": len(labels), "correct": correct, "fp": fp, "fn": fn}


# =============================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hf", action="store_true",
                    help="run fetch_datasets.py first (downloads anything "
                         "missing from Hugging Face)")
    ap.add_argument("--no-seed", action="store_true",
                    help="skip the bundled seed corpus and train on "
                         "data/external/ alone")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    if args.hf:
        import fetch_datasets
        print("Fetching datasets")
        fetch_datasets.fetch_all()
        print()

    print("Loading data")
    rows = []
    if not args.no_seed:
        rows += load_seed()
        print(f"  seed corpus: {len(rows)} rows")
    rows += load_local()

    forbidden = held_out_texts()
    print(f"  held-out prompts protected: {len(forbidden)}")
    external_eval = load_eval()
    reserved = {_normalize(t) for texts, _ in external_eval.values() for t in texts}
    if external_eval:
        print(f"  external evaluation sets: {len(external_eval)} "
              f"({len(reserved)} distinct prompts reserved)")
    rows = prepare(rows, forbidden, reserved)

    texts = [r["text"] for r in rows]
    labels = [r["label"] for r in rows]
    n_mal = sum(labels)
    print(f"  training rows: {len(rows)}  ({n_mal} malicious, {len(rows) - n_mal} benign)")
    if len(rows) < 100:
        print("  ! very small corpus — treat every number below as provisional")

    X_train, X_val, y_train, y_val = train_test_split(
        texts, labels, test_size=0.25, random_state=RANDOM_STATE, stratify=labels)

    print("\nTraining")
    started = time.perf_counter()
    pipe = build_pipeline()
    pipe.fit(X_train, y_train)
    print(f"  fit in {time.perf_counter() - started:.2f}s")

    threshold = choose_threshold(pipe, X_val, y_val)
    print(f"  block threshold: {threshold}  (lowest with no validation false positives)")

    print("\nValidation split")
    print(classification_report(
        y_val, (pipe.predict_proba(X_val)[:, 1] >= threshold).astype(int),
        target_names=["benign", "malicious"], zero_division=0))

    # Held-out sets. Never trained on; this is the only honest read.
    print("Held-out (never trained on)")
    import evaluation
    metrics = {"threshold": threshold, "held_out": {}}
    metrics["held_out"]["evaluation.py"] = report_against(
        pipe, threshold, "evaluation.py TEST_CASES",
        [c["prompt"] for c in evaluation.TEST_CASES],
        [1 if c["label"] == "MALICIOUS" else 0 for c in evaluation.TEST_CASES])

    try:
        sys.path.insert(0, os.path.join(HERE, "tests"))
        import test_generalization as tg
        metrics["held_out"]["safe_holdout"] = report_against(
            pipe, threshold, "test_generalization SAFE",
            list(tg.SAFE_HOLDOUT), [0] * len(tg.SAFE_HOLDOUT))
        metrics["held_out"]["malicious_holdout"] = report_against(
            pipe, threshold, "test_generalization MALICIOUS",
            list(tg.MALICIOUS_HOLDOUT), [1] * len(tg.MALICIOUS_HOLDOUT))
    except Exception as exc:
        print(f"  ! held-out generalization set unavailable ({type(exc).__name__})")

    if external_eval:
        print("\nExternal evaluation sets (other datasets' test splits)")
        metrics["external"] = {}
        for name, (texts, labels) in external_eval.items():
            metrics["external"][name] = report_against(
                pipe, threshold, name, texts, labels)

    sample = ["How should we store API keys securely?"] * 200
    started = time.perf_counter()
    pipe.predict_proba(sample)
    per_call = (time.perf_counter() - started) / len(sample) * 1000
    print(f"\n  inference: {per_call:.3f} ms per prompt (batched)")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({
        "pipeline": pipe,
        "threshold": threshold,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_rows": len(rows),
        "sources": sorted({r.get("source", "unknown") for r in rows}),
        "metrics": metrics,
    }, args.out, compress=3)

    size_mb = os.path.getsize(args.out) / 1e6
    print(f"\nSaved {args.out} ({size_mb:.2f} MB)")
    external = sorted({r["source"] for r in rows if r["source"].startswith("external/")})
    if not external and not args.hf:
        print("Trained on the seed corpus alone — a generated scaffold. Drop real "
              "datasets into data/external/ and re-run before quoting these "
              "numbers anywhere.")
    elif external:
        print(f"Included {len(external)} external dataset file(s): "
              + ", ".join(os.path.basename(s) for s in external))


if __name__ == "__main__":
    main()
