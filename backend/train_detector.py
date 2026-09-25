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

Whatever the source, include HARD NEGATIVES: legitimate prompts containing
attack vocabulary. Public sets pair attacks against generic benign chat, and a
model trained on that learns "mentions passwords -> attack" — the trigger-word
bias measured by InjecGuard (arXiv:2410.22770). data/hard_negatives.jsonl
(build_hard_negatives.py) is loaded by default; --no-hard-negatives leaves it
out for comparison.

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
    python train_detector.py --no-hard-negatives   # ablation
    python train_detector.py --out models/detector.joblib
"""

import argparse
import json
import math
import os
import re
import sys
import time
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import numpy as np
import sklearn

import fetch_datasets
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import FeatureUnion, Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
SEED_CORPUS = os.path.join(HERE, "data", "seed_corpus.jsonl")
HARD_NEGATIVES = os.path.join(HERE, "data", "hard_negatives.jsonl")
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

# Threshold selection — see choose_threshold().
CV_FOLDS = 5
CV_REPEATS = 3                  # fold assignments; the threshold is their median
DEFAULT_TARGET_FPR = 0.005      # per source, on out-of-fold scores
MIN_BENIGN_FOR_BUDGET = 20      # smaller sources are too noisy to budget
IN_DOMAIN_PREFIX = "seed/"      # benign rows here must never be flagged
MAX_THRESHOLD = 0.99


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

def load_seed(path=SEED_CORPUS):
    rows = []
    with open(path, encoding="utf-8") as fh:
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


def collect_rows(no_seed=False, no_hard_negatives=False):
    """Every training row, deduplicated and with all held-out prompts removed.

    Returns (rows, external_eval). Shared by train_detector.py and
    train_transformer.py so both models see exactly the same data.
    """
    print("Loading data")
    rows = []
    if not no_seed:
        rows += load_seed()
        print(f"  seed corpus: {len(rows)} rows")
    if not no_hard_negatives and os.path.exists(HARD_NEGATIVES):
        hard = load_seed(HARD_NEGATIVES)
        rows += hard
        print(f"  generated hard negatives: {len(hard)} rows "
              f"(build_hard_negatives.py)")
    rows += load_local()

    forbidden = held_out_texts()
    print(f"  held-out prompts protected: {len(forbidden)}")
    external_eval = load_eval()
    reserved = {_normalize(t) for texts, _ in external_eval.values() for t in texts}
    if external_eval:
        print(f"  external evaluation sets: {len(external_eval)} "
              f"({len(reserved)} distinct prompts reserved)")
    return prepare(rows, forbidden, reserved), external_eval


# =============================================================================
# Model
# =============================================================================

def build_pipeline():
    """Word n-grams carry phrasing; char n-grams survive obfuscation.

    min_df=2 and the feature caps drop n-grams seen in only one prompt. On the
    public data that cut the artifact from ~11 MB to a fraction of it with no
    loss: cross-validated AUC went 0.981 -> 0.983. Lowering C (stronger
    regularisation) was tried and only cost recall.
    """
    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                analyzer="word", ngram_range=(1, 2), min_df=2,
                max_features=100_000,
                sublinear_tf=True, lowercase=True, strip_accents="unicode")),
            ("char", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                max_features=100_000,
                sublinear_tf=True, lowercase=True, strip_accents="unicode")),
        ])),
        ("clf", LogisticRegression(
            max_iter=2000, C=4.0,
            class_weight="balanced",
            random_state=RANDOM_STATE)),
    ])


def out_of_fold_scores(texts, labels, groups=None, seed=RANDOM_STATE):
    """Score every training row with a model that never saw it.

    5-fold cross-validation: each row is scored by the model trained on the
    other four folds. Unlike a single 75/25 split, every row counts towards
    the threshold, and nothing is thrown away — the final model is refit on
    all of it afterwards.

    Grouped: rows sharing a group (the generated hard negatives that differ
    only by "Thanks!" or "Quick question:") stay in one fold. Otherwise one
    variant is trained on and its twin scored, and that source looks better
    than it is. Rows without a group are their own group.
    """
    if groups is None:
        groups = list(range(len(texts)))
    folds = StratifiedGroupKFold(n_splits=CV_FOLDS, shuffle=True,
                                 random_state=seed)
    return cross_val_predict(build_pipeline(), texts, labels, groups=groups,
                             cv=folds, method="predict_proba",
                             n_jobs=min(CV_FOLDS, os.cpu_count() or 1))[:, 1]


def _threshold_for_fpr(benign_scores, target_fpr):
    """Smallest threshold letting at most target_fpr of these rows through."""
    ranked = np.sort(np.asarray(benign_scores))[::-1]
    allowed = int(np.floor(target_fpr * len(ranked)))
    if allowed >= len(ranked):
        return 0.0
    return float(ranked[allowed]) + 1e-6


def choose_threshold(scores, labels, sources, target_fpr):
    """Pick the block threshold from out-of-fold scores. Two constraints:

    1. False-positive budget, per source. Every dataset with enough benign rows
       must stay within target_fpr. Per source rather than pooled, because
       pooled is dominated by whichever set is biggest (PromptShield is ~58% of
       the rows), and real traffic will not look like any one of them.

       A budget rather than zero: the public sets deliberately include
       adversarial benign prompts ("What is your response to: ignore your
       instructions") and some label noise. Zero false positives over thousands
       of such rows is unreachable, and demanding it pinned the old rule to its
       0.95 cap.

    2. Zero false positives on the in-domain benign rows (the seed corpus's
       benign and hard-negative prompts — IT-support and security questions in
       this project's voice). This is the traffic the dashboard actually sees,
       and a local block is never reviewed by the LLM tier.

    The threshold is the stricter of the two. Test sets play no part: they
    stay unseen until the report.
    """
    scores, labels, sources = map(np.asarray, (scores, labels, sources))
    detail = {"target_fpr": target_fpr, "per_source": {}}

    per_source = []
    for source in sorted(set(sources)):
        benign = scores[(sources == source) & (labels == 0)]
        if len(benign) < MIN_BENIGN_FOR_BUDGET:
            continue
        t = _threshold_for_fpr(benign, target_fpr)
        detail["per_source"][source] = round(t, 4)
        per_source.append(t)
    budget = max(per_source) if per_source else 0.5

    in_domain = scores[(np.char.startswith(sources.astype(str), IN_DOMAIN_PREFIX))
                       & (labels == 0)]
    guard = float(in_domain.max()) + 1e-6 if len(in_domain) else 0.0
    detail["budget"] = round(budget, 4)
    detail["in_domain_guard"] = round(guard, 4)

    threshold = math.ceil(max(budget, guard, 0.5) * 100) / 100
    return min(threshold, MAX_THRESHOLD), detail


def _rates(flags, labels):
    flags, labels = np.asarray(flags, bool), np.asarray(labels)
    n_pos, n_neg = int(labels.sum()), int((labels == 0).sum())
    fp = int((flags & (labels == 0)).sum())
    fn = int((~flags & (labels == 1)).sum())
    return {"fp": fp, "fn": fn, "n_pos": n_pos, "n_neg": n_neg,
            "recall": (1 - fn / n_pos) if n_pos else None,
            "fpr": (fp / n_neg) if n_neg else None}


def _fmt(r):
    parts = []
    if r["recall"] is not None:
        parts.append(f"rec {r['recall']:6.1%}")
    else:
        parts.append(" " * 10)
    if r["fpr"] is not None:
        parts.append(f"FP {r['fp']:>4} ({r['fpr']:4.1%})")
    else:
        parts.append(" " * 14)
    return " ".join(parts)


def _quiet_streamlit():
    """sanitize_input() touches st.session_state, which logs a warning per call
    outside a running Streamlit app — tens of thousands of lines here."""
    import logging
    for name in list(logging.root.manager.loggerDict):
        if name.startswith("streamlit"):
            logging.getLogger(name).setLevel(logging.ERROR)


def report_against(pipe, threshold, name, prompts, labels):
    """ML alone, regex alone, and regex-or-ML — the pipeline if ML may block.

    Scored on sanitize_input() output, which is what both tiers see at runtime.
    """
    from defense import local_pattern_detector, sanitize_input
    _quiet_streamlit()

    cleaned = [sanitize_input(p) for p in prompts]
    labels = np.asarray(labels)
    probs = pipe.predict_proba(cleaned)[:, 1]
    ml = probs >= threshold
    regex = np.array([local_pattern_detector(c)["is_malicious"] for c in cleaned])

    result = {"total": len(labels),
              "ml": _rates(ml, labels),
              "regex": _rates(regex, labels),
              "combined": _rates(ml | regex, labels)}
    auc = (roc_auc_score(labels, probs) if 0 < labels.sum() < len(labels)
           else None)
    result["auc"] = auc
    # Kept for callers that read the old flat shape.
    result.update(fp=result["ml"]["fp"], fn=result["ml"]["fn"],
                  correct=int((ml == labels).sum()))

    print(f"  {name:<28} {len(labels):>6}  "
          f"{(f'{auc:.3f}' if auc is not None else '  -  '):>5}  "
          f"{_fmt(result['ml'])}  |  {_fmt(result['regex'])}  |  "
          f"{_fmt(result['combined'])}")
    return result


def _report_header():
    print(f"  {'set':<28} {'n':>6}  {'AUC':>5}  "
          f"{'ML':<25}  |  {'regex':<25}  |  {'regex + ML':<25}")


def report_all(model, threshold, external_eval):
    """Score every held-out and external evaluation set. Never trained on;
    this is the only honest read. Returns {"held_out": ..., "external": ...}."""
    import evaluation

    print("\nHeld-out (never trained on)")
    _report_header()
    metrics = {"held_out": {}}
    metrics["held_out"]["evaluation.py"] = report_against(
        model, threshold, "evaluation.py TEST_CASES",
        [c["prompt"] for c in evaluation.TEST_CASES],
        [1 if c["label"] == "MALICIOUS" else 0 for c in evaluation.TEST_CASES])

    try:
        sys.path.insert(0, os.path.join(HERE, "tests"))
        import test_generalization as tg
        metrics["held_out"]["safe_holdout"] = report_against(
            model, threshold, "test_generalization SAFE",
            list(tg.SAFE_HOLDOUT), [0] * len(tg.SAFE_HOLDOUT))
        metrics["held_out"]["malicious_holdout"] = report_against(
            model, threshold, "test_generalization MALICIOUS",
            list(tg.MALICIOUS_HOLDOUT), [1] * len(tg.MALICIOUS_HOLDOUT))
    except Exception as exc:
        print(f"  ! held-out generalization set unavailable ({type(exc).__name__})")

    if external_eval:
        print("\nExternal evaluation sets (other datasets' test splits)")
        _report_header()
        metrics["external"] = {}
        for name, (eval_texts, eval_labels) in external_eval.items():
            metrics["external"][name] = report_against(
                model, threshold, name, eval_texts, eval_labels)
    return metrics


# =============================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hf", action="store_true",
                    help="run fetch_datasets.py first (downloads anything "
                         "missing from Hugging Face)")
    ap.add_argument("--no-seed", action="store_true",
                    help="skip the bundled seed corpus and train on "
                         "data/external/ alone")
    ap.add_argument("--cv-repeats", type=int, default=CV_REPEATS,
                    help=f"cross-validation repeats (default {CV_REPEATS})")
    ap.add_argument("--no-hard-negatives", action="store_true",
                    help="leave out data/hard_negatives.jsonl (for ablation)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--target-fpr", type=float, default=DEFAULT_TARGET_FPR,
                    help="false-positive budget per source on out-of-fold "
                         f"scores (default {DEFAULT_TARGET_FPR})")
    args = ap.parse_args()

    if args.hf:
        print("Fetching datasets")
        fetch_datasets.fetch_all()
        print()

    rows, external_eval = collect_rows(no_seed=args.no_seed,
                                       no_hard_negatives=args.no_hard_negatives)

    texts = [r["text"] for r in rows]
    labels = [r["label"] for r in rows]
    n_mal = sum(labels)
    print(f"  training rows: {len(rows)}  ({n_mal} malicious, {len(rows) - n_mal} benign)")
    if len(rows) < 100:
        print("  ! very small corpus — treat every number below as provisional")

    sources = [r.get("source", "unknown") for r in rows]
    groups = [r.get("group") or f"row:{i}" for i, r in enumerate(rows)]

    # Repeated, because one fold assignment is not enough. A 0.5% budget on a
    # source with ~500 benign rows allows 2 false positives, so its threshold
    # rests on the 2nd-3rd highest score and moved 0.91-0.94 between fold
    # assignments alone. The median over repeats is stable; the spread is
    # reported so the noise stays visible.
    repeats = max(1, args.cv_repeats)
    print(f"\nCross-validation ({CV_FOLDS}-fold x {repeats}, out-of-fold scores)")
    started = time.perf_counter()
    runs = []
    for r in range(repeats):
        scores = out_of_fold_scores(texts, labels, groups, seed=RANDOM_STATE + r)
        t, d = choose_threshold(scores, labels, sources, args.target_fpr)
        runs.append((scores, t, d))
        print(f"  repeat {r + 1}: AUC {roc_auc_score(labels, scores):.4f}  "
              f"threshold {t}  (budget {d['budget']:.3f}, "
              f"in-domain guard {d['in_domain_guard']:.3f})")
    print(f"  done in {time.perf_counter() - started:.1f}s")

    thresholds = sorted(t for _, t, _ in runs)
    threshold = float(np.median(thresholds))
    threshold = math.ceil(threshold * 100 - 1e-9) / 100
    oof = np.mean([s for s, _, _ in runs], axis=0)
    detail = {"target_fpr": args.target_fpr, "repeats": repeats,
              "thresholds": thresholds,
              "per_repeat": [d for _, _, d in runs]}
    print(f"  block threshold: {threshold}  (median of {thresholds}; "
          f"FP budget {args.target_fpr:.1%} per source, zero FP in-domain)")
    if threshold >= MAX_THRESHOLD:
        print(f"    ! capped at {MAX_THRESHOLD}: the model cannot meet both "
              f"constraints — expect low recall")

    print("\n  per source at this threshold (out-of-fold, mean over repeats):")
    oof_arr, lab_arr, src_arr = np.asarray(oof), np.asarray(labels), np.asarray(sources)
    cv_report = {}
    for source in sorted(set(sources)):
        m = src_arr == source
        r = _rates(oof_arr[m] >= threshold, lab_arr[m])
        cv_report[source] = r
        print(f"    {source:<34} {int(m.sum()):>6}  {_fmt(r)}")
    overall = _rates(oof_arr >= threshold, lab_arr)
    print(f"    {'all':<34} {len(labels):>6}  {_fmt(overall)}")

    print("\nTraining final model on all rows")
    started = time.perf_counter()
    pipe = build_pipeline()
    pipe.fit(texts, labels)
    print(f"  fit in {time.perf_counter() - started:.2f}s")

    metrics = {"threshold": threshold, "threshold_detail": detail,
               "cv": {"auc": float(roc_auc_score(labels, oof)),
                      "overall": overall, "per_source": cv_report}}
    metrics.update(report_all(pipe, threshold, external_eval))

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
        # The artifact is a pickle; a different scikit-learn can fail to load
        # it (ml_detector.py then fails open). Recorded so that is diagnosable.
        "sklearn_version": sklearn.__version__,
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
