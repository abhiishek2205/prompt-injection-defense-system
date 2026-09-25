"""Download public prompt-injection datasets for the ML detector.

Each dataset is pulled from Hugging Face at a pinned revision and written as a
two-column (text, label) parquet file:

    data/external/hf_<name>.parquet   training splits — train_detector.py
                                      picks these up with everything else in
                                      data/external/
    data/eval/<name>__<split>.parquet evaluation splits — never trained on;
                                      train_detector.py reports against them

The files are not committed (see .gitignore). Pinning the revision is what
makes a run reproducible without redistributing the data: the same command
downloads the same bytes.

WHAT IS HERE AND WHY
--------------------
Only datasets that are ungated and permissively licensed (MIT / Apache-2.0).
Each entry was checked against a live download — columns and label values
below are the real ones, not guesses from a listing.

Left out on purpose:
    qualifire/prompt-injections-benchmark  gated, CC-BY-NC-4.0 (non-commercial)
    reshabhs/SPML_Chatbot_Prompt_Injection labels mark system-prompt policy
                                           violations, not injections — e.g. a
                                           user asking for home remedies
                                           instead of a doctor is labelled 1
    xTRam1/safe-guard-prompt-injection     no licence declared

NotInject is evaluation-only. It is 339 benign prompts built around trigger
words ("Can I ignore this warning in my code?") — a direct measure of the
trigger-word bias this project's classifier suffers from (InjecGuard,
arXiv:2410.22770). Training on it would hide exactly the failure it exists to
reveal.

Usage:
    python fetch_datasets.py            # download everything missing
    python fetch_datasets.py --force    # re-download everything
    python fetch_datasets.py --list     # show the registry and exit
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXTERNAL_DIR = os.path.join(HERE, "data", "external")
EVAL_DIR = os.path.join(HERE, "data", "eval")

# Prefix for files this script owns in data/external/, so they are easy to
# tell apart from files someone dropped in by hand (and to gitignore).
TRAIN_PREFIX = "hf_"

# label: a column name, or an int for single-class sets.
# positive: label values meaning "attack" when the column is a string.
DATASETS = [
    {
        "name": "deepset",
        "repo": "deepset/prompt-injections",
        "revision": "4f61ecb038e9c3fb77e21034b22511b523772cdd",
        "licence": "Apache-2.0",
        "text": "text", "label": "label",
        "train": ["train"], "eval": ["test"],
    },
    {
        "name": "jackhhao",
        "repo": "jackhhao/jailbreak-classification",
        "revision": "2f2ceeb39658696fd3f462403562b6eea5306287",
        "licence": "Apache-2.0",
        "text": "prompt", "label": "type", "positive": {"jailbreak"},
        "train": ["train"], "eval": ["test"],
    },
    {
        "name": "slabs",
        "repo": "S-Labs/prompt-injection-dataset",
        "revision": "002a9dd18514abd021869823d6b0429b38606d99",
        "licence": "MIT",
        "text": "text", "label": "label",
        "train": ["train"], "eval": ["test"],
    },
    {
        "name": "promptshield",
        "repo": "hendzh/PromptShield",
        "revision": "a5234cb1f5cdb256600cab64b8c961195b5e8404",
        "licence": "Apache-2.0",
        "text": "prompt", "label": "label",
        "train": ["train"], "eval": ["test"],
    },
    {
        "name": "gandalf",
        "repo": "Lakera/gandalf_ignore_instructions",
        "revision": "04737b65e90a6794ec227012e4a255a7def6344b",
        "licence": "MIT",
        "text": "text", "label": 1,
        "train": ["train"], "eval": ["test"],
    },
    {
        "name": "notinject",
        "repo": "leolee99/NotInject",
        "revision": "847ae76cf8fea5ed325429e569ae8cfef022d2e0",
        "licence": "MIT",
        "text": "prompt", "label": 0,
        "train": [],
        "eval": ["NotInject_one", "NotInject_two", "NotInject_three"],
    },
]


def _to_frame(ds, spec):
    """Reduce one split to (text, label) with label in {0, 1}."""
    import pandas as pd

    frame = ds.to_pandas()
    texts = frame[spec["text"]]
    if isinstance(spec["label"], int):
        labels = pd.Series([spec["label"]] * len(frame))
    elif "positive" in spec:
        labels = frame[spec["label"]].map(
            lambda v: int(str(v).strip().lower() in spec["positive"]))
    else:
        labels = frame[spec["label"]].astype(int)

    out = pd.DataFrame({"text": texts.astype(str).str.strip(),
                        "label": labels.astype(int)})
    out = out[out["text"].str.len() > 0].reset_index(drop=True)
    bad = set(out["label"].unique()) - {0, 1}
    if bad:
        raise ValueError(f"unexpected label values {sorted(bad)}")
    return out


def _outputs(spec):
    """Every file this entry writes, as (split, role, path)."""
    for split in spec["train"]:
        yield split, "train", os.path.join(
            EXTERNAL_DIR, f"{TRAIN_PREFIX}{spec['name']}.parquet"
            if len(spec["train"]) == 1
            else f"{TRAIN_PREFIX}{spec['name']}__{split}.parquet")
    for split in spec["eval"]:
        yield split, "eval", os.path.join(
            EVAL_DIR, f"{spec['name']}__{split}.parquet")


def fetch(spec, force=False):
    """Download one dataset. Returns True on success; never raises."""
    todo = [(s, role, p) for s, role, p in _outputs(spec)
            if force or not os.path.exists(p)]
    if not todo:
        print(f"  {spec['name']}: up to date")
        return True

    try:
        from datasets import load_dataset
    except ImportError:
        print("  `datasets` is not installed — pip install -r requirements-train.txt")
        return False

    for split, role, path in todo:
        try:
            ds = load_dataset(spec["repo"], split=split,
                              revision=spec["revision"])
            frame = _to_frame(ds, spec)
        except Exception as exc:  # network, renamed column, moved revision
            print(f"  {spec['name']}/{split}: failed "
                  f"({type(exc).__name__}: {str(exc)[:160]})")
            return False
        os.makedirs(os.path.dirname(path), exist_ok=True)
        frame.to_parquet(path, index=False)
        n_mal = int(frame["label"].sum())
        print(f"  {spec['name']}/{split} -> {os.path.relpath(path, HERE)}  "
              f"{len(frame)} rows ({n_mal} malicious, {len(frame) - n_mal} benign)")
    return True


def fetch_all(force=False):
    ok = True
    for spec in DATASETS:
        ok = fetch(spec, force=force) and ok
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--force", action="store_true", help="re-download everything")
    ap.add_argument("--list", action="store_true", help="show the registry and exit")
    args = ap.parse_args()

    if args.list:
        for spec in DATASETS:
            print(f"{spec['name']:<13} {spec['repo']:<38} {spec['licence']:<11} "
                  f"train={spec['train']} eval={spec['eval']}")
        return

    print("Fetching datasets")
    if not fetch_all(force=args.force):
        sys.exit(1)


if __name__ == "__main__":
    main()
