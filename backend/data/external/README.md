# External datasets

Drop downloaded prompt-injection datasets here and `train_detector.py` picks
them up automatically — no renaming, no config.

```bash
cd backend
python train_detector.py            # seed corpus + everything in this folder
python train_detector.py --no-seed  # this folder only
```

## Formats

`.csv` · `.tsv` · `.jsonl` · `.json` · `.parquet`

The loader finds the text and label columns by name, so files usually work as
downloaded. It recognises `text`, `prompt`, `input`, `sentence`, `content`,
`message`, `query`, `instruction`, `user_input`, `question` for the text, and
`label`, `labels`, `type`, `class`, `category`, `target`, `y`, `is_injection`,
`injection`, `jailbreak`, `malicious`, `is_malicious`, `toxic`, `attack` for
the label.

Labels may be `0`/`1`, `true`/`false`, or strings like `jailbreak` / `benign`.
Anything not recognised as an attack is treated as benign, so an unfamiliar
value costs recall rather than precision — the safer direction for this
project.

If a file is not understood, the run prints its actual column names and skips
it. Either rename a column or add the name to `TEXT_COLUMNS` / `LABEL_COLUMNS`
in `train_detector.py`.

## Before you commit anything here

**Check the licence.** Committing a dataset into a public repository is
redistribution. Most prompt-injection sets are permissive (MIT, Apache-2.0,
CC-BY), but some are non-commercial or forbid redistribution outright. If a
licence does not allow it, keep the file out of git and add a download script
instead.

**Record where it came from.** Add the source and licence to `SOURCES.md` in
this folder. An examiner should be able to trace every training row back to a
dataset and a licence, and you will need the citation for your report anyway.

**Keep it small.** This repository already had 2,285 vendored files removed
once. Git keeps everything forever, so commit a curated subset — a few
thousand rows is plenty for the Stage 1 baseline — rather than a 200 MB dump.

## What to prioritise when curating

Public sets pair attacks against *generic* benign text — small talk, trivia,
general questions. Train on that alone and the model learns
"mentions passwords → attack", which is the trigger-word bias that
[InjecGuard](https://arxiv.org/abs/2410.22770) measures, and which the bundled
model already shows (8 false positives on the held-out safe prompts).

So the scarce, valuable material is **hard negatives**: legitimate IT-support
and security-education questions containing attack vocabulary — *"how should we
store API keys"*, *"send me the password reset link"*, *"show me the API key
documentation"*. 74% of the seed corpus's benign half is hard negatives for
this reason. If a public set gives you thousands of attacks and only generic
benign text, the class balance will look fine and precision will still fall.

## The test sets stay out

`evaluation.py`'s cases and the held-out prompts in
`tests/test_generalization.py` are never training data. `train_detector.py`
refuses to run if any appear here, and `tests/test_ml_detector.py` checks
again. If the guard fires, remove the offending rows — do not disable it. A
model trained on its own test set reports a number that means nothing.

Exact duplicates are caught automatically. Near-duplicates (a reworded version
of a held-out prompt) are not, so skim what you add.
