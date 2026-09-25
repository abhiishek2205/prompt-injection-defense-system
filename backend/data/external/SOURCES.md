# Dataset sources

Every dataset the ML detector trains or is evaluated on, traceable to its
origin, licence and exact revision.

## Downloaded by `fetch_datasets.py`

Not committed — `python fetch_datasets.py` downloads the same revision again.
Training splits land here as `hf_<name>.parquet`; test splits go to
`data/eval/` and are never trained on.

| Name | Dataset | Licence | Revision | Train rows | Eval rows | Role |
|------|---------|---------|----------|-----------:|----------:|------|
| deepset | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | `4f61ecb` | 546 | 116 | train + eval |
| jackhhao | [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | `2f2ceeb` | 1,044 | 262 | train + eval |
| slabs | [S-Labs/prompt-injection-dataset](https://huggingface.co/datasets/S-Labs/prompt-injection-dataset) | MIT | `002a9dd` | 11,089 | 2,101 | train + eval |
| promptshield | [hendzh/PromptShield](https://huggingface.co/datasets/hendzh/PromptShield) | Apache-2.0 | `a5234cb` | 18,909 | 23,516 | train + eval |
| gandalf | [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | `04737b6` | 777 | 112 | train + eval (attacks only) |
| notinject | [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) | MIT | `847ae76` | — | 339 | eval only (benign, trigger words) |

Considered and left out — reasons in `fetch_datasets.py`:
`qualifire/prompt-injections-benchmark` (gated, CC-BY-NC-4.0),
`reshabhs/SPML_Chatbot_Prompt_Injection` (labels do not mean "injection"),
`xTRam1/safe-guard-prompt-injection` (no licence).

## Base model

| Model | Licence | Revision | Use |
|-------|---------|----------|-----|
| [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) | Apache-2.0 | `1110a24` | fine-tuned by `train_transformer.py`; the result ships as `models/transformer/minilm-l6-ft/` |

## Committed to this folder by hand

| File | Dataset | URL | Licence | Rows | Added |
|------|---------|-----|---------|------|-------|
| _(none yet)_ | | | | | |

Add the citation to the report's references as well — a dataset is a source
like any other.
