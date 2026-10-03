"""Build the attack memory's seed: known attacks and their similarity threshold.

Writes models/attack_memory/seed.npz — every attack in the training data
(train_detector.collect_rows(), so no held-out or evaluation prompt), embedded
with the memory's sentence encoder and stored as int8 (similarity changes by
<0.01), plus the threshold above which a prompt counts as a known attack.

THE THRESHOLD
-------------
Chosen on the benign training rows, with the rule the other tiers use
(train_detector.choose_threshold): at most 0.5% of each source's benign rows
may match, and none of the in-domain ones — the seed corpus's questions and
the generated hard negatives. Test sets play no part.

WHAT TO EXPECT FROM IT
----------------------
This layer recognises attacks it has seen, reworded — not new ones. On the
training data no source's attacks matched another source's at the threshold
(<=1.5%), and on the public test splits the seed alone catches 0-6% with
almost no false positives. Its value is reuse: public jailbreaks are copied
verbatim, and attacks confirmed at runtime are learned (attack_memory.learn),
so their next rewording is stopped locally.

Usage:
    python fetch_datasets.py            # once, for the training data
    python build_attack_memory.py       # ~5 min on CPU
"""

import io
import contextlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

import train_detector as td
from attack_memory import SEED_PATH, SentenceEncoder, _preview

IN_DOMAIN = ("seed/", "generated/")
TARGET_FPR = 0.005


def max_similarity(queries, memory, chunk=2048):
    return np.concatenate([(queries[i:i + chunk] @ memory.T).max(1)
                           for i in range(0, len(queries), chunk)])


def quantize(vectors):
    """Unit vectors as int8; dequantised and renormalised at load time."""
    return np.round(vectors * 127).astype(np.int8)


def main():
    with contextlib.redirect_stdout(io.StringIO()):
        rows, _ = td.collect_rows()
    attacks = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    print(f"Embedding {len(attacks)} attacks and {len(benign)} benign rows")

    encoder = SentenceEncoder()
    started = time.perf_counter()
    A = encoder.encode([r["text"] for r in attacks])
    B = encoder.encode([r["text"] for r in benign])
    print(f"  done in {time.perf_counter() - started:.0f}s")

    # Calibrate on what will actually be stored: the int8 vectors.
    Aq = quantize(A).astype(np.float32) / 127
    Aq /= np.linalg.norm(Aq, axis=1, keepdims=True)

    b_scores = max_similarity(B, Aq)
    b_sources = np.array([r["source"] for r in benign])
    threshold, detail = td.choose_threshold(
        b_scores, np.zeros(len(benign), dtype=int), b_sources, TARGET_FPR)
    in_domain = np.array([s.startswith(IN_DOMAIN) for s in b_sources])
    guard = float(b_scores[in_domain].max()) if in_domain.any() else 0.0
    threshold = max(threshold, round(guard + 0.005, 3))
    print(f"  threshold {threshold:.3f}  (per-source budget {detail['budget']:.3f}, "
          f"in-domain guard {guard:.3f})")
    for source in sorted(set(b_sources)):
        m = b_sources == source
        print(f"    {source:<34} benign matched {(b_scores[m] >= threshold).mean():6.2%}")

    os.makedirs(os.path.dirname(SEED_PATH), exist_ok=True)
    np.savez_compressed(
        SEED_PATH,
        vectors=quantize(A),
        sources=np.array([r["source"] for r in attacks]),
        previews=np.array([_preview(r["text"]) for r in attacks]),
        threshold=np.float32(threshold),
    )
    print(f"\nSaved {SEED_PATH} ({os.path.getsize(SEED_PATH) / 1e6:.1f} MB, "
          f"{len(attacks)} attacks)")


if __name__ == "__main__":
    main()
