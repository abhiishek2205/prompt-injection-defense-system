"""Llama Prompt Guard 2 — Meta's prompt-attack classifier, as a Layer 2 tier.

Prompt Guard 2 scores a prompt's probability of being an explicit prompt
attack (jailbreak or injection technique). It complements the other tiers:
it catches reworded jailbreaks that no regex lists ("We are playing Opposite
Day..."), and by design does not flag plain requests for data — those stay
with the LLM judge and output containment.

Two backends, tried in order:

- local: models/prompt_guard/ built by build_prompt_guard.py — ONNX int8,
  a few milliseconds, works offline;
- groq: the hosted model on Groq (PROMPT_GUARD_GROQ_MODEL, default the 86M),
  when GROQ_API_KEY is set — no weights needed, one API call per prompt.

Neither available means "no opinion", like the other advisory tiers. Long
prompts are split into 512-token segments, Meta's guidance; a prompt scores as
its highest segment.

Built with Llama. Llama 4 is licensed under the Llama 4 Community License,
Copyright © Meta Platforms, Inc. All Rights Reserved.
"""

import json
import logging
import os
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(HERE, "models", "prompt_guard")
MAX_TOKENS = 512
MAX_SEGMENTS = 8                 # head and tail of anything longer
GROQ_MODEL = os.environ.get("PROMPT_GUARD_GROQ_MODEL", "meta-llama/llama-prompt-guard-2-86m")
GROQ_SEGMENT_CHARS = 1500        # ~400 tokens; the server sees no more than 512
GROQ_MAX_SEGMENTS = 4

logger = logging.getLogger("nexuscore.prompt_guard")


def _head_and_tail(chunks, limit):
    if len(chunks) <= limit:
        return chunks
    half = limit // 2
    return chunks[:half] + chunks[-(limit - half):]


class LocalPromptGuard:
    """ONNX int8 Prompt Guard from build_prompt_guard.py."""

    backend = "local"

    def __init__(self, model_dir=MODEL_DIR):
        import onnxruntime as ort
        from transformer_classifier import load_tokenizer

        with open(os.path.join(model_dir, "meta.json")) as fh:
            self.meta = json.load(fh)
        self.model = self.meta["model"]
        self.threshold = float(self.meta["threshold"])
        self._tokenizer = load_tokenizer(os.path.join(model_dir, "tokenizer.json"))
        options = ort.SessionOptions()
        options.log_severity_level = 3
        self._session = ort.InferenceSession(os.path.join(model_dir, "model.onnx"), options,
                                             providers=["CPUExecutionProvider"])

    def score(self, text: str) -> float:
        import numpy as np
        from transformer_classifier import pad_batch

        cls, sep, pad = self.meta["cls_id"], self.meta["sep_id"], self.meta["pad_id"]
        ids = self._tokenizer.encode(text or " ", add_special_tokens=False).ids or [pad]
        room = MAX_TOKENS - 2
        chunks = _head_and_tail([ids[i:i + room] for i in range(0, len(ids), room)], MAX_SEGMENTS)
        batch, mask = pad_batch([[cls] + c + [sep] for c in chunks], pad)
        logits = self._session.run(None, {"input_ids": batch, "attention_mask": mask})[0]
        z = logits.astype(np.float64)
        z -= z.max(axis=1, keepdims=True)
        p = np.exp(z) / np.exp(z).sum(axis=1, keepdims=True)
        return float(p[:, 1].max())


class GroqPromptGuard:
    """The hosted Prompt Guard on Groq: the reply is the attack probability."""

    backend = "groq"

    def __init__(self, model=GROQ_MODEL, threshold=0.5):
        from groq import Groq

        self.model = model
        self.threshold = threshold
        self._client = Groq(api_key=os.environ["GROQ_API_KEY"], timeout=5.0, max_retries=1)

    def score(self, text: str) -> float:
        text = text or " "
        chunks = [text[i:i + GROQ_SEGMENT_CHARS] for i in range(0, len(text), GROQ_SEGMENT_CHARS)]
        best = 0.0
        for chunk in _head_and_tail(chunks, GROQ_MAX_SEGMENTS):
            reply = self._client.chat.completions.create(
                model=self.model, messages=[{"role": "user", "content": chunk}])
            best = max(best, float(reply.choices[0].message.content.strip()))
        return best


_guard = None
_load_failed = False
_lock = threading.Lock()


def get_guard():
    """The shared scorer, or None when no backend is available."""
    global _guard, _load_failed
    if _guard is not None or _load_failed:
        return _guard
    with _lock:
        if _guard is None and not _load_failed:
            try:
                if os.path.exists(os.path.join(MODEL_DIR, "model.onnx")):
                    _guard = LocalPromptGuard()
                elif os.environ.get("GROQ_API_KEY"):
                    _guard = GroqPromptGuard()
                else:
                    _load_failed = True
            except Exception as exc:
                _load_failed = True
                logger.warning("Prompt Guard unavailable: %s: %s", type(exc).__name__, exc)
    return _guard


def opinion(text: str) -> dict:
    """Verdict dict in the shape the other Layer 2 tiers use."""
    guard = get_guard()
    if guard is None:
        return {"available": False, "is_malicious": False, "confidence": 0.0,
                "detection_method": "prompt_guard"}
    try:
        score = guard.score(text)
    except Exception as exc:
        logger.warning("Prompt Guard error (%s): %s: %s", guard.backend, type(exc).__name__, exc)
        return {"available": False, "is_malicious": False, "confidence": 0.0,
                "detection_method": "prompt_guard"}
    return {
        "available": True,
        "is_malicious": score >= guard.threshold,
        "confidence": round(score, 4),
        "threshold": guard.threshold,
        "model": guard.model,
        "backend": guard.backend,
        "detection_method": "prompt_guard",
    }


def reset_cache():
    """Drop the cached scorer. For tests."""
    global _guard, _load_failed
    with _lock:
        _guard = None
        _load_failed = False
