"""Attack memory — Layer 2's "have we seen this attack before?" tier.

Like Rebuff's vector layer: confirmed attacks are stored as sentence
embeddings, and a new prompt that is a close paraphrase of one is flagged.
Unlike Rebuff it runs locally — no OpenAI embeddings, no Pinecone:

- encoder: all-MiniLM-L6-v2 (sentence similarity, int8 ONNX, 23 MB), run with
  ONNX Runtime and the tokenization in transformer_classifier.py;
- store: a numpy matrix of unit vectors; lookup is one matrix-vector product
  (well under a millisecond for tens of thousands of attacks).

The general-purpose sentence model is deliberate. The fine-tuned classifier
answers "is this an attack?"; this layer answers "is this a known attack,
reworded?", which is what a similarity model is trained for.

SEED AND SELF-HARDENING
-----------------------
models/attack_memory/seed.npz holds the attacks from the training data
(build_attack_memory.py), with the similarity threshold calibrated there.
At runtime the memory learns (learn()):

- from canary leaks — an attack got past every detector and disclosed the
  system prompt (Rebuff's rule);
- from high-confidence LLM-tier blocks — attacks the cheap tiers missed, so
  the next rewording is caught locally without an LLM call.

Learned attacks go to data/attack_memory/learned.jsonl and are reloaded at
start-up. On hosts with an ephemeral disk (Railway without a volume) they last
until the next deploy; the seed is always there.

Fails open like ml_detector: missing files or onnxruntime mean "no opinion".
"""

import json
import logging
import os
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MEMORY_DIR = os.path.join(HERE, "models", "attack_memory")
ENCODER_DIR = os.path.join(MEMORY_DIR, "encoder")
SEED_PATH = os.path.join(MEMORY_DIR, "seed.npz")
LEARNED_PATH = os.path.join(HERE, "data", "attack_memory", "learned.jsonl")

# Learned attacks closer than this to something already stored add nothing.
DUPLICATE_SIMILARITY = 0.98
MAX_LEARNED = 5000
PREVIEW_CHARS = 80

logger = logging.getLogger("nexuscore.attack_memory")


class SentenceEncoder:
    """all-MiniLM-L6-v2 via ONNX Runtime: mean-pooled, L2-normalised."""

    def __init__(self, model_dir=ENCODER_DIR, max_length=256, batch_size=32):
        self.model_dir = model_dir
        self.max_length = max_length
        self.batch_size = batch_size
        self._session = None
        self._lock = threading.Lock()

    def _load(self):
        if self._session is not None:
            return
        with self._lock:
            if self._session is not None:
                return
            import onnxruntime as ort
            from transformer_classifier import load_tokenizer

            options = ort.SessionOptions()
            options.log_severity_level = 3
            self._tokenizer = load_tokenizer(os.path.join(self.model_dir, "tokenizer.json"))
            self._pad_id = self._tokenizer.token_to_id("[PAD]") or 0
            self._session = ort.InferenceSession(
                os.path.join(self.model_dir, "model.onnx"), options,
                providers=["CPUExecutionProvider"])

    def encode(self, texts):
        import numpy as np
        from transformer_classifier import encode, pad_batch

        self._load()
        seqs = encode(self._tokenizer, list(texts), self.max_length)
        order = sorted(range(len(seqs)), key=lambda i: len(seqs[i]))
        out = np.zeros((len(seqs), 384), dtype=np.float32)
        for start in range(0, len(order), self.batch_size):
            idx = order[start:start + self.batch_size]
            ids, mask = pad_batch([seqs[i] for i in idx], self._pad_id)
            hidden = self._session.run(None, {
                "input_ids": ids, "attention_mask": mask,
                "token_type_ids": np.zeros_like(ids)})[0]
            m = mask[..., None].astype(np.float32)
            pooled = (hidden * m).sum(1) / np.clip(m.sum(1), 1e-9, None)
            pooled /= np.clip(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-12, None)
            out[idx] = pooled
        return out


class AttackMemory:
    """Seed attacks plus learned ones; nearest-neighbour lookup by cosine."""

    def __init__(self, encoder, vectors, entries, threshold, learned_path=LEARNED_PATH):
        import numpy as np

        self.encoder = encoder
        self.vectors = np.asarray(vectors, dtype=np.float32)
        self.entries = list(entries)          # [{"source": ..., "preview": ...}]
        self.threshold = float(threshold)
        self.learned_path = learned_path
        self.n_seed = len(self.entries)
        self.hits = 0
        self._lock = threading.Lock()

    @property
    def size(self):
        return len(self.entries)

    @property
    def n_learned(self):
        return self.size - self.n_seed

    def similarity(self, text):
        """(best cosine similarity, matching entry) for one prompt."""
        vec = self.encoder.encode([text])[0]
        with self._lock:
            if not self.size:
                return 0.0, None
            sims = self.vectors @ vec
            best = int(sims.argmax())
            return float(sims[best]), self.entries[best]

    def check(self, text):
        """Verdict dict in the shape the other Layer 2 tiers use."""
        score, entry = self.similarity(text)
        matched = score >= self.threshold
        if matched:
            self.hits += 1
        return {
            "available": True,
            "is_malicious": matched,
            "confidence": round(score, 4),
            "threshold": round(self.threshold, 3),
            # The source only, never the stored text: learned entries are
            # other users' prompts.
            "matched_source": entry["source"] if entry else None,
            "detection_method": "attack_memory",
        }

    def learn(self, text, source, persist=True):
        """Remember a confirmed attack. Returns False if already known."""
        import numpy as np

        text = (text or "").strip()
        if not text:
            return False
        vec = self.encoder.encode([text])[0]
        with self._lock:
            if self.size and float((self.vectors @ vec).max()) >= DUPLICATE_SIMILARITY:
                return False
            if self.n_learned >= MAX_LEARNED:
                return False
            self.vectors = np.vstack([self.vectors, vec[None, :]])
            self.entries.append({"source": source, "preview": _preview(text)})
        if persist and self.learned_path:
            try:
                os.makedirs(os.path.dirname(self.learned_path), exist_ok=True)
                with open(self.learned_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"text": text, "source": source,
                                         "learned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                                        ensure_ascii=False) + "\n")
            except OSError as exc:
                logger.warning("attack memory: could not persist a learned attack: %s", exc)
        if persist:                           # not when reloading at start-up
            logger.warning("attack memory: learned a new attack (%s); %d learned in total",
                           source, self.n_learned)
        return True

    def stats(self):
        return {"available": True, "size": self.size, "seed": self.n_seed,
                "learned": self.n_learned, "hits": self.hits,
                "threshold": round(self.threshold, 3)}


def _preview(text):
    text = " ".join(text.split())
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS - 3] + "..."


_memory = None
_load_failed = False
_load_lock = threading.Lock()


def load(seed_path=SEED_PATH, learned_path=LEARNED_PATH, encoder_dir=ENCODER_DIR):
    """Build an AttackMemory from the seed file and any learned attacks."""
    import numpy as np

    seed = np.load(seed_path, allow_pickle=False)
    entries = [{"source": str(s), "preview": str(p)}
               for s, p in zip(seed["sources"], seed["previews"])]
    vectors = seed["vectors"].astype(np.float32)
    if seed["vectors"].dtype == np.int8:      # stored quantised (build_attack_memory)
        vectors /= 127.0
        vectors /= np.clip(np.linalg.norm(vectors, axis=1, keepdims=True), 1e-12, None)
    memory = AttackMemory(SentenceEncoder(encoder_dir), vectors, entries,
                          float(seed["threshold"]), learned_path)
    if learned_path and os.path.exists(learned_path):
        with open(learned_path, encoding="utf-8") as fh:
            learned = [json.loads(line) for line in fh if line.strip()]
        for item in learned[-MAX_LEARNED:]:
            memory.learn(item["text"], item.get("source", "learned"), persist=False)
    memory.encoder.encode(["warm-up"])        # fail here, not on a request
    return memory


def get_memory():
    """The shared memory, or None if it cannot be loaded (fails open)."""
    global _memory, _load_failed
    if _memory is not None or _load_failed:
        return _memory
    with _load_lock:
        if _memory is None and not _load_failed:
            try:
                _memory = load()
            except Exception as exc:
                _load_failed = True
                logger.warning("attack memory unavailable: %s: %s", type(exc).__name__, exc)
    return _memory


def reset_cache():
    """Drop the cached memory. For tests that swap files."""
    global _memory, _load_failed
    with _load_lock:
        _memory = None
        _load_failed = False
