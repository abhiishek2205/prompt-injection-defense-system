"""Runtime for the fine-tuned transformer detector (ONNX Runtime, no PyTorch).

train_transformer.py fine-tunes MiniLM-L6 to classify prompts, exports it to
ONNX and quantizes it to int8. This module is what production runs: the
`tokenizers` library for tokenization and ONNX Runtime for the forward pass,
~80 MB of dependencies instead of PyTorch's several hundred.

It exposes predict_proba() like a scikit-learn classifier, so the saved bundle
still has a "pipeline" that ml_detector.predict() calls unchanged.
AveragedClassifier combines it with the TF-IDF pipeline.

Tokenization must match training exactly, so encode() here is the one both
sides use: long prompts keep their first and last tokens (head + tail), since
injections are often appended to the end of otherwise harmless text.
"""

import os
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_LENGTH = 256


def encode(tokenizer, texts, max_length=MAX_LENGTH):
    """Token ids with [CLS]/[SEP], head + tail truncated to max_length.

    tokenizer: a `tokenizers.Tokenizer` with padding and truncation disabled.
    """
    cls_id = tokenizer.token_to_id("[CLS]")
    sep_id = tokenizer.token_to_id("[SEP]")
    room = max_length - 2
    out = []
    for enc in tokenizer.encode_batch([t if t else " " for t in texts],
                                      add_special_tokens=False):
        ids = enc.ids
        if len(ids) > room:
            head = room // 2
            ids = ids[:head] + ids[-(room - head):]
        out.append([cls_id] + ids + [sep_id])
    return out


def load_tokenizer(path):
    from tokenizers import Tokenizer

    tokenizer = Tokenizer.from_file(path)
    # The published tokenizer.json pads and truncates to a fixed 128; both are
    # done by hand in encode() instead.
    tokenizer.no_padding()
    tokenizer.no_truncation()
    return tokenizer


def pad_batch(seqs, pad_id):
    import numpy as np

    width = max(len(s) for s in seqs)
    ids = np.full((len(seqs), width), pad_id, dtype=np.int64)
    mask = np.zeros((len(seqs), width), dtype=np.int64)
    for i, seq in enumerate(seqs):
        ids[i, :len(seq)] = seq
        mask[i, :len(seq)] = 1
    return ids, mask


class TransformerClassifier:
    """predict_proba() over a fine-tuned ONNX classifier.

    model_dir is relative to backend/ so the pickled bundle is portable. The
    ONNX session is created on first use and never pickled.
    """

    classes_ = [0, 1]

    def __init__(self, model_dir, max_length=MAX_LENGTH, batch_size=32):
        self.model_dir = model_dir
        self.max_length = max_length
        self.batch_size = batch_size

    def _path(self, name):
        return os.path.join(HERE, self.model_dir, name)

    def _load(self):
        if getattr(self, "_session", None) is not None:
            return
        lock = self.__dict__.setdefault("_lock", threading.Lock())
        with lock:
            if getattr(self, "_session", None) is not None:
                return
            import onnxruntime as ort

            options = ort.SessionOptions()
            options.log_severity_level = 3
            self._tokenizer = load_tokenizer(self._path("tokenizer.json"))
            self._pad_id = self._tokenizer.token_to_id("[PAD]") or 0
            self._session = ort.InferenceSession(
                self._path("model.onnx"), options,
                providers=["CPUExecutionProvider"])

    def logits(self, texts):
        import numpy as np

        self._load()
        seqs = encode(self._tokenizer, list(texts), self.max_length)
        # Length-sorted batches pad to similar widths; order is restored.
        order = sorted(range(len(seqs)), key=lambda i: len(seqs[i]))
        out = np.zeros((len(seqs), 2), dtype=np.float32)
        for start in range(0, len(order), self.batch_size):
            idx = order[start:start + self.batch_size]
            ids, mask = pad_batch([seqs[i] for i in idx], self._pad_id)
            out[idx] = self._session.run(
                None, {"input_ids": ids, "attention_mask": mask})[0]
        return out

    def predict_proba(self, texts):
        import numpy as np

        # float64: a confident fine-tuned model has logit margins of 15-20,
        # and float32 rounds softmax of those to exactly 1.0. Ties at 1.0 make
        # every high-scoring prompt look identical to the threshold rule.
        z = self.logits(texts).astype(np.float64)
        z = z - z.max(axis=1, keepdims=True)
        e = np.exp(z)
        return e / e.sum(axis=1, keepdims=True)

    def __getstate__(self):
        state = dict(self.__dict__)
        for key in ("_session", "_tokenizer", "_lock", "_pad_id"):
            state.pop(key, None)
        return state


class AveragedClassifier:
    """Weighted mean of several predict_proba() models."""

    classes_ = [0, 1]

    def __init__(self, members, weights=None):
        self.members = list(members)
        self.weights = list(weights) if weights else [1.0] * len(self.members)

    def predict_proba(self, texts):
        texts = list(texts)
        total = sum(self.weights)
        return sum(w * m.predict_proba(texts)
                   for m, w in zip(self.members, self.weights)) / total
