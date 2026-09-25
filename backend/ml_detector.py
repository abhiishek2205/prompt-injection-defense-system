"""ML detector — a trained classifier beside the regex rules.

WHERE IT SITS
-------------
Layer 2 runs three tiers, cheapest first:

    regex (0.15 ms)  ->  ML classifier (~4 ms)  ->  LLM guardrail (~500 ms)

The regex layer keeps its job because it is explainable: it names the pattern
that matched, which is what the dashboard shows and what anyone reviewing a
block actually needs. The classifier adds coverage for phrasings nobody wrote a
rule for. The LLM is the expensive opinion of last resort.

WHAT IS LOADED
--------------
models/detector.joblib holds a "pipeline" with predict_proba() and a
"threshold". The shipped one (train_transformer.py) averages a fine-tuned
MiniLM-L6 run through ONNX Runtime (transformer_classifier.py, model files in
models/transformer/) with a TF-IDF model. train_detector.py writes a TF-IDF-only
bundle in the same format. Either way this module is unchanged.

WHY IT DOES NOT BLOCK YET
-------------------------
Config.ML_DETECTOR_CAN_BLOCK is False: the classifier runs in shadow mode.
defense.ml_tier() consults it in both guardrails and attaches its opinion to
every verdict; api.py tallies what it would have done in /metrics ->
ml_shadow. The README's "Blocking decision" section lists the criteria for
turning blocking on.

The model passes the gate in tests/test_ml_detector.py — zero false positives
on every project safe set with blocking on. It stays advisory because
precision off the project's own sets is not good enough for a verdict nobody
reviews: 5.9% false positives on NotInject (benign prompts built around
trigger words) and 4.7% on PromptShield's test split.

The threshold comes from a held-back calibration split: at most 0.5% false
positives in every source, and none on the in-domain benign rows. See
train_detector.choose_threshold().

TO TURN BLOCKING ON
-------------------
1. Improve over-defense and retrain:
   `python fetch_datasets.py && python train_transformer.py`.
2. Check the report: zero false positives on the project sets, and a
   false-positive rate on NotInject / PromptShield you are willing to ship.
3. Flip Config.ML_DETECTOR_CAN_BLOCK to True.
4. Run `python -m pytest`. tests/test_ml_detector.py enforces that the
   pipeline's zero-false-positive rule still holds with blocking enabled; if
   the model is not good enough, that test fails and the flag goes back.
"""

import os
import threading

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "models", "detector.joblib")

_model = None
_load_failed = False
_lock = threading.Lock()


def _load():
    """Load the artifact once. A missing or broken model is not fatal."""
    global _model, _load_failed
    if _model is not None or _load_failed:
        return _model

    with _lock:
        if _model is not None or _load_failed:
            return _model
        try:
            import joblib
            bundle = joblib.load(MODEL_PATH)
            if "pipeline" not in bundle:
                raise ValueError("artifact has no 'pipeline' key")
            # Warm-up: a model with an embedding block needs its ONNX files
            # too. If they are missing this fails here, so the layer reports
            # itself unavailable instead of erroring on every request — and
            # the first real request does not pay the session start-up.
            bundle["pipeline"].predict_proba(["warm-up"])
            _model = bundle
        except Exception:
            # No model file, no scikit-learn, or an artifact from an
            # incompatible version. The rest of the pipeline is unaffected.
            _load_failed = True
        return _model


def is_available() -> bool:
    """True when a usable model is loaded."""
    return _load() is not None


def model_info() -> dict:
    """Provenance for the dashboard and for the training report."""
    bundle = _load()
    if bundle is None:
        return {"available": False}
    return {
        "available": True,
        "threshold": bundle.get("threshold"),
        "trained_at": bundle.get("trained_at"),
        "n_rows": bundle.get("n_rows"),
        "sources": bundle.get("sources", []),
        "sklearn_version": bundle.get("sklearn_version"),
        "kind": bundle.get("kind", "tfidf"),
    }


def predict(text: str) -> dict:
    """Score one prompt.

    Returns:
        dict with available (bool), is_malicious (bool), confidence (float,
        the model's probability that the text is an attack), threshold, and
        detection_method. When no model is loaded, available is False and the
        caller carries on as if this layer did not exist.
    """
    bundle = _load()
    if bundle is None or not text:
        return {"available": False, "is_malicious": False, "confidence": 0.0,
                "detection_method": "ml_unavailable"}

    try:
        probability = float(bundle["pipeline"].predict_proba([text])[0][1])
    except Exception:
        return {"available": False, "is_malicious": False, "confidence": 0.0,
                "detection_method": "ml_error"}

    threshold = float(bundle.get("threshold", 0.9))
    return {
        "available": True,
        "is_malicious": probability >= threshold,
        "confidence": round(probability, 4),
        "threshold": threshold,
        "detection_method": "ml_classifier",
    }


def reset_cache():
    """Drop the cached model. For tests that swap the artifact."""
    global _model, _load_failed
    with _lock:
        _model = None
        _load_failed = False
