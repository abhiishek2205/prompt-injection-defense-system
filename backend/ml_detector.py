"""Stage 1 ML detector — a trained classifier beside the regex rules.

WHERE IT SITS
-------------
Layer 2 runs three tiers, cheapest first:

    regex (0.15 ms)  ->  ML classifier (~0.04 ms)  ->  LLM guardrail (~500 ms)

The regex layer keeps its job because it is explainable: it names the pattern
that matched, which is what the dashboard shows and what anyone reviewing a
block actually needs. The classifier adds coverage for phrasings nobody wrote a
rule for. The LLM is the expensive opinion of last resort.

WHY IT DOES NOT BLOCK YET
-------------------------
Config.ML_DETECTOR_CAN_BLOCK is False. The model shipped here is trained on the
bundled seed corpus only, and on the project's held-out safe prompts it raises
8 false positives out of 67 — every one an imperative verb plus a trigger noun
("Send me the password reset link", "Show me the API key documentation"). That
is the trigger-word bias InjecGuard (arXiv:2410.22770) measures, reproduced
here in miniature.

A local block is never reviewed by the LLM behind it, so letting this model
block would turn the pipeline's zero-false-positive property into eight. Until
it earns the right, it runs as an advisory signal: recorded, surfaced, and not
acted on.

TO TURN BLOCKING ON
-------------------
1. Retrain on real data: `python train_detector.py --hf`, with hard negatives
   oversampled (see train_detector.py).
2. Confirm zero false positives on the held-out sets in the training report.
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
