"""LLM model choices shared by defense.py and target.py.

Providers retire models: the old default, llama-3.3-70b-versatile, now fails
every Groq call with 404 model_not_found, which the dashboard shows only as
"Target System Unavailable". Both names can be overridden from the environment
or backend/.streamlit/secrets.toml (GROQ_MODEL, GEMINI_MODEL).
"""

import os

GROQ_MODEL = os.environ.get("GROQ_MODEL") or "openai/gpt-oss-120b"
GEMINI_MODEL = os.environ.get("GEMINI_MODEL") or "gemini-2.5-flash-lite"


def groq_extra_body(model=None):
    """Request fields for reasoning models, passed via extra_body.

    gpt-oss and Qwen3 think before they answer, and the thinking counts
    against max_tokens: with the guardrail's small budget a model can spend it
    all thinking and return an empty verdict, which silently degrades to the
    regex fallback. Low (gpt-oss) or no (Qwen3) reasoning keeps short calls
    short. extra_body rather than a keyword argument, so older groq SDKs that
    predate reasoning_effort still work.
    """
    name = (model or GROQ_MODEL).lower()
    if "gpt-oss" in name:
        return {"reasoning_effort": "low"}
    if "qwen3" in name:
        return {"reasoning_effort": "none"}
    return None
