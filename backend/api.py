import os
import sys

# Secrets loader — works in BOTH environments:
# Local dev: reads from .streamlit/secrets.toml
# Production: reads from Railway environment variables
_secrets_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    ".streamlit", "secrets.toml"
)
if os.path.exists(_secrets_path):
    try:
        import toml
        _secrets = toml.load(_secrets_path)
        os.environ.setdefault("GEMINI_API_KEY",
            _secrets.get("GEMINI_API_KEY", ""))
        os.environ.setdefault("GROQ_API_KEY",
            _secrets.get("GROQ_API_KEY", ""))
        for _name in ("GROQ_MODEL", "GEMINI_MODEL"):
            if _secrets.get(_name):
                os.environ.setdefault(_name, _secrets[_name])
    except Exception:
        pass

# Say which keys are missing at start-up (never their values): without them
# every LLM call degrades to "Target System Unavailable" with no other clue.
import logging as _logging
for _key, _mode in (("GROQ_API_KEY", "test mode (Groq)"),
                    ("GEMINI_API_KEY", "production mode (Gemini)")):
    if not os.environ.get(_key):
        _logging.getLogger("nexuscore.api").warning(
            "%s is not set: %s will answer 'Target System Unavailable'. "
            "Add it to backend/.streamlit/secrets.toml (not the .example file) "
            "and restart the server.", _key, _mode)

# Add svnit_ps1 directory to path so defense/target/evaluation are found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import re
import threading
import time
from collections import OrderedDict
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from defense import (
    Config,
    sanitize_input,
    security_guardrail_groq,
    security_guardrail,
    reprompt_malicious,
    contain_output,
    analyze_conversation_context,
    local_pattern_detector,
    ml_opinion,
    attach_ml_opinion,
    attach_memory_opinion,
    new_canary,
    set_protected_values,
)
from target import PROTECTED_VALUES, get_target_response_groq, get_target_response
from evaluation import get_ground_truth

# Containment redacts these wherever they appear, whatever surrounds them.
set_protected_values(PROTECTED_VALUES)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    message: str
    shield_enabled: bool = True
    test_mode: bool = True
    chat_history: list = []
    comparison_mode: bool = False

class SessionState:
    """Counters and threat score for one browser session.

    Every field is set in reset() (never as a class attribute), because a
    class-level list would be shared across instances and would not be
    replaced by reset().
    """

    def __init__(self):
        self.last_seen = time.monotonic()
        self.reset()

    def reset(self):
        self.threat_score = 0.0
        self.blocked_count = 0
        self.safe_count = 0
        self.reprompt_count = 0
        self.containment_count = 0
        self.eval_fp = 0
        self.eval_fn = 0
        self.eval_latencies = []
        # Shadow mode: what the ML tier would have done, next to what the
        # pipeline actually did. This is the evidence for (or against)
        # enabling Config.ML_DETECTOR_CAN_BLOCK on real traffic.
        self.ml_scored = 0
        self.ml_flagged = 0
        self.ml_would_add = 0      # ML flagged, pipeline let it through
        self.ml_missed = 0         # pipeline caught it, ML did not flag it
        self.ml_eval_fp = 0        # vs. ground truth, labeled prompts only
        self.ml_eval_fn = 0


# ── Sessions ─────────────────────────────────────────────────────────────────
# Each browser tab sends a random id in the X-Session-Id header, so two people
# using the demo at once get their own threat score and metrics: one judge's
# attacks must not make the other's harmless questions look suspicious.
# Requests without the header (curl, tests, older clients) share one default
# session. The attack memory stays global on purpose: an attack learned from
# one visitor protects everyone.

SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
DEFAULT_SESSION_ID = "default"
SESSION_IDLE_SECONDS = 6 * 3600
MAX_SESSIONS = 2000


class SessionStore:
    """Sessions by id, least recently used first; idle ones are dropped."""

    def __init__(self, idle_seconds=SESSION_IDLE_SECONDS, max_sessions=MAX_SESSIONS):
        self.idle_seconds = idle_seconds
        self.max_sessions = max_sessions
        self._sessions = OrderedDict()
        self._lock = threading.Lock()

    def get(self, session_id: str) -> SessionState:
        now = time.monotonic()
        with self._lock:
            state = self._sessions.pop(session_id, None) or SessionState()
            state.last_seen = now
            self._sessions[session_id] = state
            while len(self._sessions) > 1:
                oldest = next(iter(self._sessions.values()))
                if (len(self._sessions) <= self.max_sessions
                        and now - oldest.last_seen <= self.idle_seconds):
                    break
                self._sessions.popitem(last=False)
            return state

    def __len__(self):
        return len(self._sessions)

    def clear(self):
        with self._lock:
            self._sessions.clear()


sessions = SessionStore()


def current_session(x_session_id: Optional[str] = Header(default=None)) -> SessionState:
    """FastAPI dependency: the caller's session, from the X-Session-Id header."""
    if x_session_id is None:
        return sessions.get(DEFAULT_SESSION_ID)
    if not SESSION_ID_PATTERN.match(x_session_id):
        raise HTTPException(status_code=400,
                            detail="X-Session-Id must be 8-64 letters, digits, '-' or '_'.")
    return sessions.get(x_session_id)


def _update_threat_score(session: SessionState, is_malicious: bool) -> float:
    """Advance the session threat score using the shared Config constants."""
    if is_malicious:
        session.threat_score = min(Config.THREAT_SCORE_MAX,
                                   session.threat_score + Config.THREAT_SCORE_INCREMENT)
    else:
        session.threat_score = max(0.0,
                                   session.threat_score - Config.THREAT_SCORE_DECAY)
    return session.threat_score


def _record_ground_truth(session: SessionState, message: str, is_malicious: bool):
    """Score the verdict against the labeled test set, if the prompt is in it."""
    ground_truth = get_ground_truth(message)
    if not ground_truth.get("label"):
        return
    predicted = "MALICIOUS" if is_malicious else "SAFE"
    if predicted != ground_truth["label"]:
        if ground_truth["label"] == "SAFE":
            session.eval_fp += 1
        else:
            session.eval_fn += 1


def _public_containment(contained: dict) -> dict:
    """Containment result for the client, without the unredacted reply.

    contain_output() keeps "original_response" for server-side use; sending it
    to the browser would hand over exactly what containment just redacted —
    leaked credentials and the canary token.
    """
    return {k: v for k, v in contained.items() if k != "original_response"}


def _remember_attack(sanitized: str, source: str):
    """Self-hardening: store a confirmed attack in the attack memory, so its
    next rewording is caught locally. Best effort — never breaks a request."""
    if not Config.ATTACK_MEMORY_LEARN:
        return
    try:
        import attack_memory
        memory = attack_memory.get_memory()
        if memory is not None:
            memory.learn(sanitized, source)
    except Exception as exc:
        _logging.getLogger("nexuscore.api").warning(
            "attack memory: could not learn (%s: %s)", type(exc).__name__, exc)


def _learn_from_verdict(sanitized: str, security: dict):
    """Remember attacks the LLM tier blocked with high confidence: the cheap
    tiers missed them, and next time the memory will not."""
    if (security.get("is_malicious")
            and security.get("detection_method") in ("groq_llm", "gemini_llm")
            and float(security.get("confidence", 0)) >= Config.ATTACK_MEMORY_LEARN_MIN_CONFIDENCE):
        _remember_attack(sanitized, "llm_block")


def _memory_stats() -> dict:
    try:
        import attack_memory
        memory = attack_memory.get_memory()
        return memory.stats() if memory is not None else {"available": False}
    except Exception:
        return {"available": False}


def _record_ml_shadow(session: SessionState, message: str, security: dict, is_malicious: bool):
    """Count the ML tier's opinion against the pipeline's verdict.

    The pipeline verdict includes multi-turn detection, which the classifier
    does not see; a disagreement is not automatically the classifier's error.
    Where the prompt is in the labeled test set, also score it against ground
    truth — the direct measure of what blocking would cost or gain.
    """
    opinion = security.get("ml_opinion") or {}
    if not opinion.get("available"):
        return
    flagged = bool(opinion.get("is_malicious"))
    session.ml_scored += 1
    session.ml_flagged += flagged
    session.ml_would_add += flagged and not is_malicious
    session.ml_missed += is_malicious and not flagged

    label = get_ground_truth(message).get("label")
    if label == "SAFE" and flagged:
        session.ml_eval_fp += 1
    elif label == "MALICIOUS" and not flagged:
        session.ml_eval_fn += 1


def _detect(req, sanitized, session: SessionState):
    """Layer 2 for both the shielded and comparison paths.

    Runs single-turn detection, then multi-turn detection over the recent
    window so payload-splitting attacks are caught even when each individual
    message looks benign. The threat score is passed explicitly — defense.py
    cannot reach our session state on its own.
    """
    score = session.threat_score
    try:
        security = (security_guardrail_groq(sanitized, req.chat_history, score)
                    if req.test_mode
                    else security_guardrail(sanitized, req.chat_history, score))
    except Exception:
        security = attach_ml_opinion(local_pattern_detector(sanitized, score),
                                     ml_opinion(sanitized))

    if not security.get("is_malicious", False):
        history = list(req.chat_history) + [{"role": "user", "content": req.message}]
        try:
            multi = analyze_conversation_context(history, score)
        except Exception:
            multi = {"is_suspicious": False}
        if multi.get("is_suspicious"):
            multi_memory = security.get("memory_opinion")
            security = attach_ml_opinion({
                "is_malicious": True,
                "reason": multi.get("reason", "Multi-turn attack detected"),
                "confidence": multi.get("confidence", 0.75),
                "detection_method": "multi_turn",
            }, security.get("ml_opinion"))
            security = attach_memory_opinion(security, multi_memory)
    return security


@app.get("/metrics")
def get_metrics(session: SessionState = Depends(current_session)):
    avg_lat = (sum(session.eval_latencies) /
               len(session.eval_latencies)) if session.eval_latencies else 0
    return {
        "blocked": session.blocked_count,
        "safe": session.safe_count,
        "reprompted": session.reprompt_count,
        "contained": session.containment_count,
        "false_positives": session.eval_fp,
        "false_negatives": session.eval_fn,
        "avg_latency": round(avg_lat, 1),
        "threat_score": round(session.threat_score, 2),
        "threat_level": get_threat_level_local(session.threat_score),
        "total_queries": len(session.eval_latencies),
        "attack_memory": _memory_stats(),
        "ml_shadow": {
            "can_block": Config.ML_DETECTOR_CAN_BLOCK,
            "scored": session.ml_scored,
            "flagged": session.ml_flagged,
            "would_add": session.ml_would_add,
            "missed": session.ml_missed,
            "false_positives": session.ml_eval_fp,
            "false_negatives": session.ml_eval_fn,
        },
    }

def get_threat_level_local(score):
    if score >= 0.8: return "CRITICAL"
    elif score >= 0.5: return "ELEVATED"
    elif score >= 0.2: return "GUARDED"
    return "LOW"

@app.post("/reset")
def reset_session(session: SessionState = Depends(current_session)):
    session.reset()
    return {"status": "reset"}

@app.post("/chat")
async def chat(req: ChatRequest, session: SessionState = Depends(current_session)):
    start = time.time()
    raw_message = req.message  # preserve original before any sanitization
    # One canary per request: it goes into the target's system prompt, and
    # contain_output() treats its appearance in a reply as a prompt leak.
    canary = new_canary()

    # ── COMPARISON MODE ─────────────────────────────────────────────────
    if req.comparison_mode:
        # 1) Unshielded path — raw LLM response (MUST use raw_message)
        try:
            raw_response = (get_target_response_groq(raw_message, canary=canary)
                           if req.test_mode
                           else get_target_response(raw_message, canary=canary))
        except Exception as e:
            raw_response = f"Error: {str(e)}"

        # 2) Shielded path — full defense pipeline
        sanitized = sanitize_input(req.message)
        security = _detect(req, sanitized, session)
        _learn_from_verdict(sanitized, security)

        is_malicious = security.get("is_malicious", False)
        _update_threat_score(session, is_malicious)
        _record_ground_truth(session, req.message, is_malicious)
        _record_ml_shadow(session, req.message, security, is_malicious)
        shielded_type = "safe"
        shielded_response = ""
        shielded_pipeline = {"sanitize": "pass", "detect": "pass",
                             "reprompt": "skip", "contain": "skip"}

        if is_malicious:
            shielded_pipeline["detect"] = "fail"
            try:
                reprompt = reprompt_malicious(sanitized, security,
                                              use_groq=req.test_mode)
            except Exception:
                reprompt = {"can_reprompt": False, "reprompted_query": "",
                           "explanation": "Reprompt failed"}

            if reprompt.get("can_reprompt") and reprompt.get("reprompted_query"):
                shielded_type = "reprompted"
                shielded_pipeline["reprompt"] = "warn"
                try:
                    shielded_response = (
                        get_target_response_groq(reprompt["reprompted_query"], canary=canary)
                        if req.test_mode
                        else get_target_response(reprompt["reprompted_query"], canary=canary))
                except Exception as e:
                    shielded_response = f"Error: {str(e)}"
                contained = contain_output(shielded_response, canary=canary)
                if contained["canary_detected"]:
                    _remember_attack(sanitized, "canary_leak")
                shielded_pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
                shielded_response = contained["filtered_response"]
                if contained["is_leaked"]:
                    session.containment_count += 1
                session.reprompt_count += 1
                session.safe_count += 1
            else:
                shielded_type = "blocked"
                shielded_pipeline["reprompt"] = "fail"
                shielded_pipeline["contain"] = "skip"
                session.blocked_count += 1
        else:
            try:
                shielded_response = (get_target_response_groq(sanitized, canary=canary)
                                    if req.test_mode
                                    else get_target_response(sanitized, canary=canary))
            except Exception as e:
                shielded_response = f"Error: {str(e)}"
            contained = contain_output(shielded_response, canary=canary)
            if contained["canary_detected"]:
                _remember_attack(sanitized, "canary_leak")
            shielded_pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
            shielded_response = contained["filtered_response"]
            if contained["is_leaked"]:
                session.containment_count += 1
            session.safe_count += 1

        elapsed = (time.time() - start) * 1000
        session.eval_latencies.append(elapsed)

        return {
            "type": "comparison",
            "shielded": {
                "type": shielded_type,
                "response": shielded_response,
                "security": security,
                "pipeline": shielded_pipeline,
            },
            "unshielded": {
                "type": "unshielded",
                "response": raw_response,
            },
            "metrics": get_metrics(session)
        }

    # ── SHIELD OFF ──────────────────────────────────────────────────────
    if not req.shield_enabled:
        try:
            response = (get_target_response_groq(raw_message, canary=canary)
                       if req.test_mode
                       else get_target_response(raw_message, canary=canary))
        except Exception as e:
            response = f"Error: {str(e)}"
        session.safe_count += 1
        session.eval_latencies.append((time.time() - start) * 1000)
        return {
            "type": "unshielded",
            "response": response,
            "pipeline": {"sanitize":"skip","detect":"skip",
                        "reprompt":"skip","contain":"skip"},
            "metrics": get_metrics(session)
        }

    # LAYER 1: Sanitize
    sanitized = sanitize_input(req.message)

    # LAYER 2: Detect (single-turn + multi-turn, threat score applied)
    # _detect() reads the threat score from before this message, so the
    # elevated-threat boost reflects the session's prior history; the score is
    # advanced afterwards.
    security = _detect(req, sanitized, session)
    _learn_from_verdict(sanitized, security)

    is_malicious = security.get("is_malicious", False)
    _update_threat_score(session, is_malicious)
    _record_ground_truth(session, req.message, is_malicious)
    _record_ml_shadow(session, req.message, security, is_malicious)

    pipeline = {"sanitize": "pass", "detect": "pass",
                "reprompt": "skip", "contain": "skip"}

    # LAYER 3: Reprompt or Block
    if is_malicious:
        pipeline["detect"] = "fail"
        try:
            reprompt = reprompt_malicious(sanitized, security,
                                          use_groq=req.test_mode)
        except Exception:
            reprompt = {"can_reprompt": False, "reprompted_query": "",
                       "explanation": "Reprompt failed"}

        if reprompt.get("can_reprompt") and reprompt.get("reprompted_query"):
            pipeline["reprompt"] = "warn"
            try:
                response = (get_target_response_groq(reprompt["reprompted_query"], canary=canary)
                           if req.test_mode
                           else get_target_response(reprompt["reprompted_query"], canary=canary))
            except Exception as e:
                response = f"Error: {str(e)}"

            contained = contain_output(response, canary=canary)
            if contained["canary_detected"]:
                _remember_attack(sanitized, "canary_leak")
            pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
            if contained["is_leaked"]:
                session.containment_count += 1

            session.safe_count += 1
            session.reprompt_count += 1
            session.eval_latencies.append((time.time() - start) * 1000)
            return {
                "type": "reprompted",
                "response": contained["filtered_response"],
                "reprompted_query": reprompt["reprompted_query"],
                "explanation": reprompt.get("explanation", ""),
                "security": security,
                "containment": _public_containment(contained),
                "pipeline": pipeline,
                "metrics": get_metrics(session)
            }
        else:
            pipeline["reprompt"] = "fail"
            pipeline["contain"] = "skip"
            session.blocked_count += 1
            session.eval_latencies.append((time.time() - start) * 1000)
            return {
                "type": "blocked",
                "response": "",
                "security": security,
                "pipeline": pipeline,
                "metrics": get_metrics(session)
            }

    # SAFE PATH — Layer 4
    pipeline["detect"] = "pass"
    pipeline["reprompt"] = "skip"
    try:
        response = (get_target_response_groq(sanitized, canary=canary)
                   if req.test_mode
                   else get_target_response(sanitized, canary=canary))
    except Exception as e:
        response = f"Error: {str(e)}"

    contained = contain_output(response, canary=canary)
    if contained["canary_detected"]:
        _remember_attack(sanitized, "canary_leak")
    pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
    if contained["is_leaked"]:
        session.containment_count += 1

    session.safe_count += 1
    session.eval_latencies.append((time.time() - start) * 1000)
    return {
        "type": "safe",
        "response": contained["filtered_response"],
        "security": security,
        "containment": _public_containment(contained),
        "pipeline": pipeline,
        "metrics": get_metrics(session)
    }

class EvaluateRequest(BaseModel):
    message: str
    test_mode: bool = True


@app.post("/evaluate")
async def evaluate(req: EvaluateRequest):
    """Run one prompt through the shielded pipeline in a throwaway session.

    For the dashboard's scorecard: each prompt is judged on its own — no chat
    history, a threat score of zero — and the caller's session metrics and
    threat score are left untouched. Same response shape as /chat.
    """
    return await chat(ChatRequest(message=req.message, test_mode=req.test_mode,
                                  shield_enabled=True, comparison_mode=False,
                                  chat_history=[]),
                      session=SessionState())
