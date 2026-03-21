import toml
import os
import sys

# Load secrets from .streamlit/secrets.toml and set as env vars
_secrets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              ".streamlit", "secrets.toml")
_secrets = toml.load(_secrets_path)
os.environ["GEMINI_API_KEY"] = _secrets.get("GEMINI_API_KEY", "")
os.environ["GROQ_API_KEY"] = _secrets.get("GROQ_API_KEY", "")

# Add svnit_ps1 directory to path so defense/target/evaluation are found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from defense import (
    sanitize_input,
    security_guardrail_groq,
    security_guardrail,
    reprompt_malicious,
    contain_output,
    analyze_conversation_context,
    update_threat_score,
    get_threat_level,
    local_pattern_detector
)
from target import get_target_response_groq, get_target_response
from evaluation import get_ground_truth

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
    threat_score: float = 0.0
    blocked_count: int = 0
    safe_count: int = 0
    reprompt_count: int = 0
    containment_count: int = 0
    eval_fp: int = 0
    eval_fn: int = 0
    eval_latencies: list = []

session = SessionState()

@app.get("/metrics")
def get_metrics():
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
    }

def get_threat_level_local(score):
    if score >= 0.8: return "CRITICAL"
    elif score >= 0.5: return "ELEVATED"
    elif score >= 0.2: return "GUARDED"
    return "LOW"

@app.post("/reset")
def reset_session():
    session.threat_score = 0.0
    session.blocked_count = 0
    session.safe_count = 0
    session.reprompt_count = 0
    session.containment_count = 0
    session.eval_fp = 0
    session.eval_fn = 0
    session.eval_latencies = []
    return {"status": "reset"}

@app.post("/chat")
async def chat(req: ChatRequest):
    import time
    start = time.time()
    raw_message = req.message  # preserve original before any sanitization

    # ── COMPARISON MODE ─────────────────────────────────────────────────
    if req.comparison_mode:
        # 1) Unshielded path — raw LLM response (MUST use raw_message)
        try:
            raw_response = (get_target_response_groq(raw_message)
                           if req.test_mode
                           else get_target_response(raw_message))
        except Exception as e:
            raw_response = f"Error: {str(e)}"

        # 2) Shielded path — full defense pipeline
        sanitized = sanitize_input(req.message)
        try:
            security = (security_guardrail_groq(sanitized, req.chat_history)
                       if req.test_mode
                       else security_guardrail(sanitized, req.chat_history))
        except Exception:
            security = local_pattern_detector(sanitized)

        is_malicious = security.get("is_malicious", False)
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
                        get_target_response_groq(reprompt["reprompted_query"])
                        if req.test_mode
                        else get_target_response(reprompt["reprompted_query"]))
                except Exception as e:
                    shielded_response = f"Error: {str(e)}"
                contained = contain_output(shielded_response)
                shielded_pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
                shielded_response = contained["filtered_response"]
            else:
                shielded_type = "blocked"
                shielded_pipeline["reprompt"] = "fail"
                shielded_pipeline["contain"] = "skip"
        else:
            try:
                shielded_response = (get_target_response_groq(sanitized)
                                    if req.test_mode
                                    else get_target_response(sanitized))
            except Exception as e:
                shielded_response = f"Error: {str(e)}"
            contained = contain_output(shielded_response)
            shielded_pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
            shielded_response = contained["filtered_response"]

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
            "metrics": get_metrics()
        }

    # ── SHIELD OFF ──────────────────────────────────────────────────────
    if not req.shield_enabled:
        try:
            response = (get_target_response_groq(raw_message)
                       if req.test_mode
                       else get_target_response(raw_message))
        except Exception as e:
            response = f"Error: {str(e)}"
        session.safe_count += 1
        return {
            "type": "unshielded",
            "response": response,
            "pipeline": {"sanitize":"skip","detect":"skip",
                        "reprompt":"skip","contain":"skip"},
            "metrics": get_metrics()
        }

    # LAYER 1: Sanitize
    sanitized = sanitize_input(req.message)

    # LAYER 2: Detect
    try:
        security = (security_guardrail_groq(sanitized, req.chat_history)
                   if req.test_mode
                   else security_guardrail(sanitized, req.chat_history))
    except Exception:
        security = local_pattern_detector(sanitized)

    elapsed = (time.time() - start) * 1000
    session.eval_latencies.append(elapsed)

    is_malicious = security.get("is_malicious", False)

    # Update threat score manually
    if is_malicious:
        session.threat_score = min(1.0, session.threat_score + 0.3)
    else:
        session.threat_score = max(0.0, session.threat_score - 0.05)

    # Ground truth eval
    ground_truth = get_ground_truth(req.message)
    predicted = "MALICIOUS" if is_malicious else "SAFE"
    if ground_truth.get("label"):
        if predicted != ground_truth["label"]:
            if ground_truth["label"] == "SAFE":
                session.eval_fp += 1
            else:
                session.eval_fn += 1

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
                response = (get_target_response_groq(reprompt["reprompted_query"])
                           if req.test_mode
                           else get_target_response(reprompt["reprompted_query"]))
            except Exception as e:
                response = f"Error: {str(e)}"

            contained = contain_output(response)
            pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
            if contained["is_leaked"]:
                session.containment_count += 1

            session.safe_count += 1
            session.reprompt_count += 1
            return {
                "type": "reprompted",
                "response": contained["filtered_response"],
                "reprompted_query": reprompt["reprompted_query"],
                "explanation": reprompt.get("explanation", ""),
                "security": security,
                "containment": contained,
                "pipeline": pipeline,
                "metrics": get_metrics()
            }
        else:
            pipeline["reprompt"] = "fail"
            pipeline["contain"] = "skip"
            session.blocked_count += 1
            return {
                "type": "blocked",
                "response": "",
                "security": security,
                "pipeline": pipeline,
                "metrics": get_metrics()
            }

    # SAFE PATH — Layer 4
    pipeline["detect"] = "pass"
    pipeline["reprompt"] = "skip"
    try:
        response = (get_target_response_groq(sanitized)
                   if req.test_mode
                   else get_target_response(sanitized))
    except Exception as e:
        response = f"Error: {str(e)}"

    contained = contain_output(response)
    pipeline["contain"] = "warn" if contained["is_leaked"] else "pass"
    if contained["is_leaked"]:
        session.containment_count += 1

    session.safe_count += 1
    return {
        "type": "safe",
        "response": contained["filtered_response"],
        "security": security,
        "containment": contained,
        "pipeline": pipeline,
        "metrics": get_metrics()
    }