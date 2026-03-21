"""
Prompt Injection Defense System - Main Application
A Streamlit-based UI for demonstrating LLM security guardrails.

IMPROVEMENTS ADDED:
- Preset attack demo buttons in sidebar (one-click demos)
- Defense pipeline visualization (Layer 1→2→3→4 status per query)
- Color-coded chat bubbles (green/red/yellow/orange)
- Side-by-side comparison mode (shield ON vs OFF)
- Session threat score display
- Per-category accuracy in evaluation dashboard
"""

import streamlit as st
import defense
import time
from evaluation import get_ground_truth, TEST_CASES
try:
    from evaluation import get_preset_attacks
except ImportError:
    def get_preset_attacks():
        return []

# Graceful fallback for target module
try:
    import target
    if not hasattr(target, 'get_target_response'):
        raise ImportError("target.py missing get_target_response function")
except ImportError:
    class MockTarget:
        def get_target_response(self, user_input: str):
            """Mock response when target.py is not available."""
            return f"[Mock Response] I received: {user_input}"
        def get_target_response_groq(self, user_input: str):
            return f"[Mock Response - Groq] I received: {user_input}"
    
    target = MockTarget()

# Page configuration
st.set_page_config(
    page_title="Prompt Injection Defense System",
    page_icon="🛡️",
    layout="wide"
)

# Initialize theme state
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

# Custom CSS based on theme
if st.session_state.dark_mode:
    # DARK THEME (Default)
    st.markdown("""
    <style>
        /* ====== DARK THEME ====== */
        .theme-btn button {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%) !important;
            color: #e0e0e0 !important;
            border: 1px solid #e94560 !important;
            border-radius: 20px !important;
        }
        
        /* Pipeline visualization */
        .pipeline-step {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            margin: 2px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .pipeline-pass { background: #1a472a; color: #4ade80; border: 1px solid #22c55e; }
        .pipeline-fail { background: #4a1a1a; color: #f87171; border: 1px solid #ef4444; }
        .pipeline-skip { background: #3a3a3a; color: #9ca3af; border: 1px solid #6b7280; }
        .pipeline-warn { background: #4a3a1a; color: #fbbf24; border: 1px solid #f59e0b; }
        
        /* Chat bubble colors */
        .blocked-msg { border-left: 4px solid #ef4444 !important; }
        .safe-msg { border-left: 4px solid #22c55e !important; }
        .reprompted-msg { border-left: 4px solid #f59e0b !important; }
        .contained-msg { border-left: 4px solid #f97316 !important; }
        
        /* Threat level indicator */
        .threat-indicator {
            padding: 8px 16px;
            border-radius: 8px;
            text-align: center;
            font-weight: 700;
            margin: 4px 0;
        }
        .threat-low { background: #1a472a; color: #4ade80; }
        .threat-guarded { background: #4a3a1a; color: #fbbf24; }
        .threat-elevated { background: #4a2a1a; color: #fb923c; }
        .threat-critical { background: #4a1a1a; color: #f87171; }
        
        /* Preset buttons */
        .preset-btn button {
            background: transparent !important;
            border: 1px solid #4a4a6a !important;
            color: #e0e0e0 !important;
            font-size: 0.8em !important;
            padding: 4px 8px !important;
            border-radius: 8px !important;
            width: 100% !important;
        }
        .preset-btn button:hover {
            border-color: #e94560 !important;
            background: #1a1a2e !important;
        }
        
        /* Metrics & Alerts */
        .stButton > button { border-radius: 8px; font-weight: 600; }
        [data-testid="stAlert"] { border-radius: 8px; }
    </style>
    """, unsafe_allow_html=True)
else:
    # LIGHT THEME (Apple HIG)
    st.markdown("""
    <style>
        /* ====== APPLE LIGHT THEME ====== */
        .theme-btn button {
            background: linear-gradient(135deg, #FFD93D 0%, #FF8C00 100%) !important;
            color: #1a1a2e !important;
            border: none !important;
            border-radius: 20px !important;
        }
        
        /* Pipeline visualization */
        .pipeline-step {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            margin: 2px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .pipeline-pass { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
        .pipeline-fail { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
        .pipeline-skip { background: #f3f4f6; color: #6b7280; border: 1px solid #d1d5db; }
        .pipeline-warn { background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
        
        /* Chat bubble colors */
        .blocked-msg { border-left: 4px solid #FF3B30 !important; }
        .safe-msg { border-left: 4px solid #34C759 !important; }
        .reprompted-msg { border-left: 4px solid #FF9500 !important; }
        .contained-msg { border-left: 4px solid #FF6B00 !important; }
        
        /* Threat level indicator */
        .threat-indicator {
            padding: 8px 16px;
            border-radius: 8px;
            text-align: center;
            font-weight: 700;
            margin: 4px 0;
        }
        .threat-low { background: #dcfce7; color: #166534; }
        .threat-guarded { background: #fef3c7; color: #92400e; }
        .threat-elevated { background: #ffedd5; color: #9a3412; }
        .threat-critical { background: #fee2e2; color: #991b1b; }
        
        /* Preset buttons */
        .preset-btn button {
            background: transparent !important;
            border: 1px solid #d1d5db !important;
            color: #374151 !important;
            font-size: 0.8em !important;
            padding: 4px 8px !important;
            border-radius: 8px !important;
            width: 100% !important;
        }
        .preset-btn button:hover {
            border-color: #007AFF !important;
            background: #eff6ff !important;
        }
        
        /* General */
        [data-testid="stAppViewContainer"] {
            background: linear-gradient(180deg, #F5F5F7 0%, #FFFFFF 100%);
        }
        section[data-testid="stSidebar"] {
            background: rgba(255, 255, 255, 0.85) !important;
            backdrop-filter: blur(20px);
        }
        .stButton > button {
            background: #007AFF !important;
            color: white !important;
            border: none !important;
            border-radius: 10px !important;
            font-weight: 600 !important;
        }
        [data-testid="stAlert"] { border-radius: 8px; }
    </style>
    """, unsafe_allow_html=True)

# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================
defaults = {
    "messages": [],
    "blocked_count": 0,
    "safe_count": 0,
    "reprompt_count": 0,
    "containment_count": 0,
    "shield_enabled": True,
    "test_mode": True,
    "last_security_log": None,
    "last_raw_error": None,
    "last_containment_log": None,
    "eval_fp": 0,
    "eval_fn": 0,
    "eval_latencies": [],
    "last_eval_result": None,
    "threat_score": 0.0,
    "last_pipeline": None,  # NEW: Pipeline status for visualization
    "comparison_mode": False,  # NEW: Side-by-side comparison
    "preset_attack": None,  # NEW: Preset attack to inject
    "session_total_queries": 0,  # FIX 7: Live session counters
    "session_blocked_count": 0,
    "session_reprompted_count": 0,
}

for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val


# =============================================================================
# HELPER: Pipeline visualization HTML
# =============================================================================
def render_pipeline(pipeline: dict) -> str:
    """Generate HTML for the defense pipeline visualization."""
    steps = [
        ("🧹 Sanitize", pipeline.get("sanitize", "skip")),
        ("🔍 Detect", pipeline.get("detect", "skip")),
        ("🔄 Reprompt", pipeline.get("reprompt", "skip")),
        ("🔒 Contain", pipeline.get("contain", "skip")),
    ]
    
    html = ""
    for label, status in steps:
        css_class = {
            "pass": "pipeline-pass",
            "fail": "pipeline-fail",
            "skip": "pipeline-skip",
            "warn": "pipeline-warn",
        }.get(status, "pipeline-skip")
        
        icon = {"pass": "✅", "fail": "❌", "skip": "⬜", "warn": "⚠️"}.get(status, "⬜")
        html += f'<span class="pipeline-step {css_class}">{icon} {label}</span> '
    
    return html


def get_threat_css_class() -> str:
    """Get CSS class for current threat level."""
    score = st.session_state.threat_score
    if score >= 0.8:
        return "threat-critical"
    elif score >= 0.5:
        return "threat-elevated"
    elif score >= 0.2:
        return "threat-guarded"
    return "threat-low"


# =============================================================================
# SIDEBAR
# =============================================================================
with st.sidebar:
    st.title("🛡️ Shield Metrics")
    st.divider()
    
    # Shield Toggle
    shield_on = st.toggle(
        "🛡️ Defense Shield",
        value=st.session_state.shield_enabled,
        help="ON = Full 4-layer defense. OFF = Bypass all defenses (demo mode)"
    )
    st.session_state.shield_enabled = shield_on
    
    # NEW: Comparison Mode Toggle
    compare_mode = st.toggle(
        "⚔️ Comparison Mode",
        value=st.session_state.comparison_mode,
        help="Show BOTH shielded and unshielded responses side-by-side"
    )
    st.session_state.comparison_mode = compare_mode
    
    st.divider()
    
    # Counters
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="🚫 Blocked", value=st.session_state.blocked_count)
    with col2:
        st.metric(label="✅ Safe", value=st.session_state.safe_count)
    
    col3, col4 = st.columns(2)
    with col3:
        st.metric(label="🔄 Reprompted", value=st.session_state.reprompt_count)
    with col4:
        st.metric(label="🔒 Contained", value=st.session_state.containment_count)
    
    st.divider()
    
    # NEW: Session Threat Level
    threat_level = defense.get_threat_level()
    threat_css = get_threat_css_class()
    st.markdown(f'<div class="threat-indicator {threat_css}">{threat_level}<br>Threat Score: {st.session_state.threat_score:.2f}</div>', unsafe_allow_html=True)
    
    # FIX 7: Live Session Stats
    st.markdown("---")
    st.markdown("### 📊 Session Stats")
    
    total = st.session_state.get("session_total_queries", 0)
    blocked = st.session_state.get("session_blocked_count", 0)
    reprompted = st.session_state.get("session_reprompted_count", 0)
    safe = total - blocked - reprompted
    
    if total > 0:
        stat_col1, stat_col2 = st.columns(2)
        stat_col1.metric("Total queries", total)
        stat_col2.metric("Blocked", blocked, delta=f"{blocked/total:.0%}" if total > 0 else "0%")
        stat_col1.metric("Safe", safe)
        stat_col2.metric("Reprompted", reprompted)
    else:
        st.caption("No queries yet this session.")
    
    st.divider()
    
    # NEW: Preset Attack Buttons
    st.subheader("🎯 Try an Attack")
    preset_attacks = get_preset_attacks()
    for i, attack in enumerate(preset_attacks):
        with st.container():
            st.markdown(f'<div class="preset-btn">', unsafe_allow_html=True)
            if st.button(attack["description"], key=f"preset_{i}", use_container_width=True):
                st.session_state.preset_attack = attack["prompt"]
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Pipeline Visualization
    with st.expander("🔗 Defense Pipeline", expanded=st.session_state.last_pipeline is not None):
        if st.session_state.last_pipeline:
            st.markdown(render_pipeline(st.session_state.last_pipeline), unsafe_allow_html=True)
            pipeline = st.session_state.last_pipeline
            if pipeline.get("details"):
                st.caption(pipeline["details"])
        else:
            st.info("Submit a prompt to see the pipeline in action.")
    
    # Security Log
    with st.expander("🔐 Security Log", expanded=False):
        if st.session_state.last_security_log:
            st.json(st.session_state.last_security_log)
        else:
            st.info("No security logs yet.")
    
    # Containment Log
    with st.expander("🔒 Containment Log", expanded=False):
        if st.session_state.last_containment_log:
            log = st.session_state.last_containment_log
            if log.get("is_leaked"):
                st.error(f"🔒 {log.get('leak_count', 0)} leak(s) detected and redacted")
                if log.get("canary_detected"):
                    st.error("🐦 CANARY TOKEN DETECTED — System prompt was leaked!")
                st.json(log.get("leaked_patterns", []))
            else:
                st.success("✅ No leaks in response")
        else:
            st.info("No containment checks performed yet.")
    
    # Error Log
    with st.expander("⚠️ System Errors", expanded=st.session_state.last_raw_error is not None):
        if st.session_state.last_raw_error:
            st.code(st.session_state.last_raw_error, language="text")
        else:
            st.success("No errors")
    
    st.divider()
    
    # Clear Button
    if st.button("🗑️ Clear Chat", use_container_width=True):
        for key in ["messages", "blocked_count", "safe_count", "reprompt_count",
                     "containment_count", "last_security_log", "last_raw_error",
                     "last_containment_log", "eval_fp", "eval_fn", "eval_latencies",
                     "last_eval_result", "threat_score", "last_pipeline",
                     "session_total_queries", "session_blocked_count", "session_reprompted_count"]:
            if key in defaults:
                st.session_state[key] = defaults[key]
        st.rerun()
    
    st.divider()
    
    # =========================================================================
    # EVALUATION METRICS DASHBOARD
    # =========================================================================
    st.subheader("📊 Evaluation Metrics")
    
    # Error Rates
    st.markdown("**Error Rates**")
    eval_col1, eval_col2 = st.columns(2)
    with eval_col1:
        st.metric(label="❌ False Positives", value=st.session_state.eval_fp, help="Safe prompts incorrectly blocked")
    with eval_col2:
        st.metric(label="⚠️ False Negatives", value=st.session_state.eval_fn, help="Malicious prompts incorrectly allowed")
    
    # Latency
    st.markdown("**Latency**")
    if st.session_state.eval_latencies:
        avg_latency = sum(st.session_state.eval_latencies) / len(st.session_state.eval_latencies)
        max_latency = max(st.session_state.eval_latencies)
        lat_col1, lat_col2 = st.columns(2)
        with lat_col1:
            st.metric(label="📊 Avg", value=f"{avg_latency:.0f}ms")
        with lat_col2:
            st.metric(label="🔺 Max", value=f"{max_latency:.0f}ms")
    else:
        st.caption("No latency data yet")
    
    st.caption(f"📋 Prompts analyzed: {len(st.session_state.eval_latencies)}")
    
    # Last Evaluation Result
    with st.expander("📋 Last Evaluation", expanded=False):
        if st.session_state.last_eval_result:
            result = st.session_state.last_eval_result
            method = result.get("method", "unknown")
            st.write(f"**Predicted:** {result.get('predicted', 'N/A')}")
            st.write(f"**Expected:** {result.get('expected', 'N/A')} ({method})")
            if result.get("similarity") and method == "fuzzy":
                st.write(f"**Similarity:** {result['similarity']:.0%}")
            if result.get("expected"):
                if result.get("correct"):
                    st.success("✅ Correct!")
                elif result.get("error_type") == "FP":
                    st.error("❌ False Positive (safe marked malicious)")
                else:
                    st.warning("⚠️ False Negative (attack allowed)")
        else:
            st.info("No evaluations yet")


# =============================================================================
# MAIN CONTENT
# =============================================================================
header_col1, header_col2 = st.columns([6, 1])
with header_col1:
    st.title("🛡️ Prompt Injection Defense System")
with header_col2:
    st.markdown('<div class="theme-btn">', unsafe_allow_html=True)
    if st.button("🌙" if st.session_state.dark_mode else "☀️", key="theme_toggle"):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

# Display chat history with color-coded messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        if message.get("blocked"):
            st.error(message["content"])
        elif message.get("reprompted"):
            st.warning(message["content"])
        elif message.get("contained"):
            st.info(message["content"])
        else:
            st.markdown(message["content"])

# Check for preset attack injection
prompt = st.session_state.preset_attack
if prompt:
    st.session_state.preset_attack = None  # Clear immediately

# Chat input (only if no preset to process)
if not prompt:
    prompt = st.chat_input("Enter your message...")

if prompt:
    # Display user message
    with st.chat_message("user"):
        st.markdown(prompt)
    
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    # Initialize pipeline tracking
    pipeline = {"sanitize": "skip", "detect": "skip", "reprompt": "skip", "contain": "skip", "details": ""}
    
    if st.session_state.shield_enabled or st.session_state.comparison_mode:
        # =====================================================================
        # SHIELDED PATH
        # =====================================================================
        
        # Step 1: Sanitize
        with st.spinner("🧹 Sanitizing input..."):
            start_time = time.time()
            sanitized = defense.sanitize_input(prompt)
            pipeline["sanitize"] = "pass"
            time.sleep(0.2)
        
        # FIX 4: Show truncation warning
        if st.session_state.get("input_truncated"):
            st.warning("⚠️ Input truncated to 2000 characters to prevent abuse.")
        
        # Step 1.5: Multi-turn analysis (NEW)
        multi_turn_result = defense.analyze_conversation_context(st.session_state.messages)
        
        # Step 2: Security guardrail
        with st.spinner("🔍 Analyzing for threats..."):
            if st.session_state.test_mode:
                security_result = defense.security_guardrail_groq(sanitized, st.session_state.messages)
            else:
                security_result = defense.security_guardrail(sanitized, st.session_state.messages)
            
            elapsed_ms = (time.time() - start_time) * 1000
            st.session_state.eval_latencies.append(elapsed_ms)
        
        # Store security log
        st.session_state.last_security_log = security_result
        
        is_malicious = security_result.get("is_malicious", False)
        
        # Check multi-turn result — if conversation-level attack detected, flag it
        if not is_malicious and multi_turn_result.get("is_suspicious"):
            is_malicious = True
            security_result["is_malicious"] = True
            security_result["reason"] = multi_turn_result.get("reason", "Multi-turn attack")
            security_result["confidence"] = multi_turn_result.get("confidence", 0.75)
            security_result["detection_method"] = "multi_turn"
        
        pipeline["detect"] = "fail" if is_malicious else "pass"
        
        # Update threat score (NEW)
        defense.update_threat_score(is_malicious)
        
        # FIX 7: Increment total queries counter
        st.session_state.session_total_queries += 1
        
        # Evaluation
        ground_truth = get_ground_truth(prompt)
        predicted_label = "MALICIOUS" if is_malicious else "SAFE"
        
        eval_result = {
            "predicted": predicted_label,
            "expected": ground_truth.get("label"),
            "method": ground_truth.get("method"),
            "similarity": ground_truth.get("similarity"),
            "correct": True,
            "error_type": None
        }
        
        if ground_truth.get("label"):
            if predicted_label == ground_truth["label"]:
                eval_result["correct"] = True
            else:
                eval_result["correct"] = False
                if ground_truth["label"] == "SAFE" and predicted_label == "MALICIOUS":
                    st.session_state.eval_fp += 1
                    eval_result["error_type"] = "FP"
                elif ground_truth["label"] == "MALICIOUS" and predicted_label == "SAFE":
                    st.session_state.eval_fn += 1
                    eval_result["error_type"] = "FN"
        
        st.session_state.last_eval_result = eval_result
        
        # =====================================================================
        # Step 3: Conditional response
        # =====================================================================
        if is_malicious:
            # Try reprompting
            with st.spinner("🔄 Attempting to extract legitimate query..."):
                reprompt_result = defense.reprompt_malicious(
                    sanitized, security_result, use_groq=st.session_state.test_mode
                )
            
            if reprompt_result.get("can_reprompt") and reprompt_result.get("reprompted_query"):
                # REPROMPTED
                pipeline["reprompt"] = "warn"
                reprompted_query = reprompt_result["reprompted_query"]
                
                with st.chat_message("assistant"):
                    st.warning(f"🔄 **REPROMPTED**: Malicious content removed.\n\n**Cleaned query:** \"{reprompted_query}\"\n\n**Removed:** {reprompt_result.get('explanation', 'N/A')}")
                    
                    with st.spinner("💬 Generating response for cleaned query..."):
                        try:
                            if st.session_state.test_mode:
                                response = target.get_target_response_groq(reprompted_query)
                            else:
                                response = target.get_target_response(reprompted_query)
                        except Exception as e:
                            response = f"⚠️ Error: {str(e)}"
                    
                    # Apply containment
                    containment_result = defense.contain_output(response)
                    st.session_state.last_containment_log = containment_result
                    pipeline["contain"] = "warn" if containment_result.get("is_leaked") else "pass"
                    
                    if containment_result.get("is_leaked"):
                        response = containment_result["filtered_response"]
                        st.session_state.containment_count += 1
                        st.warning(f"🔒 **CONTAINED**: {containment_result.get('leak_count', 0)} sensitive pattern(s) redacted")
                    
                    st.markdown(response)
                
                st.session_state.messages.append({
                    "role": "assistant", "content": response,
                    "blocked": False, "reprompted": True, "contained": containment_result.get("is_leaked", False)
                })
                st.session_state.safe_count += 1
                st.session_state.reprompt_count += 1
                st.session_state.session_reprompted_count += 1  # FIX 7
                pipeline["details"] = f"Reprompted: \"{reprompted_query}\""
                
            else:
                # BLOCKED
                pipeline["reprompt"] = "fail"
                pipeline["contain"] = "skip"
                
                reason = security_result.get("reason", "Suspicious activity detected")
                confidence = security_result.get("confidence", 0.0)
                method = security_result.get("detection_method", "unknown")
                
                block_message = f"🛡️ **BLOCKED** — {reason}\n\n**Confidence:** {confidence:.0%} | **Method:** {method}"
                
                with st.chat_message("assistant"):
                    st.error(block_message)
                
                st.session_state.messages.append({
                    "role": "assistant", "content": block_message, "blocked": True
                })
                st.session_state.blocked_count += 1
                st.session_state.session_blocked_count += 1  # FIX 7
                pipeline["details"] = f"Blocked: {reason}"
                
                # FIX 6: "Why was this blocked?" explainer
                with st.expander("🔍 Why was this blocked?", expanded=False):
                    method = security_result.get("detection_method", "unknown")
                    reason = security_result.get("reason", "No reason provided")
                    confidence = security_result.get("confidence", 0.0)
                    
                    st.markdown(f"**Detection method:** `{method}`")
                    st.markdown(f"**Reason:** {reason}")
                    st.markdown(f"**Confidence:** {confidence:.0%}")
                    st.progress(confidence)
                    
                    if method == "local_pattern" or method == "groq_local_pattern":
                        st.info("🔎 Caught by Layer 2 regex pattern matching (no API call needed)")
                    elif "groq" in method:
                        st.info("🤖 Caught by Layer 2 Groq LLM analysis (Llama 3.3-70B)")
                    elif "gemini" in method:
                        st.info("🤖 Caught by Layer 2 Gemini LLM analysis")
            
        else:
            # SAFE — Pass to target LLM
            pipeline["reprompt"] = "skip"
            with st.spinner("💬 Generating response..."):
                try:
                    if st.session_state.test_mode:
                        response = target.get_target_response_groq(sanitized)
                    else:
                        response = target.get_target_response(sanitized)
                except Exception as e:
                    response = f"⚠️ Error: {str(e)}"
            
            # Apply containment
            containment_result = defense.contain_output(response)
            st.session_state.last_containment_log = containment_result
            pipeline["contain"] = "warn" if containment_result.get("is_leaked") else "pass"
            
            if containment_result.get("is_leaked"):
                response = containment_result["filtered_response"]
                st.session_state.containment_count += 1
            
            with st.chat_message("assistant"):
                if containment_result.get("is_leaked"):
                    st.warning(f"🔒 **CONTAINED**: {containment_result.get('leak_count', 0)} sensitive pattern(s) redacted from response")
                st.markdown(response)
            
            st.session_state.messages.append({
                "role": "assistant", "content": response,
                "blocked": False, "contained": containment_result.get("is_leaked", False)
            })
            st.session_state.safe_count += 1
            pipeline["details"] = "Safe — passed all checks"
        
        st.session_state.last_pipeline = pipeline
        
        # =====================================================================
        # COMPARISON MODE: Also show unshielded response (NEW)
        # =====================================================================
        if st.session_state.comparison_mode:
            st.divider()
            st.markdown("### ⚔️ Comparison: Unshielded Response")
            st.caption("This shows what the LLM would respond WITHOUT any defense:")
            
            with st.spinner("💀 Getting unshielded response..."):
                try:
                    if st.session_state.test_mode:
                        unshielded = target.get_target_response_groq(prompt)
                    else:
                        unshielded = target.get_target_response(prompt)
                except Exception as e:
                    unshielded = f"⚠️ Error: {str(e)}"
            
            with st.chat_message("assistant"):
                st.error("⚠️ **UNSHIELDED** (No defense)")
                st.markdown(unshielded)
    
    elif not st.session_state.shield_enabled:
        # Shield OFF — bypass all defense
        sanitized = prompt
        security_result = {"is_malicious": False, "reason": "Shield disabled", "confidence": 0.0}
        st.session_state.last_security_log = {"status": "⚠️ SHIELD DISABLED", "message": "Defense bypassed for demo"}
        st.session_state.last_pipeline = {
            "sanitize": "skip", "detect": "skip", "reprompt": "skip", "contain": "skip",
            "details": "Shield disabled — all defenses bypassed"
        }
        
        with st.spinner("💬 Generating response (UNPROTECTED)..."):
            try:
                if st.session_state.test_mode:
                    response = target.get_target_response_groq(sanitized)
                else:
                    response = target.get_target_response(sanitized)
            except Exception as e:
                response = f"⚠️ Error: {str(e)}"
        
        with st.chat_message("assistant"):
            st.warning("⚠️ Shield is OFF — defense bypassed")
            st.markdown(response)
        
        st.session_state.messages.append({
            "role": "assistant", "content": response, "blocked": False
        })
        st.session_state.safe_count += 1
    
    st.rerun()

# Footer
st.divider()
col1, col2 = st.columns([3, 1])
with col1:
    st.caption("Built by Team SRON | Echelon Hackathon")
with col2:
    test_mode = st.toggle(
        "🧪 Test Mode",
        value=st.session_state.test_mode,
        help="ON = Groq API (free, fast). OFF = Gemini API (production)"
    )
    st.session_state.test_mode = test_mode
