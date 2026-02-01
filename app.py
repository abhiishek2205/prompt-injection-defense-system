"""
Prompt Injection Defense System - Main Application
A Streamlit-based UI for demonstrating LLM security guardrails.
"""

import streamlit as st
import defense
import time
from evaluation import get_ground_truth, TEST_CASES

# Try to import target module, create mock if not available
try:
    import target
    # Check if the required function exists
    if not hasattr(target, 'get_target_response'):
        raise ImportError("target.py missing get_target_response function")
except ImportError:
    # Mock target module when teammate's code isn't available yet
    class MockTarget:
        @staticmethod
        def get_target_response(user_input: str) -> str:
            """Mock response when target.py is not available."""
            return f"🤖 [Mock Bot Response] I received your message: '{user_input}'. (Note: target.py not yet available)"
    
    target = MockTarget()

# Page configuration
st.set_page_config(
    page_title="Prompt Injection Defense System",
    page_icon="🛡️",
    layout="wide"
)

# Initialize theme state BEFORE page config
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True  # Default to dark theme

# Custom CSS based on theme
if st.session_state.dark_mode:
    # DARK THEME (Default Streamlit-like)
    st.markdown("""
    <style>
        /* ====== DARK THEME ====== */
        
        /* Theme toggle button styling */
        .theme-btn button {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%) !important;
            border: 1px solid #333 !important;
            border-radius: 20px !important;
            padding: 8px 16px !important;
            font-size: 1.2rem !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
        }
        
        .theme-btn button:hover {
            transform: scale(1.05) !important;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4) !important;
        }
        
        /* Metric styling */
        [data-testid="stMetricValue"] {
            font-size: 1.8rem;
            font-weight: 700;
        }
        
        .blocked-metric [data-testid="stMetricValue"] {
            color: #FF4B4B !important;
        }
        
        .safe-metric [data-testid="stMetricValue"] {
            color: #00C853 !important;
        }
        
        /* Chat styling */
        .stChatMessage {
            border-radius: 8px;
        }
        
        /* Buttons */
        .stButton > button {
            border-radius: 8px;
            font-weight: 600;
        }
        
        /* Alerts */
        [data-testid="stAlert"] {
            border-radius: 8px;
        }
    </style>
    """, unsafe_allow_html=True)
else:
    # LIGHT THEME (Apple HIG)
    st.markdown("""
    <style>
        /* ====== APPLE LIGHT THEME ====== */
        
        /* Theme toggle button styling */
        .theme-btn button {
            background: linear-gradient(135deg, #FFD93D 0%, #FF8C00 100%) !important;
            border: none !important;
            border-radius: 20px !important;
            padding: 8px 16px !important;
            font-size: 1.2rem !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 2px 8px rgba(255,140,0,0.3) !important;
            color: #1D1D1F !important;
        }
        
        .theme-btn button:hover {
            transform: scale(1.05) rotate(15deg) !important;
            box-shadow: 0 4px 12px rgba(255,140,0,0.4) !important;
        }
        
        /* 1. FORCE LIGHT BACKGROUND EVERYWHERE */
        .stApp {
            background-color: #F5F5F7 !important;
        }
        
        [data-testid="stAppViewContainer"] {
            background-color: #F5F5F7 !important;
        }
        
        .main .block-container {
            background-color: #F5F5F7 !important;
        }
        
        [data-testid="stHeader"] {
            background-color: rgba(245, 245, 247, 0.8) !important;
            backdrop-filter: blur(10px);
        }
        
        [data-testid="stToolbar"] {
            background-color: transparent !important;
        }
        
        /* 2. SIDEBAR - Frosted Glass */
        section[data-testid="stSidebar"] {
            background: rgba(255, 255, 255, 0.85) !important;
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
        }
        
        section[data-testid="stSidebar"] > div {
            background: transparent !important;
        }
        
        /* 3. TEXT COLORS - Dark text on light background */
        .stApp, .stApp p, .stApp span, .stApp label, .stApp div {
            color: #1D1D1F;
        }
        
        h1, h2, h3 {
            font-weight: 700 !important;
            color: #1D1D1F !important;
        }
        
        /* 4. METRICS - iOS Widget Cards */
        [data-testid="stMetric"] {
            background: #FFFFFF !important;
            border-radius: 16px;
            padding: 16px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
        }
        
        [data-testid="stMetricValue"] {
            font-size: 1.8rem;
            font-weight: 700;
            color: #1D1D1F !important;
        }
        
        [data-testid="stMetricLabel"] {
            color: #6E6E73 !important;
            font-size: 0.8rem;
        }
        
        .blocked-metric [data-testid="stMetricValue"] {
            color: #FF3B30 !important;
        }
        
        .safe-metric [data-testid="stMetricValue"] {
            color: #34C759 !important;
        }
        
        /* 5. CHAT MESSAGES */
        [data-testid="stChatMessage"] {
            background: #FFFFFF !important;
            border-radius: 12px !important;
            padding: 12px !important;
            margin-bottom: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }
        
        .stChatMessage p {
            color: #1D1D1F !important;
        }
        
        /* 6. CHAT INPUT */
        [data-testid="stChatInput"] {
            background: #FFFFFF !important;
            border-radius: 24px !important;
            border: 1px solid #D1D1D6 !important;
        }
        
        [data-testid="stChatInput"] textarea {
            background: #FFFFFF !important;
            color: #1D1D1F !important;
        }
        
        .stChatInputContainer {
            background: #F5F5F7 !important;
        }
        
        [data-testid="stBottom"] {
            background: #F5F5F7 !important;
        }
        
        [data-testid="stBottomBlockContainer"] {
            background: #F5F5F7 !important;
        }
        
        .stChatInput {
            background: #FFFFFF !important;
        }
        
        .stChatInput > div {
            background: #FFFFFF !important;
        }
        
        /* 7. BUTTONS - Apple Blue */
        .stButton > button {
            background: #007AFF !important;
            color: white !important;
            border: none !important;
            border-radius: 10px !important;
            font-weight: 600 !important;
        }
        
        .stButton > button:hover {
            background: #0062CC !important;
        }
        
        /* 8. EXPANDERS */
        [data-testid="stExpander"] {
            background: #FFFFFF !important;
            border-radius: 12px !important;
            border: none !important;
        }
        
        details summary {
            color: #1D1D1F !important;
        }
        
        /* 9. ALERTS */
        [data-testid="stAlert"] {
            border-radius: 12px !important;
        }
        
        /* 10. DIVIDERS */
        hr {
            border: none;
            border-top: 1px solid rgba(0, 0, 0, 0.08);
        }
        
        .stCaption {
            color: #86868B;
        }
    </style>
    """, unsafe_allow_html=True)

# Initialize session state
if "messages" not in st.session_state:
    st.session_state.messages = []

if "blocked_count" not in st.session_state:
    st.session_state.blocked_count = 0

if "safe_count" not in st.session_state:
    st.session_state.safe_count = 0

if "last_security_log" not in st.session_state:
    st.session_state.last_security_log = None

if "shield_enabled" not in st.session_state:
    st.session_state.shield_enabled = True

if "last_error" not in st.session_state:
    st.session_state.last_error = None

if "last_raw_error" not in st.session_state:
    st.session_state.last_raw_error = None

if "test_mode" not in st.session_state:
    st.session_state.test_mode = True  # Default to test mode (no API calls)

if "reprompt_count" not in st.session_state:
    st.session_state.reprompt_count = 0

if "containment_count" not in st.session_state:
    st.session_state.containment_count = 0

if "last_containment_log" not in st.session_state:
    st.session_state.last_containment_log = None

# Evaluation metrics session state
if "eval_fp" not in st.session_state:
    st.session_state.eval_fp = 0  # False Positives

if "eval_fn" not in st.session_state:
    st.session_state.eval_fn = 0  # False Negatives

if "eval_latencies" not in st.session_state:
    st.session_state.eval_latencies = []  # Latency tracking

if "last_eval_result" not in st.session_state:
    st.session_state.last_eval_result = None  # Last evaluation result

# Sidebar - Shield Metrics
with st.sidebar:
    st.title("🛡️ Shield Metrics")
    st.divider()
    
    # Shield Toggle
    shield_on = st.toggle(
        "🛡️ Defense Shield",
        value=st.session_state.shield_enabled,
        help="Toggle OFF to demo vulnerable target without protection"
    )
    st.session_state.shield_enabled = shield_on
    
    if shield_on:
        st.success("🟢 SHIELD ACTIVE")
    else:
        st.error("🔴 SHIELD DOWN - VULNERABLE")
    
    st.divider()
    
    # Metrics display with custom styling
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="blocked-metric">', unsafe_allow_html=True)
        st.metric(
            label="🚫 Attacks Blocked",
            value=st.session_state.blocked_count,
            delta=None
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="safe-metric">', unsafe_allow_html=True)
        st.metric(
            label="✅ Safe Queries",
            value=st.session_state.safe_count,
            delta=None
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Additional metrics row for reprompt and containment
    col3, col4 = st.columns(2)
    with col3:
        st.metric(
            label="🔄 Reprompted",
            value=st.session_state.reprompt_count,
            delta=None,
            help="Queries that were cleaned and resubmitted"
        )
    with col4:
        st.metric(
            label="🔒 Contained",
            value=st.session_state.containment_count,
            delta=None,
            help="Responses with leaked data redacted"
        )
    
    st.divider()
    
    # Security Logs Expander
    with st.expander("🔍 Security Logs", expanded=False):
        if st.session_state.last_security_log:
            log = st.session_state.last_security_log
            
            # Status indicator
            if log.get("is_malicious"):
                st.error("⚠️ THREAT DETECTED")
            else:
                st.success("✅ INPUT SAFE")
            
            # Display JSON reasoning
            st.json(log)
        else:
            st.info("No security checks performed yet.")
    
    # Containment Logs Expander
    with st.expander("🔒 Containment Logs", expanded=False):
        if st.session_state.last_containment_log:
            clog = st.session_state.last_containment_log
            
            if clog.get("is_leaked"):
                st.error(f"🚨 LEAK DETECTED: {clog.get('leak_count', 0)} pattern(s) redacted")
                st.json(clog.get("leaked_patterns", []))
            else:
                st.success("✅ No leaks in response")
        else:
            st.info("No containment checks performed yet.")
    
    st.divider()
    
    # Error Log Expander - Shows RAW API errors
    with st.expander("⚠️ System Errors", expanded=st.session_state.last_raw_error is not None):
        if st.session_state.last_raw_error:
            st.code(st.session_state.last_raw_error, language="text")
            if st.button("🗑️ Clear Error", key="clear_error"):
                st.session_state.last_raw_error = None
                st.rerun()
        else:
            st.success("✅ No errors")
    
    st.divider()
    
    # Reset button
    if st.button("🔄 Reset Session", use_container_width=True):
        st.session_state.messages = []
        st.session_state.blocked_count = 0
        st.session_state.safe_count = 0
        st.session_state.reprompt_count = 0
        st.session_state.containment_count = 0
        st.session_state.last_security_log = None
        st.session_state.last_containment_log = None
        st.session_state.shield_enabled = True
        st.session_state.last_error = None
        st.session_state.last_raw_error = None
        st.session_state.eval_fp = 0
        st.session_state.eval_fn = 0
        st.session_state.eval_latencies = []
        st.session_state.last_eval_result = None
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
        st.metric(
            label="❌ False Positives",
            value=st.session_state.eval_fp,
            help="Safe prompts incorrectly blocked"
        )
    with eval_col2:
        st.metric(
            label="⚠️ False Negatives",
            value=st.session_state.eval_fn,
            help="Malicious prompts incorrectly allowed"
        )
    
    # Latency
    st.markdown("**Latency**")
    if st.session_state.eval_latencies:
        avg_latency = sum(st.session_state.eval_latencies) / len(st.session_state.eval_latencies)
        max_latency = max(st.session_state.eval_latencies)
        lat_col1, lat_col2 = st.columns(2)
        with lat_col1:
            st.metric(label="⏱️ Avg", value=f"{avg_latency:.0f}ms")
        with lat_col2:
            st.metric(label="🔺 Max", value=f"{max_latency:.0f}ms")
    else:
        st.caption("No latency data yet")
    
    st.caption(f"📋 Prompts analyzed: {len(st.session_state.eval_latencies)}")
    
    # Last Evaluation Result
    with st.expander("📋 Last Evaluation", expanded=False):
        if st.session_state.last_eval_result:
            result = st.session_state.last_eval_result
            st.markdown(f"**Prompt**: \"{result['prompt'][:50]}...\"" if len(result['prompt']) > 50 else f"**Prompt**: \"{result['prompt']}\"")
            st.markdown(f"**Expected**: {result['expected']}")
            st.markdown(f"**Predicted**: {result['predicted']}")
            
            if result['expected'] is None:
                st.info("ℹ️ Prompt not in test database")
            elif result['correct']:
                st.success("✅ Correct!")
            else:
                if result['error_type'] == 'FP':
                    st.error("❌ False Positive (safe marked malicious)")
                else:
                    st.warning("⚠️ False Negative (attack allowed)")
        else:
            st.info("No evaluations yet")

# Main content area - Header with theme toggle
header_col1, header_col2 = st.columns([6, 1])
with header_col1:
    st.title("🛡️ Prompt Injection Defense System")
with header_col2:
    # Compact animated theme toggle
    theme_icon = "🌙" if st.session_state.dark_mode else "☀️"
    st.markdown('<div class="theme-btn">', unsafe_allow_html=True)
    if st.button(theme_icon, key="theme_toggle"):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

st.caption("An AI-powered security layer that detects and blocks malicious prompts before they reach the target LLM.")

st.divider()

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        if message.get("blocked"):
            st.error(message["content"])
        else:
            st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Enter your message..."):
    # Display user message
    with st.chat_message("user"):
        st.markdown(prompt)
    
    # Add user message to history
    st.session_state.messages.append({
        "role": "user",
        "content": prompt
    })
    
    # Check if shield is enabled
    if st.session_state.shield_enabled:
        # Step 1: Sanitize input
        with st.spinner("🔍 Sanitizing input..."):
            sanitized = defense.sanitize_input(prompt)
            time.sleep(0.3)  # Brief visual feedback
        
        # Step 2: Security guardrail check
        with st.spinner("🛡️ Running security analysis..."):
            # Start latency timer
            start_time = time.perf_counter()
            
            # Check if test mode is enabled
            if st.session_state.test_mode:
                # Test mode - use Groq API (free, fast)
                security_result = defense.security_guardrail_groq(sanitized, st.session_state.messages)
            else:
                # Production mode - use Gemini API
                security_result = defense.security_guardrail(
                    sanitized_input=sanitized,
                    chat_history=st.session_state.messages
                )
            
            # End latency timer
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000
            st.session_state.eval_latencies.append(latency_ms)
            
            # Store the security log
            st.session_state.last_security_log = security_result
        
        is_malicious = security_result.get("is_malicious", False)
        
        # =========================================================================
        # EVALUATION METRICS: Compare prediction with ground truth
        # =========================================================================
        ground_truth = get_ground_truth(prompt)
        predicted_label = "MALICIOUS" if is_malicious else "SAFE"
        
        eval_result = {
            "prompt": prompt,
            "expected": ground_truth["label"],
            "predicted": predicted_label,
            "method": ground_truth["method"],
            "category": ground_truth["category"],
            "correct": None,
            "error_type": None
        }
        
        if ground_truth["label"] is not None:
            # Prompt is in test database - can evaluate
            eval_result["correct"] = (predicted_label == ground_truth["label"])
            
            if not eval_result["correct"]:
                if ground_truth["label"] == "SAFE" and predicted_label == "MALICIOUS":
                    st.session_state.eval_fp += 1
                    eval_result["error_type"] = "FP"
                elif ground_truth["label"] == "MALICIOUS" and predicted_label == "SAFE":
                    st.session_state.eval_fn += 1
                    eval_result["error_type"] = "FN"
        
        st.session_state.last_eval_result = eval_result
    else:
        # Shield OFF - bypass all defense
        sanitized = prompt
        security_result = {"is_malicious": False, "reason": "Shield disabled", "confidence": 0.0}
        st.session_state.last_security_log = {"status": "⚠️ SHIELD DISABLED", "message": "Defense bypassed for demo"}
        is_malicious = False
    
    # Step 3: Conditional response based on security check
    if is_malicious:
        # MALICIOUS DETECTED - Try reprompting first
        with st.spinner("🔄 Attempting to extract legitimate query..."):
            reprompt_result = defense.reprompt_malicious(
                sanitized, 
                security_result, 
                use_groq=st.session_state.test_mode
            )
        
        if reprompt_result.get("can_reprompt") and reprompt_result.get("reprompted_query"):
            # REPROMPTED - We salvaged a legitimate query
            reprompted_query = reprompt_result["reprompted_query"]
            
            # Show what happened
            with st.chat_message("assistant"):
                st.warning(f"🔄 **REPROMPTED**: Malicious content removed.\n\n"
                          f"**Original threat**: {security_result.get('reason', 'Unknown')}\n\n"
                          f"**Cleaned query**: \"{reprompted_query}\"")
            
            # Log the reprompt action
            st.session_state.messages.append({
                "role": "assistant",
                "content": f"🔄 REPROMPTED: {reprompt_result.get('explanation', '')}",
                "reprompted": True
            })
            
            st.session_state.reprompt_count += 1
            
            # Now send the cleaned query to target
            with st.spinner("💬 Generating response for cleaned query..."):
                try:
                    if st.session_state.test_mode:
                        response = target.get_target_response_groq(reprompted_query)
                    else:
                        response = target.get_target_response(reprompted_query)
                except Exception as e:
                    response = f"⚠️ Error: {str(e)}"
            
            # Apply containment to the response
            containment_result = defense.contain_output(response)
            st.session_state.last_containment_log = containment_result
            
            if containment_result.get("is_leaked"):
                response = containment_result["filtered_response"]
                st.session_state.containment_count += 1
            
            with st.chat_message("assistant"):
                if containment_result.get("is_leaked"):
                    st.warning(f"🔒 **CONTAINED**: {containment_result.get('leak_count', 0)} sensitive pattern(s) redacted")
                st.markdown(response)
            
            st.session_state.messages.append({
                "role": "assistant",
                "content": response,
                "blocked": False,
                "contained": containment_result.get("is_leaked", False)
            })
            
            st.session_state.safe_count += 1
            
        else:
            # BLOCKED - No legitimate query could be salvaged
            reason = security_result.get("reason", "Suspicious activity detected")
            confidence = security_result.get("confidence", 0.0)
            reprompt_explanation = reprompt_result.get("explanation", "No legitimate query found")
            
            block_message = f"🛡️ **BLOCKED**: {reason} (Confidence: {confidence:.0%})\n\n" \
                           f"🔄 **Reprompt failed**: {reprompt_explanation}"
            
            with st.chat_message("assistant"):
                st.error(block_message)
            
            st.session_state.messages.append({
                "role": "assistant",
                "content": block_message,
                "blocked": True
            })
            
            st.session_state.blocked_count += 1
        
    else:
        # SAFE - Pass to target LLM
        with st.spinner("💬 Generating response..."):
            try:
                if st.session_state.test_mode:
                    response = target.get_target_response_groq(sanitized)
                else:
                    response = target.get_target_response(sanitized)
                if response.startswith("Error:"):
                    st.session_state.last_raw_error = f"🎯 Target Bot: {response}"
            except Exception as e:
                error_msg = str(e)
                response = f"⚠️ Error from target bot: {error_msg}"
                st.session_state.last_raw_error = f"🎯 Target Bot Error: {error_msg}"
        
        # Apply containment to the response (even for "safe" inputs)
        containment_result = defense.contain_output(response)
        st.session_state.last_containment_log = containment_result
        
        if containment_result.get("is_leaked"):
            response = containment_result["filtered_response"]
            st.session_state.containment_count += 1
        
        with st.chat_message("assistant"):
            if containment_result.get("is_leaked"):
                st.warning(f"🔒 **CONTAINED**: {containment_result.get('leak_count', 0)} sensitive pattern(s) redacted from response")
            st.markdown(response)
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": response,
            "blocked": False,
            "contained": containment_result.get("is_leaked", False)
        })
        
        st.session_state.safe_count += 1
    
    # Rerun to update sidebar metrics
    st.rerun()

# Footer
st.divider()
col1, col2 = st.columns([3, 1])
with col1:
    st.caption("Built with ❤️ for Hackathon | Powered by Google Gemini & Streamlit")
with col2:
    test_mode = st.toggle("🧪 Test Mode", value=st.session_state.test_mode, help="ON = Local detection only (no API). OFF = Gemini API (for jury demo)")
    st.session_state.test_mode = test_mode
