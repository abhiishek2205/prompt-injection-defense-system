"""
Prompt Injection Defense System - Main Application
A Streamlit-based UI for demonstrating LLM security guardrails.
"""

import streamlit as st
import defense
import time

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

# Custom CSS for colored metrics
st.markdown("""
<style>
    [data-testid="stMetricValue"] {
        font-size: 2rem;
    }
    .blocked-metric [data-testid="stMetricValue"] {
        color: #ff4b4b;
    }
    .safe-metric [data-testid="stMetricValue"] {
        color: #00c853;
    }
    .stChatMessage {
        padding: 1rem;
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
        st.session_state.last_security_log = None
        st.session_state.shield_enabled = True
        st.session_state.last_error = None
        st.session_state.last_raw_error = None
        st.rerun()

# Main content area
st.title("🛡️ Prompt Injection Defense System")
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
            security_result = defense.security_guardrail(
                sanitized_input=sanitized,
                chat_history=st.session_state.messages
            )
            # Store the security log
            st.session_state.last_security_log = security_result
            
            # Check for defense errors (from fallback)
            if security_result.get("detection_method") == "local_pattern":
                st.session_state.last_error = "🛡️ Defense: API unavailable, using local pattern detection"
        
        is_malicious = security_result.get("is_malicious", False)
    else:
        # Shield OFF - bypass all defense
        sanitized = prompt
        security_result = {"is_malicious": False, "reason": "Shield disabled", "confidence": 0.0}
        st.session_state.last_security_log = {"status": "⚠️ SHIELD DISABLED", "message": "Defense bypassed for demo"}
        is_malicious = False
    
    # Step 3: Conditional response based on security check
    if is_malicious:
        # BLOCKED - Malicious input detected
        reason = security_result.get("reason", "Suspicious activity detected")
        confidence = security_result.get("confidence", 0.0)
        
        block_message = f"🛡️ **BLOCKED**: {reason} (Confidence: {confidence:.0%})"
        
        with st.chat_message("assistant"):
            st.error(block_message)
        
        # Add blocked message to history
        st.session_state.messages.append({
            "role": "assistant",
            "content": block_message,
            "blocked": True
        })
        
        # Increment blocked count
        st.session_state.blocked_count += 1
        
    else:
        # SAFE - Pass to target LLM
        with st.spinner("💬 Generating response..."):
            try:
                response = target.get_target_response(sanitized)
                # Check if response indicates an error
                if response.startswith("Error:"):
                    st.session_state.last_error = f"🎯 Target Bot: {response}"
            except Exception as e:
                error_msg = str(e)
                response = f"⚠️ Error from target bot: {error_msg}"
                st.session_state.last_error = f"🎯 Target Bot Error: {error_msg}"
        
        with st.chat_message("assistant"):
            st.markdown(response)
        
        # Add response to history
        st.session_state.messages.append({
            "role": "assistant",
            "content": response,
            "blocked": False
        })
        
        # Increment safe count
        st.session_state.safe_count += 1
    
    # Rerun to update sidebar metrics
    st.rerun()

# Footer
st.divider()
st.caption("Built with ❤️ for Hackathon | Powered by Google Gemini & Streamlit")
