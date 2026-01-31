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

if "test_mode" not in st.session_state:
    st.session_state.test_mode = True  # Default to test mode (no API calls)

if "reprompt_count" not in st.session_state:
    st.session_state.reprompt_count = 0

if "containment_count" not in st.session_state:
    st.session_state.containment_count = 0

if "last_containment_log" not in st.session_state:
    st.session_state.last_containment_log = None

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
            
            # Store the security log
            st.session_state.last_security_log = security_result
        
        is_malicious = security_result.get("is_malicious", False)
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
