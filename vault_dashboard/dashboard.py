import streamlit as st
import pandas as pd
import numpy as np
import time

# --- 1. PAGE SETUP ---
st.set_page_config(page_title="VAULT-AEGIS Security", page_icon="🛡️", layout="wide")
st.title("🛡️ VAULT-AEGIS : GenAI Security Gateway")
st.markdown("Live monitoring of Intent Analysis, Policy Guards, and Threat Interception.")

# --- 2. SIDEBAR NAVIGATION & CONTROLS ---
with st.sidebar:
    st.header("⚙️ Control Panel")
    refresh_rate = st.slider("Auto-refresh rate (seconds)", 1, 60, 5)
    st.markdown("---")
    st.subheader("System Status")
    st.success("🟢 FastAPI Gateway: ONLINE")
    st.success("🟢 Redis Rate Limiter: ONLINE")
    st.success("🟢 Tamper-Proof Ledger: SECURE")

# --- 3. MOCK DATA GENERATION (Replace with actual FastAPI/Redis calls) ---
# In a real app, you would use requests.get("http://localhost:8000/admin/audit-trail")
def get_live_metrics():
    return {
        "total_requests": np.random.randint(1000, 5000),
        "blocked_threats": np.random.randint(10, 150),
        "secrets_redacted": np.random.randint(5, 50),
        "avg_latency": round(np.random.uniform(40.0, 120.0), 2)
    }

metrics = get_live_metrics()

# --- 4. TOP KPI CARDS (The Gateway View) ---
st.subheader("Gateway Traffic & Access Control")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total API Requests", metrics["total_requests"], delta=np.random.randint(10, 50))
col2.metric("Threats Blocked (Aegis)", metrics["blocked_threats"], delta=-np.random.randint(1, 5), delta_color="inverse")
col3.metric("Secrets Redacted (Vault)", metrics["secrets_redacted"], delta=np.random.randint(1, 10))
col4.metric("Avg Gateway Latency", f"{metrics['avg_latency']} ms", delta=round(np.random.uniform(-5.0, 5.0), 2))

st.markdown("---")

# --- 5. INTENT & RISK MATRIX (GenAI Threat Intelligence) ---
st.subheader("🧠 GenAI Intent & Risk Matrix")
col_chart, col_alerts = st.columns([2, 1])

with col_chart:
    # Scatter plot simulating IntentAnalyzer output (Risk vs Confidence)
    chart_data = pd.DataFrame(
        np.random.randn(50, 2) * [20, 20] + [50, 50],
        columns=['Risk Score', 'Confidence Level']
    )
    chart_data['Intent Category'] = np.random.choice(['Chat', 'Tool Usage', 'Admin Override', 'Prompt Injection'], 50)
    
    # Native Streamlit scatter chart
    st.scatter_chart(
        chart_data,
        x='Risk Score',
        y='Confidence Level',
        color='Intent Category',
        height=350
    )

with col_alerts:
    st.error("🚨 **High Priority Alerts**")
    st.markdown("""
    * **11:24 AM:** `detect_direct_prompt_injection()` triggered. IP: 192.168.1.45
    * **11:21 AM:** `detect_system_override_attempt()` blocked. User: guest_token
    * **11:15 AM:** `check_rate_limit()` Burst detection triggered. IP: 10.0.0.5
    """)
    st.warning("⚠️ **Policy Warnings**")
    st.markdown("""
    * **11:10 AM:** Token limit exceeded for intent `allow_summarize`.
    """)

st.markdown("---")

# --- 6. AUDIT LEDGER (Audit & Vulnerability View) ---
st.subheader("⛓️ Tamper-Resistant Ledger (Live Feed)")

# Mocking the hashed audit trail from audit/ledger.py
ledger_data = pd.DataFrame({
    "Timestamp": pd.date_range(end=pd.Timestamp.now(), periods=5, freq='1min').strftime('%Y-%m-%d %H:%M:%S'),
    "Action": ["Auth Validated", "Intent Analyzed", "Policy Evaluated", "GenAI Forward", "Response Guard"],
    "Status": ["✅ PASS", "✅ PASS", "⚠️ RESTRICTED", "✅ PASS", "🛑 REDACTED"],
    "Hash Chain": [
        "e3b0c44298fc1c14", 
        "8d969eef6ecad3c2", 
        "9f86d081884c7d65", 
        "f4c9c4c4495535ea", 
        "a94a8fe5ccb19ba6"
    ]
})

st.dataframe(ledger_data, use_container_width=True, hide_index=True)

# --- 7. AUTO-REFRESH LOGIC ---
# This forces the app to rerun based on the slider in the sidebar
time.sleep(refresh_rate)
st.rerun()