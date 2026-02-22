"""
VAULT Aegis Dashboard - Screenshot Demo Generator
Generates preview screenshots of the dashboard
"""

import streamlit as st
from app import inject_custom_css, generate_dummy_data, render_metric_card, render_progress_bar
import plotly.graph_objects as go

# Page config
st.set_page_config(page_title="VAULT Demo", layout="wide")

# Inject CSS
inject_custom_css()

# Generate data
data = generate_dummy_data()

# Demo Header
st.markdown("""
<div style="text-align: center; padding: 40px 0;">
    <div class="vault-logo" style="font-size: 48px;">🛡️ VAULT AEGIS</div>
    <h1 style="color: #ffffff; margin: 20px 0;">Security Dashboard Demo</h1>
    <p style="color: #787878; font-size: 18px;">Production-Ready Streamlit Application</p>
</div>
""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Feature Showcase
st.markdown('<div class="section-header">✨ Key Features</div>', unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    <div class="glass-card">
        <div class="icon icon-purple" style="font-size: 32px;">🎨</div>
        <h3 style="color: #ffffff; font-size: 18px;">Glassmorphic UI</h3>
        <p style="color: #787878; font-size: 14px;">Modern dark theme with blur effects and gradients</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="glass-card">
        <div class="icon icon-purple" style="font-size: 32px;">📊</div>
        <h3 style="color: #ffffff; font-size: 18px;">Interactive Charts</h3>
        <p style="color: #787878; font-size: 14px;">Plotly-powered visualizations with hover effects</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="glass-card">
        <div class="icon icon-green" style="font-size: 32px;">⚡</div>
        <h3 style="color: #ffffff; font-size: 18px;">Real-time Monitoring</h3>
        <p style="color: #787878; font-size: 14px;">Live threat detection and AI model tracking</p>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown("""
    <div class="glass-card">
        <div class="icon icon-green" style="font-size: 32px;">🔧</div>
        <h3 style="color: #ffffff; font-size: 18px;">Fully Customizable</h3>
        <p style="color: #787878; font-size: 14px;">Modular code structure for easy modifications</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Sample Metrics
st.markdown('<div class="section-header">📈 Sample Metrics Display</div>', unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(render_metric_card("Total Assets", 32268, 10, "icon-purple"), unsafe_allow_html=True)

with col2:
    st.markdown(render_metric_card("Active Threats", 1254, -5, "icon-red"), unsafe_allow_html=True)

with col3:
    st.markdown(render_metric_card("AI Models", 2, None, "icon-purple"), unsafe_allow_html=True)

with col4:
    st.markdown(render_metric_card("API Requests", 892340, 8, "icon-purple"), unsafe_allow_html=True)

with col5:
    st.markdown(render_metric_card("Resolved", 1245, 15, "icon-green"), unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Sample Chart
st.markdown('<div class="section-header">📊 Sample Visualization</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    
    fig = go.Figure(data=[go.Pie(
        labels=['Secure', 'Under Review', 'Compromised'],
        values=[76, 18, 6],
        hole=0.6,
        marker=dict(
            colors=['#23C193', '#9D88FF', '#FE3B3B'],
            line=dict(color='#1a1a2e', width=2)
        )
    )])
    
    fig.update_layout(
        title="System Health Overview",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        showlegend=True,
        legend=dict(font=dict(color='#ffffff')),
        height=300
    )
    
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<h3 style="color: #ffffff; font-size: 18px; margin-bottom: 20px;">Threat Categories</h3>', unsafe_allow_html=True)
    
    categories = ['Malware', 'Prompt Injection', 'Data Exfiltration', 'Model Manipulation', 'API Abuse']
    percentages = [29, 23, 18, 15, 12]
    
    for cat, pct in zip(categories, percentages):
        st.markdown(render_progress_bar(cat, pct, '#9D88FF'), unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Tech Stack
st.markdown('<div class="section-header">🛠️ Technology Stack</div>', unsafe_allow_html=True)

st.markdown("""
<div class="glass-card">
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 30px; padding: 20px;">
        <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 10px;">🐍</div>
            <div style="color: #ffffff; font-weight: 600;">Python 3.8+</div>
            <div style="color: #787878; font-size: 12px;">Core Language</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 10px;">📊</div>
            <div style="color: #ffffff; font-weight: 600;">Streamlit</div>
            <div style="color: #787878; font-size: 12px;">Web Framework</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 10px;">📈</div>
            <div style="color: #ffffff; font-weight: 600;">Plotly</div>
            <div style="color: #787878; font-size: 12px;">Visualizations</div>
        </div>
        <div style="text-align: center;">
            <div style="font-size: 48px; margin-bottom: 10px;">🎨</div>
            <div style="color: #ffffff; font-weight: 600;">Custom CSS</div>
            <div style="color: #787878; font-size: 12px;">Styling</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Getting Started
st.markdown('<div class="section-header">🚀 Getting Started</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    <div class="glass-card">
        <h3 style="color: #ffffff; margin-bottom: 20px;">Installation Steps</h3>
        <div style="background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; font-family: monospace;">
            <div style="color: #23C193; margin-bottom: 10px;">$ cd vault_dashboard</div>
            <div style="color: #9D88FF; margin-bottom: 10px;">$ pip install -r requirements.txt</div>
            <div style="color: #4852F5;">$ streamlit run app.py</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="glass-card">
        <h3 style="color: #ffffff; margin-bottom: 20px;">Features Overview</h3>
        <ul style="color: #787878; line-height: 2;">
            <li>✅ Dark futuristic UI design</li>
            <li>✅ Real-time threat monitoring</li>
            <li>✅ AI model performance tracking</li>
            <li>✅ API gateway analytics</li>
            <li>✅ Interactive data tables</li>
            <li>✅ Fully responsive layout</li>
            <li>✅ Production-ready code</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Footer
st.markdown("""
<div style="text-align: center; padding: 40px 0; border-top: 1px solid rgba(157, 136, 255, 0.2); margin-top: 40px;">
    <div class="vault-logo" style="font-size: 32px; margin-bottom: 20px;">🛡️ VAULT AEGIS</div>
    <p style="color: #787878;">Production-Ready Security Dashboard • Built with Streamlit</p>
    <p style="color: #787878; font-size: 12px; margin-top: 10px;">Run the main app.py file to see the complete dashboard</p>
</div>
""", unsafe_allow_html=True)
