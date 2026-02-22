"""
VAULT Aegis — Executive Security Dashboard
Premium Streamlit dashboard with dual-theme (Dark / Light) and Gold accent UI.
Multi-page: Dashboard | API Keys | Security Setup Guide
"""

import pathlib
import re
import streamlit as st
from utils.data import (
    generate_activity_events,
    get_kpi_data,
    get_recent_sidecars,
    get_quickstart_items,
    get_risk_breakdown,
    get_security_trend,
    get_pii_detection_stats,
    get_api_threat_stats,
)
from utils.charts import plot_activity_bar, plot_risk_donut, plot_security_sparkline

# ──────────────────────────────────────────────────────────────────────────────
# Page config
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VAULT Aegis — Executive Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────────────────────────────────────
# Session state
# ──────────────────────────────────────────────────────────────────────────────
if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "page" not in st.session_state:
    st.session_state.page = "dashboard"


def toggle_theme():
    st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"


def navigate_to(page: str):
    st.session_state.page = page


# ──────────────────────────────────────────────────────────────────────────────
# Theme tokens
# ──────────────────────────────────────────────────────────────────────────────
THEMES = {
    "dark": {
        "bg": "#0E1117",
        "card_bg": "#161B22",
        "card_bg_alt": "#1C2230",
        "text": "#FFFFFF",
        "text_secondary": "#8B949E",
        "accent": "#F4A261",
        "accent_glow": "rgba(244,162,97,0.25)",
        "border": "rgba(255,255,255,0.06)",
        "shadow": "0 8px 32px rgba(0,0,0,0.45)",
        "critical": "#E63946",
        "warning": "#F4A261",
        "safe": "#2A9D8F",
    },
    "light": {
        "bg": "#F5F5F0",
        "card_bg": "#FFFFFF",
        "card_bg_alt": "#F9F9F6",
        "text": "#1A1A1A",
        "text_secondary": "#6B7280",
        "accent": "#E9963A",
        "accent_glow": "rgba(233,150,58,0.18)",
        "border": "rgba(0,0,0,0.07)",
        "shadow": "0 8px 32px rgba(0,0,0,0.08)",
        "critical": "#DC2626",
        "warning": "#D97706",
        "safe": "#059669",
    },
}


def t() -> dict:
    return THEMES[st.session_state.theme]


# ──────────────────────────────────────────────────────────────────────────────
# CSS injection
# ──────────────────────────────────────────────────────────────────────────────
def inject_css():
    theme = t()
    css = f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

    /* ── Global reset ─────────────────────────────────────────────── */
    .stApp {{
        background-color: {theme['bg']};
        color: {theme['text']};
        font-family: 'Inter', sans-serif;
    }}
    .stApp > header {{ background: transparent !important; }}
    section[data-testid="stSidebar"] {{ display: none !important; }}

    /* Hide Streamlit chrome */
    #MainMenu, footer, .stDeployButton {{ display: none !important; }}

    /* ── Scrollbar ─────────────────────────────────────────────────── */
    ::-webkit-scrollbar {{ width: 6px; }}
    ::-webkit-scrollbar-track {{ background: transparent; }}
    ::-webkit-scrollbar-thumb {{ background: {theme['accent']}55; border-radius: 3px; }}

    /* ── Card system ───────────────────────────────────────────────── */
    .vault-card {{
        background: {theme['card_bg']};
        border-radius: 20px;
        padding: 24px;
        box-shadow: {theme['shadow']};
        border: 1px solid {theme['border']};
        transition: all 0.3s cubic-bezier(.25,.8,.25,1);
        margin-bottom: 16px;
    }}
    .vault-card:hover {{
        box-shadow: 0 12px 40px {theme['accent_glow']};
        border-color: {theme['accent']}33;
        transform: translateY(-2px);
    }}

    .vault-card-accent {{
        background: linear-gradient(135deg, {theme['accent']}18, {theme['card_bg']});
        border-left: 4px solid {theme['accent']};
    }}

    /* ── KPI numbers ──────────────────────────────────────────────── */
    .kpi-value {{
        font-size: 2.8rem;
        font-weight: 800;
        color: {theme['text']};
        line-height: 1.1;
        letter-spacing: -1px;
    }}
    .kpi-value-accent {{
        font-size: 2.8rem;
        font-weight: 800;
        color: {theme['accent']};
        line-height: 1.1;
        letter-spacing: -1px;
    }}
    .kpi-label {{
        font-size: 0.82rem;
        font-weight: 500;
        color: {theme['text_secondary']};
        text-transform: uppercase;
        letter-spacing: 1.2px;
        margin-bottom: 6px;
    }}
    .kpi-delta {{
        font-size: 0.85rem;
        font-weight: 600;
        color: {theme['safe']};
        margin-top: 4px;
    }}

    /* ── Section header ───────────────────────────────────────────── */
    .section-title {{
        font-size: 0.75rem;
        font-weight: 700;
        color: {theme['accent']};
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 18px;
        display: flex;
        align-items: center;
        gap: 8px;
    }}
    .section-title::before {{
        content: '';
        width: 4px;
        height: 16px;
        background: {theme['accent']};
        border-radius: 2px;
        display: inline-block;
    }}

    /* ── Top bar ───────────────────────────────────────────────────── */
    .top-bar-label {{
        font-size: 0.72rem;
        font-weight: 600;
        color: {theme['text_secondary']};
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-bottom: 4px;
    }}

    /* ── Checklist ─────────────────────────────────────────────────── */
    .checklist-item {{
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 9px 0;
        font-size: 0.88rem;
        color: {theme['text']};
        border-bottom: 1px solid {theme['border']};
    }}
    .checklist-item:last-child {{ border-bottom: none; }}
    .check-done {{ color: {theme['safe']}; font-size: 1rem; }}
    .check-pending {{ color: {theme['text_secondary']}; font-size: 1rem; }}

    /* ── Resource link ─────────────────────────────────────────────── */
    .resource-link {{
        display: block;
        padding: 10px 14px;
        border-radius: 10px;
        color: {theme['text']};
        font-size: 0.88rem;
        font-weight: 500;
        transition: background 0.2s;
        text-decoration: none;
        cursor: pointer;
    }}
    .resource-link:hover {{
        background: {theme['accent']}15;
        color: {theme['accent']};
    }}

    /* ── Progress bar ─────────────────────────────────────────────── */
    .progress-wrap {{
        background: {theme['border']};
        border-radius: 10px;
        height: 8px;
        overflow: hidden;
        margin-top: 10px;
    }}
    .progress-fill {{
        height: 100%;
        border-radius: 10px;
        background: linear-gradient(90deg, {theme['accent']}, {theme['safe']});
        transition: width 0.6s ease;
    }}

    /* ── Sidecar list item ─────────────────────────────────────────── */
    .sidecar-item {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 0;
        border-bottom: 1px solid {theme['border']};
        font-size: 0.85rem;
    }}
    .sidecar-item:last-child {{ border-bottom: none; }}
    .sidecar-name {{
        font-weight: 600;
        color: {theme['text']};
        font-family: 'Courier New', monospace;
        font-size: 0.82rem;
    }}
    .sidecar-badge {{
        font-size: 0.72rem;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
    }}
    .sidecar-healthy {{
        background: {theme['safe']}22;
        color: {theme['safe']};
    }}
    .sidecar-warning {{
        background: {theme['warning']}22;
        color: {theme['warning']};
    }}

    /* ── Security stat row ─────────────────────────────────────────── */
    .sec-stat {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 14px 0;
        border-bottom: 1px solid {theme['border']};
    }}
    .sec-stat:last-child {{ border-bottom: none; }}
    .sec-stat-label {{ font-size: 0.85rem; color: {theme['text_secondary']}; }}
    .sec-stat-value {{ font-size: 1.35rem; font-weight: 700; color: {theme['text']}; }}

    /* ── Brand header ─────────────────────────────────────────────── */
    .brand {{
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 28px;
    }}
    .brand-logo {{
        width: 44px; height: 44px;
        background: linear-gradient(135deg, {theme['accent']}, #E76F51);
        border-radius: 12px;
        display: flex; align-items: center; justify-content: center;
        font-size: 0.9rem;
        font-weight: 800;
        color: #fff;
        letter-spacing: 1px;
        box-shadow: 0 4px 15px {theme['accent_glow']};
    }}
    .brand-name {{
        font-size: 1.25rem;
        font-weight: 800;
        letter-spacing: 3px;
        color: {theme['text']};
    }}
    .brand-sub {{
        font-size: 0.68rem;
        color: {theme['text_secondary']};
        letter-spacing: 1px;
        text-transform: uppercase;
    }}

    /* ── Plotly charts override ────────────────────────────────────── */
    .stPlotlyChart {{ background: transparent !important; }}

    /* ── Streamlit container overrides for card styling ────────────── */
    [data-testid="stVerticalBlockBorderWrapper"] {{
        background: {theme['card_bg']};
        border-radius: 20px !important;
        border: 1px solid {theme['border']} !important;
        box-shadow: {theme['shadow']};
        transition: all 0.3s cubic-bezier(.25,.8,.25,1);
    }}
    [data-testid="stVerticalBlockBorderWrapper"]:hover {{
        box-shadow: 0 12px 40px {theme['accent_glow']};
        border-color: {theme['accent']}33 !important;
        transform: translateY(-2px);
    }}

    /* ── Streamlit overrides ──────────────────────────────────────── */
    .stSelectbox label {{ color: {theme['text_secondary']} !important; font-size: 0.8rem !important; }}
    div[data-baseweb="select"] {{
        background: {theme['card_bg_alt']} !important;
        border-radius: 10px !important;
        border: 1px solid {theme['border']} !important;
    }}
    div[data-baseweb="select"] * {{ color: {theme['text']} !important; }}

    /* ── Sub-page content ─────────────────────────────────────────── */
    .page-header {{
        font-size: 1.8rem;
        font-weight: 800;
        color: {theme['text']};
        margin-bottom: 8px;
        letter-spacing: -0.5px;
    }}
    .page-subheader {{
        font-size: 0.9rem;
        color: {theme['text_secondary']};
        margin-bottom: 32px;
    }}
    .guide-content {{
        background: {theme['card_bg']};
        border-radius: 20px;
        padding: 36px 40px;
        box-shadow: {theme['shadow']};
        border: 1px solid {theme['border']};
        color: {theme['text']};
        line-height: 1.75;
        font-size: 0.92rem;
    }}
    .guide-content h1 {{
        color: {theme['accent']};
        font-size: 1.6rem;
        font-weight: 800;
        margin-top: 36px;
        margin-bottom: 14px;
        padding-bottom: 8px;
        border-bottom: 2px solid {theme['accent']}33;
    }}
    .guide-content h2 {{
        color: {theme['accent']};
        font-size: 1.35rem;
        font-weight: 700;
        margin-top: 36px;
        margin-bottom: 14px;
        padding-bottom: 8px;
        border-bottom: 2px solid {theme['accent']}33;
    }}
    .guide-content h3 {{
        color: {theme['text']};
        font-size: 1.1rem;
        font-weight: 700;
        margin-top: 24px;
        margin-bottom: 10px;
    }}
    .guide-content code {{
        background: {theme['card_bg_alt']};
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.85rem;
        color: {theme['accent']};
    }}
    .guide-content pre {{
        background: {theme['card_bg_alt']};
        border: 1px solid {theme['border']};
        border-radius: 12px;
        padding: 16px 20px;
        overflow-x: auto;
        margin: 12px 0;
    }}
    .guide-content pre code {{
        background: transparent;
        padding: 0;
        color: {theme['text']};
    }}
    .guide-content ul, .guide-content ol {{
        padding-left: 24px;
    }}
    .guide-content li {{
        margin-bottom: 6px;
    }}
    .guide-content strong {{
        color: {theme['text']};
    }}
    .guide-content a {{
        color: {theme['accent']};
        text-decoration: none;
    }}
    .guide-content a:hover {{
        text-decoration: underline;
    }}
    .guide-content hr {{
        border: none;
        border-top: 1px solid {theme['border']};
        margin: 28px 0;
    }}

    /* ── API key table ─────────────────────────────────────────────── */
    .api-key-row {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 20px;
        background: {theme['card_bg']};
        border-radius: 14px;
        border: 1px solid {theme['border']};
        margin-bottom: 10px;
        transition: all 0.2s;
    }}
    .api-key-row:hover {{
        border-color: {theme['accent']}44;
        box-shadow: 0 4px 20px {theme['accent_glow']};
    }}
    .api-key-name {{
        font-weight: 700;
        color: {theme['text']};
        font-size: 0.95rem;
    }}
    .api-key-value {{
        font-family: 'Courier New', monospace;
        font-size: 0.82rem;
        color: {theme['text_secondary']};
        background: {theme['card_bg_alt']};
        padding: 6px 14px;
        border-radius: 8px;
        letter-spacing: 0.5px;
    }}
    .api-key-status {{
        font-size: 0.75rem;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 20px;
    }}
    .api-key-active {{
        background: {theme['safe']}22;
        color: {theme['safe']};
    }}
    .api-key-expired {{
        background: {theme['critical']}22;
        color: {theme['critical']};
    }}
    .api-key-section-title {{
        font-size: 0.72rem;
        font-weight: 700;
        color: {theme['text_secondary']};
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-bottom: 14px;
        margin-top: 28px;
    }}

    /* ── Back button ───────────────────────────────────────────────── */
    .back-btn {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        color: {theme['accent']};
        font-size: 0.85rem;
        font-weight: 600;
        cursor: pointer;
        margin-bottom: 24px;
        transition: opacity 0.2s;
    }}
    .back-btn:hover {{ opacity: 0.8; }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Component: Brand header
# ──────────────────────────────────────────────────────────────────────────────
def render_brand():
    st.markdown("""
    <div class="brand">
        <div class="brand-logo">VA</div>
        <div>
            <div class="brand-name">VAULT AEGIS</div>
            <div class="brand-sub">Executive Security Dashboard</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Component: Activity bar (top)
# ──────────────────────────────────────────────────────────────────────────────
def render_activity_chart():
    theme = t()
    df = generate_activity_events()
    with st.container(border=True):
        st.markdown('<div class="top-bar-label">Events — Last Hour</div>', unsafe_allow_html=True)
        fig = plot_activity_bar(df, accent=theme["accent"], text_color=theme["text_secondary"])
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


# ──────────────────────────────────────────────────────────────────────────────
# Component: Left sidebar
# ──────────────────────────────────────────────────────────────────────────────
def render_sidebar():
    theme = t()

    # Brand
    render_brand()

    # Quickstart — all in a single HTML block
    items = get_quickstart_items()
    done_count = sum(1 for i in items if i["done"])
    pct = int(done_count / len(items) * 100)

    checklist_html = ""
    for item in items:
        icon = "&#10003;" if item["done"] else "&#9675;"
        cls = "check-done" if item["done"] else "check-pending"
        checklist_html += f'<div class="checklist-item"><span class="{cls}">{icon}</span>{item["label"]}</div>'

    st.markdown(
        f"""
        <div class="vault-card vault-card-accent">
            <div class="section-title">Quickstart Guide</div>
            {checklist_html}
            <div style="margin-top:14px;font-size:0.82rem;color:{theme['text_secondary']}">
                Setup <strong style="color:{theme['accent']}">{pct}%</strong> Complete
            </div>
            <div class="progress-wrap"><div class="progress-fill" style="width:{pct}%"></div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Resources — navigable links
    st.markdown(
        f"""
        <div class="vault-card">
            <div class="section-title">Resources</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.button("API Keys", key="nav_api_keys", on_click=navigate_to, args=("api_keys",), use_container_width=True)
    st.button("Security Setup Guide", key="nav_security_guide", on_click=navigate_to, args=("security_guide",), use_container_width=True)


# ──────────────────────────────────────────────────────────────────────────────
# Component: Main KPI grid
# ──────────────────────────────────────────────────────────────────────────────
def render_kpi_grid():
    theme = t()
    kpi = get_kpi_data()
    risk_df = get_risk_breakdown()

    # Row 1
    r1c1, r1c2 = st.columns(2, gap="medium")
    with r1c1:
        with st.container(border=True):
            st.markdown('<div class="kpi-label">Today Risk Rating</div>', unsafe_allow_html=True)
            fig = plot_risk_donut(risk_df, kpi["risk_score"], accent=theme["accent"], text_color=theme["text"])
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(
                    f'<div style="text-align:center"><div style="font-size:0.75rem;color:{theme["text_secondary"]}">UPTIME</div>'
                    f'<div style="font-size:1.3rem;font-weight:700;color:{theme["safe"]}">{kpi["risk_uptime"]}%</div></div>',
                    unsafe_allow_html=True,
                )
            with col_b:
                st.markdown(
                    f'<div style="text-align:center"><div style="font-size:0.75rem;color:{theme["text_secondary"]}">ANOMALIES</div>'
                    f'<div style="font-size:1.3rem;font-weight:700;color:{theme["critical"]}">{kpi["risk_anomalies"]}</div></div>',
                    unsafe_allow_html=True,
                )

    with r1c2:
        st.markdown(
            f"""
            <div class="vault-card">
                <div class="kpi-label">Active Users</div>
                <div class="kpi-value-accent">{kpi["active_users"]:,}</div>
                <div class="kpi-delta">MoM Over {kpi["active_users_mom"]}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Row 2
    r2c1, r2c2 = st.columns(2, gap="medium")
    with r2c1:
        st.markdown(
            f"""
            <div class="vault-card" style="background: linear-gradient(135deg, {theme['accent']}22, {theme['card_bg']});">
                <div class="kpi-label">Total Consumers</div>
                <div class="kpi-value-accent">{kpi['total_consumers']:,}</div>
                <div class="kpi-delta">MoM Over {kpi['total_consumers_mom']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with r2c2:
        st.markdown(
            f"""
            <div class="vault-card">
                <div class="kpi-label">Total Users</div>
                <div class="kpi-value">{kpi['total_users']:,}</div>
                <div class="kpi-delta">MoM Over {kpi['total_users_mom']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Component: Right security panel
# ──────────────────────────────────────────────────────────────────────────────
def render_security_panel():
    theme = t()
    kpi = get_kpi_data()
    trend_df = get_security_trend()

    # Security Status card — uses st.container for Streamlit widgets
    with st.container(border=True):
        st.markdown('<div class="section-title">Security Status</div>', unsafe_allow_html=True)
        st.selectbox("Period", ["Last 7 Days", "Last 30 Days", "Last 90 Days"], label_visibility="collapsed", key="sec_period")
        fig = plot_security_sparkline(trend_df, accent=theme["accent"], text_color=theme["text_secondary"])
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        stats_html = ""
        for label, value in [
            ("Total Queries", f'{kpi["total_queries"]:,}'),
            ("Policies Triggered", str(kpi["policies_triggered"])),
            ("Policy Suspension Requests", str(kpi["policy_suspensions"])),
        ]:
            stats_html += f'<div class="sec-stat"><span class="sec-stat-label">{label}</span><span class="sec-stat-value">{value}</span></div>'
        st.markdown(stats_html, unsafe_allow_html=True)

    # Healthy Sidecars card — pure HTML
    sidecars = get_recent_sidecars()
    sidecar_html = ""
    for sc in sidecars:
        badge_class = "sidecar-healthy" if sc["status"] == "healthy" else "sidecar-warning"
        sidecar_html += (
            f'<div class="sidecar-item">'
            f'<span class="sidecar-name">{sc["name"]}</span>'
            f'<span class="sidecar-badge {badge_class}">{sc["latency"]}</span>'
            f'</div>'
        )

    st.markdown(
        f"""
        <div class="vault-card">
            <div class="section-title">Healthy Sidecars</div>
            <div class="kpi-value-accent">{kpi["healthy_sidecars_a"]:,}</div>
            <div style="font-size:1rem;color:{theme["text_secondary"]};margin-top:2px">/ {kpi["healthy_sidecars_b"]:,} monitored</div>
            <div style="margin-top:14px">
                {sidecar_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# PAGE: API Keys
# ──────────────────────────────────────────────────────────────────────────────
def render_api_keys_page():
    theme = t()

    st.button("< Back to Dashboard", key="back_from_api", on_click=navigate_to, args=("dashboard",))

    st.markdown('<div class="page-header">API Key Management</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subheader">View and manage your VAULT Aegis API keys for secure integration.</div>', unsafe_allow_html=True)

    # Active Keys
    st.markdown('<div class="api-key-section-title">Active Keys</div>', unsafe_allow_html=True)

    active_keys = [
        {"name": "Production Gateway", "key": "va-prod-****-****-a8f3", "created": "2026-01-15", "status": "active"},
        {"name": "Staging Environment", "key": "va-stg-****-****-c2d7", "created": "2026-02-01", "status": "active"},
        {"name": "CI/CD Pipeline", "key": "va-ci-****-****-e9b1", "created": "2026-02-10", "status": "active"},
    ]

    for k in active_keys:
        st.markdown(
            f"""
            <div class="api-key-row">
                <div>
                    <div class="api-key-name">{k['name']}</div>
                    <div style="font-size:0.75rem;color:{theme['text_secondary']};margin-top:2px">Created: {k['created']}</div>
                </div>
                <div class="api-key-value">{k['key']}</div>
                <div class="api-key-status api-key-active">Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Expired Keys
    st.markdown('<div class="api-key-section-title">Expired Keys</div>', unsafe_allow_html=True)

    expired_keys = [
        {"name": "Legacy Integration", "key": "va-leg-****-****-f4a2", "created": "2025-08-20", "status": "expired"},
        {"name": "Test Sandbox", "key": "va-test-****-****-d1e5", "created": "2025-11-05", "status": "expired"},
    ]

    for k in expired_keys:
        st.markdown(
            f"""
            <div class="api-key-row">
                <div>
                    <div class="api-key-name">{k['name']}</div>
                    <div style="font-size:0.75rem;color:{theme['text_secondary']};margin-top:2px">Created: {k['created']}</div>
                </div>
                <div class="api-key-value">{k['key']}</div>
                <div class="api-key-status api-key-expired">Expired</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Usage guidelines
    st.markdown(
        f"""
        <div class="vault-card" style="margin-top:28px;">
            <div class="section-title">Usage Guidelines</div>
            <div style="color:{theme['text_secondary']};font-size:0.88rem;line-height:1.8">
                <div style="margin-bottom:8px"><strong style="color:{theme['text']}">Rate Limits:</strong> 1,000 requests/min (Production), 100 requests/min (Staging)</div>
                <div style="margin-bottom:8px"><strong style="color:{theme['text']}">Authentication:</strong> Include your key in the <code style="background:{theme['card_bg_alt']};padding:2px 8px;border-radius:4px;color:{theme['accent']}">Authorization</code> header as a Bearer token</div>
                <div style="margin-bottom:8px"><strong style="color:{theme['text']}">Rotation Policy:</strong> Keys are automatically rotated every 90 days. You will receive a notification 7 days before expiry.</div>
                <div><strong style="color:{theme['text']}">Scopes:</strong> Each key inherits the permissions of the creating user's role. Contact admin to modify scopes.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# PAGE: Security Setup Guide  (reads from INSTALLATION.md)
# ──────────────────────────────────────────────────────────────────────────────
_INSTALLATION_MD_PATH = pathlib.Path(__file__).resolve().parent.parent / "vault_dashboard_gp" / "INSTALLATION.md"


def _load_installation_guide() -> str:
    """Read the INSTALLATION.md file from disk."""
    try:
        return _INSTALLATION_MD_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "**Error:** INSTALLATION.md not found."


def _md_to_html(md_text: str) -> str:
    """Convert markdown text to HTML using the markdown library."""
    import markdown
    return markdown.markdown(
        md_text,
        extensions=["fenced_code", "tables", "toc", "nl2br", "sane_lists"],
    )


def render_security_guide_page():
    theme = t()

    st.button("< Back to Dashboard", key="back_from_guide", on_click=navigate_to, args=("dashboard",))

    st.markdown('<div class="page-header">Security Setup Guide</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subheader">Complete installation, configuration, deployment, and security guide for VAULT Aegis.</div>', unsafe_allow_html=True)

    guide_md = _load_installation_guide()
    st.markdown(
        f'<div class="guide-content">{_md_to_html(guide_md)}</div>',
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Component: PII Activity Monitor Panel
# ──────────────────────────────────────────────────────────────────────────────
def render_pii_monitor():
    """Render the PII Activity Monitor dashboard block."""
    theme = t()
    pii = get_pii_detection_stats()

    st.markdown(f"""
    <div class="vault-card" style="margin-top:18px">
        <div class="section-title" style="font-size:1.15rem;margin-bottom:16px">PII Activity Monitor</div>

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:18px">
            <div style="flex:1;min-width:120px;background:{theme['card_alt'] if theme.get('card_alt') else 'rgba(255,255,255,0.04)'};border-radius:10px;padding:14px;text-align:center">
                <div style="font-size:0.72rem;color:{theme['text_secondary']};text-transform:uppercase;letter-spacing:1px">Total Detections</div>
                <div style="font-size:1.6rem;font-weight:700;color:{theme['accent']}">{pii['total_detections']:,}</div>
            </div>
            <div style="flex:1;min-width:120px;background:{theme['card_alt'] if theme.get('card_alt') else 'rgba(255,255,255,0.04)'};border-radius:10px;padding:14px;text-align:center">
                <div style="font-size:0.72rem;color:{theme['text_secondary']};text-transform:uppercase;letter-spacing:1px">Blocked Requests</div>
                <div style="font-size:1.6rem;font-weight:700;color:{theme['critical']}">{pii['blocked_requests']}</div>
            </div>
            <div style="flex:1;min-width:120px;background:{theme['card_alt'] if theme.get('card_alt') else 'rgba(255,255,255,0.04)'};border-radius:10px;padding:14px;text-align:center">
                <div style="font-size:0.72rem;color:{theme['text_secondary']};text-transform:uppercase;letter-spacing:1px">Today</div>
                <div style="font-size:1.6rem;font-weight:700;color:{theme['safe']}">{pii['detections_today']}</div>
            </div>
        </div>

        <div style="display:flex;gap:24px;flex-wrap:wrap">
            <div style="flex:1.2;min-width:220px">
                <div style="font-size:0.82rem;font-weight:600;color:{theme['text']};margin-bottom:8px">Severity Breakdown</div>
                {''.join(f'''<div style="display:flex;align-items:center;margin-bottom:6px">
                    <div style="width:70px;font-size:0.75rem;color:{theme['text_secondary']}">{sev}</div>
                    <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:6px;height:18px;overflow:hidden">
                        <div style="height:100%;width:{int(cnt / max(pii['severity_breakdown'].values()) * 100)}%;background:{'#E63946' if sev == 'Critical' else '#F4A261' if sev == 'High' else '#E9C46A' if sev == 'Medium' else '#2A9D8F'};border-radius:6px;transition:width 0.5s"></div>
                    </div>
                    <div style="width:40px;text-align:right;font-size:0.78rem;font-weight:600;color:{theme['text']}">{cnt}</div>
                </div>''' for sev, cnt in pii['severity_breakdown'].items())}
            </div>

            <div style="flex:1;min-width:200px">
                <div style="font-size:0.82rem;font-weight:600;color:{theme['text']};margin-bottom:8px">Top PII Types</div>
                {''.join(f'''<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.05)">
                    <span style="font-size:0.78rem;color:{theme['text_secondary']}">{item['type']}</span>
                    <span style="font-size:0.78rem;font-weight:600;color:{theme['accent']}">{item['count']} ({item['pct']}%)</span>
                </div>''' for item in pii['top_pii_types'][:5])}
            </div>
        </div>

        <div style="margin-top:16px">
            <div style="font-size:0.82rem;font-weight:600;color:{theme['text']};margin-bottom:8px">Most Affected Endpoints</div>
            {''.join(f'''<div style="display:flex;justify-content:space-between;padding:5px 8px;margin-bottom:4px;background:rgba(255,255,255,0.03);border-radius:6px">
                <code style="font-size:0.76rem;color:{theme['text_secondary']}">{ep['endpoint']}</code>
                <span style="font-size:0.76rem;font-weight:600;color:{theme['critical'] if ep['detections'] > 100 else theme['accent']}">{ep['detections']}</span>
            </div>''' for ep in pii['most_affected_endpoints'])}
        </div>
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Component: API Threat Detection Panel
# ──────────────────────────────────────────────────────────────────────────────
def render_api_threat_panel():
    """Render the API Threat Detection dashboard block."""
    theme = t()
    api = get_api_threat_stats()

    def status_color(status):
        if status == "secure":
            return theme["safe"]
        elif status == "at_risk":
            return "#F4A261"
        else:
            return theme["critical"]

    def status_icon(status):
        if status == "secure":
            return "&#x2714;"
        elif status == "at_risk":
            return "&#x26A0;"
        else:
            return "&#x2718;"

    st.markdown(f"""
    <div class="vault-card" style="margin-top:18px">
        <div class="section-title" style="font-size:1.15rem;margin-bottom:16px">API Threat Detection</div>

        <div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px">
            <div style="flex:1;min-width:100px;background:rgba(42,157,143,0.12);border:1px solid rgba(42,157,143,0.3);border-radius:10px;padding:14px;text-align:center">
                <div style="font-size:0.72rem;color:{theme['text_secondary']};text-transform:uppercase;letter-spacing:1px">Secure</div>
                <div style="font-size:1.8rem;font-weight:700;color:{theme['safe']}">{api['secure_apis']}</div>
                <div style="font-size:0.7rem;color:{theme['text_secondary']}">of {api['total_apis']} APIs</div>
            </div>
            <div style="flex:1;min-width:100px;background:rgba(244,162,97,0.12);border:1px solid rgba(244,162,97,0.3);border-radius:10px;padding:14px;text-align:center">
                <div style="font-size:0.72rem;color:{theme['text_secondary']};text-transform:uppercase;letter-spacing:1px">At Risk</div>
                <div style="font-size:1.8rem;font-weight:700;color:#F4A261">{api['at_risk_apis']}</div>
                <div style="font-size:0.7rem;color:{theme['text_secondary']}">need attention</div>
            </div>
            <div style="flex:1;min-width:100px;background:rgba(230,57,70,0.12);border:1px solid rgba(230,57,70,0.3);border-radius:10px;padding:14px;text-align:center">
                <div style="font-size:0.72rem;color:{theme['text_secondary']};text-transform:uppercase;letter-spacing:1px">Critical</div>
                <div style="font-size:1.8rem;font-weight:700;color:{theme['critical']}">{api['critical_apis']}</div>
                <div style="font-size:0.7rem;color:{theme['text_secondary']}">immediate action</div>
            </div>
        </div>

        <div style="font-size:0.82rem;font-weight:600;color:{theme['text']};margin-bottom:8px">API Security Status</div>
        {''.join(f'''<div style="display:flex;align-items:center;padding:8px 10px;margin-bottom:4px;background:rgba(255,255,255,0.03);border-radius:8px;border-left:3px solid {status_color(ep['status'])}">
            <span style="font-size:0.85rem;margin-right:8px">{status_icon(ep['status'])}</span>
            <code style="flex:1;font-size:0.76rem;color:{theme['text']}">{ep['name']}</code>
            <span style="font-size:0.72rem;color:{theme['text_secondary']};margin-right:12px">{ep['last_scan']}</span>
            <span style="font-size:0.76rem;font-weight:700;color:{status_color(ep['status'])}">{ep['risk_score']}</span>
        </div>''' for ep in api['api_details'][:8])}

        <div style="margin-top:16px">
            <div style="font-size:0.82rem;font-weight:600;color:{theme['text']};margin-bottom:8px">Active Threats</div>
            {''.join(f'''<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 8px;margin-bottom:4px;background:rgba(255,255,255,0.03);border-radius:6px">
                <span style="font-size:0.76rem;color:{theme['text_secondary']}">{tt['threat']}</span>
                <div>
                    <span style="font-size:0.72rem;padding:2px 8px;border-radius:10px;background:{'rgba(230,57,70,0.15)' if tt['severity'] == 'Critical' else 'rgba(244,162,97,0.15)' if tt['severity'] == 'High' else 'rgba(233,196,106,0.15)'};color:{'#E63946' if tt['severity'] == 'Critical' else '#F4A261' if tt['severity'] == 'High' else '#E9C46A'}">{tt['severity']}</span>
                    <span style="font-size:0.76rem;font-weight:600;color:{theme['text']};margin-left:8px">{tt['count']}</span>
                </div>
            </div>''' for tt in api['threat_types'])}
        </div>
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Main layout
# ──────────────────────────────────────────────────────────────────────────────
def main():
    inject_css()

    # ── Theme toggle (top-right) ──────────────────────────────────────────
    toggle_col = st.columns([0.88, 0.12])
    with toggle_col[1]:
        label = "Light" if st.session_state.theme == "dark" else "Dark"
        st.button(
            label,
            on_click=toggle_theme,
            key="theme_toggle",
            use_container_width=True,
        )

    # ── Page routing ─────────────────────────────────────────────────────
    page = st.session_state.page

    if page == "api_keys":
        render_api_keys_page()
    elif page == "security_guide":
        render_security_guide_page()
    else:
        # ── Dashboard (default) ──────────────────────────────────────────
        render_activity_chart()

        left, center, right = st.columns([1, 2.2, 1.2], gap="large")

        with left:
            render_sidebar()

        with center:
            render_kpi_grid()

        with right:
            render_security_panel()

        # ── PII Activity Monitor & API Threat Detection ──────────────────
        pii_col, api_col = st.columns(2, gap="large")

        with pii_col:
            render_pii_monitor()

        with api_col:
            render_api_threat_panel()


if __name__ == "__main__":
    main()
