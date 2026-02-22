"""
VAULT Aegis — Dummy data generation for the Executive Dashboard.
All functions return pandas DataFrames or plain dicts suitable for UI binding.
"""

import random
import datetime
import pandas as pd
import numpy as np


# ---------------------------------------------------------------------------
# Activity Events (last hour) – used by the top horizontal bar
# ---------------------------------------------------------------------------

def generate_activity_events(minutes: int = 60, base: int = 40, spike: int = 120) -> pd.DataFrame:
    """Return a DataFrame with one row per minute for the last *minutes* minutes."""
    now = datetime.datetime.now().replace(second=0, microsecond=0)
    times = [now - datetime.timedelta(minutes=minutes - i) for i in range(minutes)]
    counts = []
    for i in range(minutes):
        if random.random() < 0.12:
            counts.append(random.randint(spike, spike + 80))
        else:
            counts.append(random.randint(base, base + 50))
    return pd.DataFrame({"time": times, "events": counts})


# ---------------------------------------------------------------------------
# KPI summary numbers
# ---------------------------------------------------------------------------

def get_kpi_data() -> dict:
    """Return a dict with all headline KPI values."""
    return {
        "risk_score": 3020,
        "risk_uptime": 99.7,
        "risk_anomalies": 14,
        "active_users": 248,
        "active_users_mom": "+318",
        "total_consumers": 6992,
        "total_consumers_mom": "+5,209",
        "total_users": 570,
        "total_users_mom": "+672",
        "total_queries": 3949,
        "policies_triggered": 53,
        "policy_suspensions": 25,
        "healthy_sidecars_a": 8550,
        "healthy_sidecars_b": 1046,
    }


# ---------------------------------------------------------------------------
# Recent sidecars list
# ---------------------------------------------------------------------------

def get_recent_sidecars() -> list[dict]:
    return [
        {"name": "DROPBOX-POSTGRES-SQL", "status": "healthy", "latency": "12 ms"},
        {"name": "DJANGO-RDS", "status": "healthy", "latency": "8 ms"},
        {"name": "DROPBOX-STAGING", "status": "healthy", "latency": "15 ms"},
        {"name": "AWS-LAMBDA-PROXY", "status": "healthy", "latency": "6 ms"},
        {"name": "REDIS-CACHE-PROD", "status": "warning", "latency": "42 ms"},
    ]


# ---------------------------------------------------------------------------
# Quickstart checklist
# ---------------------------------------------------------------------------

def get_quickstart_items() -> list[dict]:
    return [
        {"label": "Activate Account", "done": True},
        {"label": "Company Information", "done": True},
        {"label": "API Integration", "done": True},
        {"label": "Map Security Logs", "done": True},
        {"label": "Setup Teams", "done": True},
        {"label": "Distribute User Access", "done": False},
    ]


# ---------------------------------------------------------------------------
# Risk donut data
# ---------------------------------------------------------------------------

def get_risk_breakdown() -> pd.DataFrame:
    labels = ["Threats Blocked", "Anomalies", "Clean Traffic"]
    values = [420, 14, 2586]
    colors = ["#E63946", "#F4A261", "#2A9D8F"]
    return pd.DataFrame({"label": labels, "value": values, "color": colors})


# ---------------------------------------------------------------------------
# Security trend (sparkline)
# ---------------------------------------------------------------------------

def get_security_trend(days: int = 7) -> pd.DataFrame:
    dates = pd.date_range(end=datetime.date.today(), periods=days)
    queries = np.random.randint(300, 700, size=days)
    return pd.DataFrame({"date": dates, "queries": queries})


# ---------------------------------------------------------------------------
# PII Detection Statistics – used by the PII Activity Monitor panel
# ---------------------------------------------------------------------------

def get_pii_detection_stats() -> dict:
    """Return mock PII detection statistics for the dashboard."""
    return {
        "total_detections": 1247,
        "blocked_requests": 89,
        "detections_today": 34,
        "top_pii_types": [
            {"type": "Email Address", "count": 412, "pct": 33.0},
            {"type": "Credit Card", "count": 287, "pct": 23.0},
            {"type": "Phone Number", "count": 198, "pct": 15.9},
            {"type": "SSN", "count": 134, "pct": 10.7},
            {"type": "API Key", "count": 98, "pct": 7.9},
            {"type": "JWT Token", "count": 67, "pct": 5.4},
            {"type": "IP Address", "count": 51, "pct": 4.1},
        ],
        "severity_breakdown": {
            "Critical": 312,
            "High": 498,
            "Medium": 287,
            "Low": 150,
        },
        "trend_7d": [
            {"day": "Mon", "count": 45},
            {"day": "Tue", "count": 38},
            {"day": "Wed", "count": 52},
            {"day": "Thu", "count": 41},
            {"day": "Fri", "count": 67},
            {"day": "Sat", "count": 28},
            {"day": "Sun", "count": 34},
        ],
        "most_affected_endpoints": [
            {"endpoint": "/api/v1/users", "detections": 156},
            {"endpoint": "/api/v1/payments", "detections": 134},
            {"endpoint": "/api/v1/auth/login", "detections": 98},
            {"endpoint": "/llm-endpoint", "detections": 87},
            {"endpoint": "/api/v1/documents", "detections": 54},
        ],
    }


# ---------------------------------------------------------------------------
# API Threat Detection – secure vs at-risk APIs
# ---------------------------------------------------------------------------

def get_api_threat_stats() -> dict:
    """Return mock API threat detection statistics for the dashboard."""
    return {
        "total_apis": 24,
        "secure_apis": 18,
        "at_risk_apis": 4,
        "critical_apis": 2,
        "api_details": [
            {"name": "/api/v1/users", "status": "secure", "risk_score": 12, "last_scan": "2 min ago"},
            {"name": "/api/v1/auth/login", "status": "secure", "risk_score": 8, "last_scan": "5 min ago"},
            {"name": "/api/v1/payments", "status": "at_risk", "risk_score": 68, "last_scan": "1 min ago"},
            {"name": "/api/v1/admin", "status": "critical", "risk_score": 92, "last_scan": "3 min ago"},
            {"name": "/api/v1/documents", "status": "at_risk", "risk_score": 55, "last_scan": "8 min ago"},
            {"name": "/llm-endpoint", "status": "secure", "risk_score": 15, "last_scan": "1 min ago"},
            {"name": "/api/v1/reports", "status": "secure", "risk_score": 5, "last_scan": "12 min ago"},
            {"name": "/api/v1/config", "status": "critical", "risk_score": 88, "last_scan": "2 min ago"},
            {"name": "/api/v1/webhooks", "status": "at_risk", "risk_score": 62, "last_scan": "4 min ago"},
            {"name": "/api/v1/export", "status": "at_risk", "risk_score": 71, "last_scan": "6 min ago"},
        ],
        "threat_types": [
            {"threat": "SQL Injection Risk", "count": 12, "severity": "High"},
            {"threat": "Auth Bypass Attempt", "count": 8, "severity": "Critical"},
            {"threat": "Rate Limit Exceeded", "count": 34, "severity": "Medium"},
            {"threat": "Data Exposure Risk", "count": 6, "severity": "High"},
            {"threat": "SSRF Vulnerability", "count": 3, "severity": "Critical"},
        ],
    }
