"""
VAULT Aegis — Plotly chart builders for the Executive Dashboard.
Each function returns a plotly.graph_objects.Figure ready for st.plotly_chart().
"""

import plotly.graph_objects as go
import pandas as pd


# ---------------------------------------------------------------------------
# Common layout helpers
# ---------------------------------------------------------------------------

def _transparent_layout(**overrides) -> dict:
    base = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=0, b=0),
        font=dict(family="Inter, sans-serif"),
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Activity histogram (top bar)
# ---------------------------------------------------------------------------

def plot_activity_bar(df: pd.DataFrame, accent: str = "#F4A261", text_color: str = "#FFFFFF") -> go.Figure:
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=df["time"],
        y=df["events"],
        marker_color=accent,
        marker_line_width=0,
        hovertemplate="%{x|%H:%M}<br>%{y} events<extra></extra>",
    ))
    fig.update_layout(
        **_transparent_layout(),
        height=90,
        xaxis=dict(
            showgrid=False,
            tickformat="%H:%M",
            tickfont=dict(size=9, color=text_color),
            nticks=8,
        ),
        yaxis=dict(showgrid=False, showticklabels=False),
        bargap=0.15,
    )
    return fig


# ---------------------------------------------------------------------------
# 2. Risk donut / circular progress
# ---------------------------------------------------------------------------

def plot_risk_donut(df: pd.DataFrame, score: int, accent: str = "#F4A261", text_color: str = "#FFFFFF") -> go.Figure:
    fig = go.Figure()
    fig.add_trace(go.Pie(
        labels=df["label"],
        values=df["value"],
        hole=0.72,
        marker=dict(colors=df["color"].tolist(), line=dict(width=0)),
        textinfo="none",
        hovertemplate="%{label}: %{value}<extra></extra>",
    ))
    fig.update_layout(
        **_transparent_layout(),
        height=220,
        showlegend=False,
        annotations=[dict(
            text=f"<b>{score:,}</b>",
            x=0.5, y=0.5,
            font=dict(size=32, color=accent, family="Inter, sans-serif"),
            showarrow=False,
        )],
    )
    return fig


# ---------------------------------------------------------------------------
# 3. Security trend sparkline
# ---------------------------------------------------------------------------

def plot_security_sparkline(df: pd.DataFrame, accent: str = "#F4A261", text_color: str = "#FFFFFF") -> go.Figure:
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["date"],
        y=df["queries"],
        mode="lines+markers",
        line=dict(color=accent, width=2, shape="spline"),
        marker=dict(size=5, color=accent),
        fill="tozeroy",
        fillcolor=f"rgba(244,162,97,0.15)",
        hovertemplate="%{x|%b %d}: %{y}<extra></extra>",
    ))
    fig.update_layout(
        **_transparent_layout(),
        height=120,
        xaxis=dict(showgrid=False, tickfont=dict(size=9, color=text_color), nticks=5),
        yaxis=dict(showgrid=False, showticklabels=False),
    )
    return fig
