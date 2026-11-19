"""Plotly chart builders. Every chart is computed from real stored data."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from config import SEVERITIES
from dashboard.theme import EVENT_TYPE_COLORS, SEVERITY_COLORS, SURFACE, style_figure


def _bucket(series: pd.Series) -> str:
    """Choose hourly buckets for spans up to a week, daily buckets beyond that."""
    span = series.max() - series.min()
    return "h" if span <= pd.Timedelta(days=7) else "D"


def _complete(counts: pd.DataFrame | pd.Series, freq: str):
    """Fill missing time buckets with zero so gaps show as gaps, not slopes."""
    full = pd.date_range(counts.index.min(), counts.index.max(), freq=freq)
    return counts.reindex(full, fill_value=0)


def alerts_over_time(alerts: pd.DataFrame) -> go.Figure:
    """Stacked bars of alerts per time bucket, split by severity."""
    fig = go.Figure()
    if alerts.empty:
        return style_figure(fig)
    freq = _bucket(alerts["timestamp"])
    df = alerts.assign(bucket=alerts["timestamp"].dt.floor(freq))
    counts = _complete(df.groupby(["bucket", "severity"]).size().unstack(fill_value=0), freq)
    # Low at the bottom so the most severe sit on top where the eye lands.
    for sev in reversed(SEVERITIES):
        if sev in counts:
            fig.add_bar(
                x=counts.index, y=counts[sev], name=sev,
                marker=dict(color=SEVERITY_COLORS[sev], line=dict(color=SURFACE, width=1)),
                hovertemplate=f"<b>{sev}</b><br>%{{x}}<br>%{{y}} alert(s)<extra></extra>",
            )
    fig.update_layout(barmode="stack", title="Alert trend by severity",
                      xaxis_title=None, yaxis_title="Alerts")
    return style_figure(fig)


def events_over_time(events: pd.DataFrame) -> go.Figure:
    """Line chart of events per bucket for each event type."""
    fig = go.Figure()
    if events.empty:
        return style_figure(fig)
    freq = _bucket(events["timestamp"])
    df = events.assign(bucket=events["timestamp"].dt.floor(freq))
    counts = _complete(df.groupby(["bucket", "event_type"]).size().unstack(fill_value=0).sort_index(), freq)
    for etype, color in EVENT_TYPE_COLORS.items():
        if etype in counts:
            fig.add_scatter(
                x=counts.index, y=counts[etype], name=etype,
                line=dict(color=color, width=2), mode="lines",
                hovertemplate=f"{etype}: %{{y}}<extra></extra>",
            )
    fig.update_layout(title="Log events over time", hovermode="x unified", yaxis_title="Events")
    return style_figure(fig)


def horizontal_count_bar(counts: pd.Series, title: str, color: str = "#3987e5",
                         x_title: str = "Count") -> go.Figure:
    """Single-series horizontal bar chart (largest at top)."""
    fig = go.Figure()
    if counts.empty:
        return style_figure(fig, legend=False)
    counts = counts.sort_values(ascending=True)
    fig.add_bar(
        x=counts.values, y=[str(i) for i in counts.index], orientation="h",
        marker=dict(color=color, line=dict(color=SURFACE, width=1)),
        text=counts.values, textposition="outside", textfont=dict(color="#94a3b8"),
        hovertemplate="%{y}: %{x}<extra></extra>",
    )
    fig.update_layout(title=title, xaxis_title=x_title)
    return style_figure(fig, height=max(240, 34 * len(counts) + 80), legend=False)


def failed_logins_over_time(events: pd.DataFrame) -> go.Figure:
    fails = events[events["event_type"] == "auth_failure"]
    fig = go.Figure()
    if fails.empty:
        return style_figure(fig, legend=False)
    freq = _bucket(fails["timestamp"])
    counts = _complete(fails.groupby(fails["timestamp"].dt.floor(freq)).size(), freq)
    fig.add_bar(x=counts.index, y=counts.values, marker=dict(color=EVENT_TYPE_COLORS["auth_failure"]),
                hovertemplate="%{x}<br>%{y} failed login(s)<extra></extra>")
    fig.update_layout(title="Failed logins over time", yaxis_title="Failures")
    return style_figure(fig, legend=False)


def risk_breakdown(factors: list[dict[str, object]]) -> go.Figure:
    """Show how each factor contributed to an alert's risk score."""
    fig = go.Figure()
    if not factors:
        return style_figure(fig, legend=False)
    labels = [str(f["reason"]) for f in factors][::-1]
    values = [int(f["points"]) for f in factors][::-1]
    fig.add_bar(x=values, y=labels, orientation="h", marker=dict(color="#3987e5"),
                text=[f"+{v}" for v in values], textposition="outside",
                textfont=dict(color="#94a3b8"), hovertemplate="%{y}: +%{x}<extra></extra>")
    fig.update_layout(title="Risk score contributions", xaxis_title="Points")
    return style_figure(fig, height=60 + 38 * len(factors), legend=False)
