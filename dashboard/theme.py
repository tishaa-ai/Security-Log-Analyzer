"""Dark SOC theme: CSS, colour tokens and the shared Plotly styling."""

from __future__ import annotations

import plotly.graph_objects as go

# Severity is a *status* (state) encoding: fixed colours, always shown with a
# text label so meaning never relies on colour alone.
SEVERITY_COLORS: dict[str, str] = {
    "Critical": "#d03b3b",
    "High": "#ec835a",
    "Medium": "#fab219",
    "Low": "#3987e5",
}
STATUS_COLORS: dict[str, str] = {
    "New": "#3987e5",
    "Investigating": "#fab219",
    "Resolved": "#0ca30c",
    "False Positive": "#8b8b85",
}
# Categorical identity colours (fixed order, dark-mode steps).
EVENT_TYPE_COLORS: dict[str, str] = {
    "auth_failure": "#d95926",
    "auth_success": "#199e70",
    "http_request": "#3987e5",
    "system": "#9085e9",
}

SURFACE = "#111a2e"
TEXT_PRIMARY = "#e2e8f0"
TEXT_SECONDARY = "#94a3b8"
GRID = "rgba(148,163,184,0.12)"

CSS = """
<style>
:root {
  --surface: #111a2e; --surface-2: #16213a; --border: #22304d;
  --text: #e2e8f0; --muted: #94a3b8;
}
.stApp { background: #0b1220; }
section[data-testid="stSidebar"] { background: #0e1729; border-right: 1px solid var(--border); }
.block-container { padding-top: 2.2rem; max-width: 1400px; }
h1, h2, h3 { letter-spacing: -0.01em; }
div[data-testid="stMetric"] {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px;
}
div[data-testid="stMetric"] label { color: var(--muted) !important; }
.sev-badge {
  display: inline-block; padding: 2px 10px; border-radius: 999px;
  font-size: 0.78rem; font-weight: 700; color: #0b1220;
}
.sev-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 14px; border-left-width: 5px;
}
.sev-card .label { color: var(--muted); font-size: 0.82rem; }
.sev-card .value { color: var(--text); font-size: 1.8rem; font-weight: 700; line-height: 1.2; }
.indicator-note {
  background: rgba(250,178,25,0.08); border: 1px solid rgba(250,178,25,0.35);
  border-radius: 8px; padding: 8px 12px; color: #f5d68a; font-size: 0.85rem;
}
.page-sub { color: var(--muted); margin-top: -0.6rem; margin-bottom: 1rem; }
</style>
"""


def style_figure(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    """Apply the shared dark styling: recessive grid, transparent surfaces."""
    fig.update_layout(
        template="plotly_dark",
        height=height,
        margin=dict(l=10, r=10, t=40, b=10 if not legend else 80),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT_PRIMARY, size=12),
        title_font=dict(size=14, color=TEXT_PRIMARY),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="left", x=0,
                    font=dict(color=TEXT_SECONDARY)),
        hoverlabel=dict(bgcolor="#16213a", bordercolor="#22304d", font=dict(color=TEXT_PRIMARY)),
        bargap=0.25,
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=TEXT_SECONDARY))
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=TEXT_SECONDARY))
    return fig
