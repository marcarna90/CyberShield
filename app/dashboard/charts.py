"""Plotly figure builders for the dashboard (pure functions, unit tested).

Visual system (dark SOC theme):
* severity uses the fixed status palette, always with text labels (never colour alone);
* magnitudes use a single blue hue; categorical series use a fixed, CVD-validated order;
* one y-axis per chart, thin marks, recessive grid, hover tooltips on every mark.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import plotly.graph_objects as go

SURFACE = "rgba(0,0,0,0)"
INK = "#f0efec"
INK_2 = "#c3c2b7"
MUTED = "#898781"
GRID = "#2c2c2a"
AXIS = "#383835"
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_COLORS = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#3987e5",
    "informational": "#898781",
}
SEVERITY_TEXT = {
    "critical": "#ffffff",
    "high": "#0b0b0b",
    "medium": "#0b0b0b",
    "low": "#ffffff",
    "informational": "#ffffff",
}
CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]
SEQUENTIAL = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
PRIMARY = "#3987e5"


def apply_theme(fig: go.Figure, height: int = 320, title: str | None = None) -> go.Figure:
    fig.update_layout(
        height=height,
        title={"text": title, "font": {"size": 14, "color": INK}, "x": 0, "xanchor": "left"} if title else None,
        paper_bgcolor=SURFACE,
        plot_bgcolor=SURFACE,
        font={"family": FONT, "color": INK_2, "size": 12},
        margin={"l": 8, "r": 8, "t": 40 if title else 12, "b": 8},
        legend={"orientation": "h", "y": -0.18, "x": 0, "font": {"color": INK_2}},
        hoverlabel={"bgcolor": "#262624", "bordercolor": AXIS, "font": {"color": INK, "family": FONT}},
        bargap=0.35,
    )
    fig.update_xaxes(showgrid=False, linecolor=AXIS, tickcolor=AXIS, tickfont={"color": MUTED}, zeroline=False)
    fig.update_yaxes(gridcolor=GRID, gridwidth=1, linecolor=AXIS, tickfont={"color": MUTED}, zeroline=False)
    return fig


def empty_figure(message: str, height: int = 260) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message, showarrow=False, font={"color": MUTED, "size": 13}, x=0.5, y=0.5, xref="paper", yref="paper"
    )
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return apply_theme(fig, height)


def _status_for_risk(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "serious"
    if score >= 25:
        return "warning"
    return "good"


def risk_gauge(score: float, title: str = "Risk score") -> go.Figure:
    """0-100 gauge; band colours follow the status palette, label shows the band name."""
    band = _status_for_risk(score)
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": " / 100", "font": {"color": INK, "size": 34}},
            title={
                "text": f"{title}<br><span style='font-size:12px;color:{INK_2}'>{band.upper()}</span>",
                "font": {"color": INK, "size": 14},
            },
            gauge={
                "axis": {"range": [0, 100], "tickcolor": MUTED, "tickfont": {"color": MUTED}},
                "bar": {"color": STATUS[band], "thickness": 0.28},
                "bgcolor": "#262624",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 25], "color": "rgba(12,163,12,0.18)"},
                    {"range": [25, 50], "color": "rgba(250,178,25,0.18)"},
                    {"range": [50, 75], "color": "rgba(236,131,90,0.18)"},
                    {"range": [75, 100], "color": "rgba(208,59,59,0.22)"},
                ],
            },
        )
    )
    return apply_theme(fig, 280)


def severity_donut(counts: Mapping[str, int], title: str = "Open findings by severity") -> go.Figure:
    labels = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    if not labels:
        return empty_figure("No open findings")
    values = [counts[s] for s in labels]
    fig = go.Figure(
        go.Pie(
            labels=[s.capitalize() for s in labels],
            values=values,
            hole=0.58,
            sort=False,
            direction="clockwise",
            marker={"colors": [SEVERITY_COLORS[s] for s in labels], "line": {"color": "#1a1a19", "width": 2}},
            textinfo="label+value",
            textfont={"color": [SEVERITY_TEXT[s] for s in labels]},
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        )
    )
    fig.add_annotation(text=f"<b>{sum(values)}</b><br>open", showarrow=False, font={"color": INK, "size": 16})
    fig.update_layout(showlegend=False)
    return apply_theme(fig, 300, title)


def severity_bars(counts: Mapping[str, int], title: str = "Severity distribution") -> go.Figure:
    fig = go.Figure(
        go.Bar(
            x=[s.capitalize() for s in SEVERITY_ORDER],
            y=[counts.get(s, 0) for s in SEVERITY_ORDER],
            marker={"color": [SEVERITY_COLORS[s] for s in SEVERITY_ORDER], "cornerradius": 4},
            text=[counts.get(s, 0) for s in SEVERITY_ORDER],
            textposition="outside",
            textfont={"color": INK_2},
            hovertemplate="%{x}: %{y}<extra></extra>",
        )
    )
    return apply_theme(fig, 300, title)


def findings_trend(trend: Sequence[Mapping[str, Any]], title: str = "Open findings trend (14 days)") -> go.Figure:
    if not trend:
        return empty_figure("No history yet")
    dates = [point["date"] for point in trend]
    fig = go.Figure()
    for severity in SEVERITY_ORDER[:4]:
        fig.add_bar(
            x=dates,
            y=[point.get(severity, 0) for point in trend],
            name=severity.capitalize(),
            marker={"color": SEVERITY_COLORS[severity], "line": {"color": "#1a1a19", "width": 1}},
            hovertemplate=f"{severity.capitalize()}: %{{y}}<extra>%{{x}}</extra>",
        )
    fig.update_layout(barmode="stack", hovermode="x unified")
    return apply_theme(fig, 320, title)


def compliance_bars(scores: Mapping[str, float], title: str = "Compliance score by framework") -> go.Figure:
    if not scores:
        return empty_figure("No compliance evaluation yet")
    names = list(scores)
    values = [scores[n] for n in names]
    fig = go.Figure(
        go.Bar(
            x=values,
            y=names,
            orientation="h",
            marker={"color": PRIMARY, "cornerradius": 4},
            text=[f"{v:.0f}%" for v in values],
            textposition="outside",
            textfont={"color": INK_2},
            hovertemplate="%{y}: %{x:.1f}%<extra></extra>",
        )
    )
    fig.update_xaxes(range=[0, 110], ticksuffix="%")
    fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
    return apply_theme(fig, 60 + 56 * len(names), title)


def compliance_trend(history: Iterable[Mapping[str, Any]], title: str = "Compliance score history") -> go.Figure:
    series: dict[str, tuple[list[str], list[float]]] = {}
    for row in history:
        xs, ys = series.setdefault(row["framework"], ([], []))
        xs.append(row["created_at"])
        ys.append(row["score"])
    if not series:
        return empty_figure("No compliance history yet")
    fig = go.Figure()
    for index, (framework, (xs, ys)) in enumerate(series.items()):
        color = CATEGORICAL[index % len(CATEGORICAL)]
        fig.add_scatter(
            x=xs,
            y=ys,
            name=framework,
            mode="lines+markers",
            line={"color": color, "width": 2, "shape": "hv"},
            marker={"size": 8, "line": {"color": "#1a1a19", "width": 2}},
            hovertemplate=f"{framework}: %{{y:.1f}}%<extra></extra>",
        )
    fig.update_yaxes(range=[0, 105], ticksuffix="%")
    fig.update_layout(hovermode="x unified")
    return apply_theme(fig, 320, title)


def horizontal_bars(
    labels: Sequence[str], values: Sequence[float], title: str, value_format: str = ",.0f", height: int | None = None
) -> go.Figure:
    if not labels:
        return empty_figure("No data")
    fig = go.Figure(
        go.Bar(
            x=list(values),
            y=list(labels),
            orientation="h",
            marker={"color": PRIMARY, "cornerradius": 4},
            text=[f"{v:{value_format}}" for v in values],
            textposition="outside",
            cliponaxis=False,
            textfont={"color": INK_2, "size": 11},
            hovertemplate=f"%{{y}}: %{{x:{value_format}}}<extra></extra>",
        )
    )
    fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
    return apply_theme(fig, height or 60 + 30 * len(labels), title)


def protocol_bars(protocols: Mapping[str, int], title: str = "Protocol mix (packets)") -> go.Figure:
    items = sorted(protocols.items(), key=lambda kv: -kv[1])[:10]
    return horizontal_bars([k for k, _ in items], [v for _, v in items], title)


def top_talkers(talkers: Sequence[Mapping[str, Any]], title: str = "Top talkers (bytes sent)") -> go.Figure:
    labels = [f"{t['ip']}{'' if t.get('internal') else '  (external)'}" for t in talkers]
    return horizontal_bars(labels, [t["bytes"] for t in talkers], title)


def traffic_trend(points: Sequence[Mapping[str, Any]], title: str = "Traffic volume") -> go.Figure:
    if not points:
        return empty_figure("No traffic captured yet")
    fig = go.Figure(
        go.Scatter(
            x=[p["ts"] for p in points],
            y=[p["bytes"] / 1024 for p in points],
            mode="lines",
            line={"color": PRIMARY, "width": 2},
            fill="tozeroy",
            fillcolor="rgba(57,135,229,0.12)",
            hovertemplate="%{y:,.0f} KB<extra>%{x}</extra>",
            name="KB",
        )
    )
    fig.update_yaxes(ticksuffix=" KB")
    fig.update_layout(hovermode="x")
    return apply_theme(fig, 300, title)


def asset_risk(assets: Sequence[Mapping[str, Any]], title: str = "Riskiest assets") -> go.Figure:
    ranked = sorted(assets, key=lambda a: -a.get("risk_score", 0))[:10]
    labels = [f"{a['ip']} {(a.get('hostname') or '').split('.')[0]}".strip() for a in ranked]
    fig = horizontal_bars(labels, [a.get("risk_score", 0) for a in ranked], title, ",.1f")
    fig.update_xaxes(range=[0, 100])
    return fig


def risk_matrix(matrix: Mapping[str, Any] | None, title: str = "Risk matrix (likelihood x impact)") -> go.Figure:
    """Counts per cell. Dark theme: zero recedes into the surface, magnitude lightens (single blue hue)."""
    if not matrix:
        return empty_figure("No risk data")
    z = [list(matrix["cells"][li]) for li in range(5)]
    zmax = max(max(row) for row in z) or 1
    ramp = ["#1f2733", *reversed(SEQUENTIAL[1:])]  # near-surface -> light
    fig = go.Figure(
        go.Heatmap(
            z=z,
            x=matrix["impact_labels"],
            y=matrix["likelihood_labels"],
            zmin=0,
            zmax=zmax,
            colorscale=[[i / (len(ramp) - 1), c] for i, c in enumerate(ramp)],
            showscale=False,
            xgap=2,
            ygap=2,
            hovertemplate="Likelihood %{y} / Impact %{x}: %{z} finding(s)<extra></extra>",
        )
    )
    for li, row in enumerate(z):
        for im, value in enumerate(row):
            if value:
                fig.add_annotation(
                    x=matrix["impact_labels"][im],
                    y=matrix["likelihood_labels"][li],
                    text=str(value),
                    showarrow=False,
                    font={"color": "#0b0b0b" if value / zmax > 0.45 else INK, "size": 13},
                )
    fig.update_xaxes(title={"text": "Impact", "font": {"color": MUTED}})
    fig.update_yaxes(title={"text": "Likelihood", "font": {"color": MUTED}}, gridcolor="rgba(0,0,0,0)")
    return apply_theme(fig, 340, title)
