from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any, Dict, List


GRADE_STYLES = {
    "A": {"label": "Strong", "color": "#15803d", "bg": "#dcfce7", "border": "#86efac"},
    "B": {"label": "Good", "color": "#3f6212", "bg": "#ecfccb", "border": "#bef264"},
    "C": {"label": "Moderate", "color": "#92400e", "bg": "#fef3c7", "border": "#fcd34d"},
    "D": {"label": "Needs Attention", "color": "#c2410c", "bg": "#ffedd5", "border": "#fdba74"},
    "F": {"label": "High Risk", "color": "#b91c1c", "bg": "#fee2e2", "border": "#fca5a5"},
}

RISK_LEVEL_STYLES = {
    "HIGH": {"color": "#b91c1c", "bg": "#fee2e2", "border": "#fca5a5"},
    "MEDIUM": {"color": "#c2410c", "bg": "#ffedd5", "border": "#fdba74"},
    "LOW": {"color": "#15803d", "bg": "#dcfce7", "border": "#86efac"},
}

SEVERITY_STYLES = {
    "high": {"label": "High", "color": "#b91c1c", "bg": "#fee2e2", "border": "#fca5a5"},
    "medium": {"label": "Medium", "color": "#c2410c", "bg": "#ffedd5", "border": "#fdba74"},
    "low": {"label": "Low", "color": "#15803d", "bg": "#dcfce7", "border": "#86efac"},
}

VALID_SEVERITIES = set(SEVERITY_STYLES)
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _validated_fixes(fixes: Any) -> List[Dict[str, Any]]:
    if fixes is None:
        return []
    if not isinstance(fixes, list):
        raise TypeError("Expected fixes to be a list of standard fix dictionaries.")

    normalized: List[Dict[str, Any]] = []
    for fix in fixes:
        if not isinstance(fix, dict):
            continue

        steps = fix.get("steps", [])
        if isinstance(steps, str):
            steps = [steps]
        elif not isinstance(steps, list):
            steps = []

        severity = str(fix.get("severity", "medium")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        normalized.append(
            {
                "id": str(fix.get("id", "UNKNOWN_CONTROL")),
                "title": str(fix.get("title", "Review configuration")),
                "why": str(fix.get("why", "")),
                "steps": [str(step) for step in steps if str(step).strip()],
                "severity": severity,
            }
        )

    return normalized


def _grade_style(grade: str) -> Dict[str, str]:
    return GRADE_STYLES.get(
        grade,
        {"label": "Unrated", "color": "#475569", "bg": "#f1f5f9", "border": "#cbd5e1"},
    )


def _risk_level(score: int) -> str:
    if score <= 49:
        return "HIGH"
    if score <= 74:
        return "MEDIUM"
    return "LOW"


def _display_risk_level(result: Dict[str, Any], score: int) -> str:
    risk_level = str(result.get("risk_level", "")).upper()
    if risk_level in RISK_LEVEL_STYLES:
        return risk_level
    return _risk_level(score)


def _failed_control_id(control: Any) -> str:
    if isinstance(control, dict):
        return str(control.get("id", ""))
    return str(control)


def _severity_badge(severity: str) -> str:
    severity = severity if severity in VALID_SEVERITIES else "medium"
    style = SEVERITY_STYLES[severity]
    return f"""
    <span class="severity-badge" style="color:{style['color']};background:{style['bg']};border-color:{style['border']};">
        {escape(style['label'])}
    </span>
    """


def _executive_summary(score: int, grade: str, risk_level: str, fixes: List[Dict[str, Any]]) -> str:
    if not fixes:
        return (
            "Based on the responses provided, this baseline did not identify material security gaps. "
            "The environment appears well aligned to expected SMB controls, with routine review and maintenance recommended."
        )

    if risk_level == "HIGH":
        posture = "The environment has several important gaps that could create avoidable business risk."
    elif risk_level == "MEDIUM":
        posture = "The environment has a workable foundation, but several improvements should be prioritized."
    else:
        posture = "The environment is in a generally strong position, with a small number of targeted improvements available."

    return (
        f"{posture} The final score is {score}/100 with grade {escape(grade)}. "
        "The recommendations below focus on practical actions that improve resilience, reduce exposure, "
        "and make day-to-day operations easier to protect."
    )


def _business_impact_text(risk_level: str, top_risks: List[Dict[str, Any]]) -> str:
    if not top_risks:
        return (
            "No immediate business-impact scenario was identified from this baseline. "
            "Continue routine reviews so controls remain effective as systems and users change."
        )

    if risk_level == "HIGH":
        lead = "If left unresolved, these gaps could increase the likelihood of disruption, data exposure, or costly recovery work."
    elif risk_level == "MEDIUM":
        lead = "If left unresolved, these gaps may increase operational friction and make incidents harder to contain."
    else:
        lead = "If left unresolved, these gaps could still create avoidable exposure over time."

    themes = [risk["title"] for risk in top_risks[:3]]
    return f"{lead} The most important areas to address are: {escape('; '.join(themes))}."


def _sorted_fixes(fixes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        fixes,
        key=lambda fix: (SEVERITY_RANK.get(fix.get("severity", "medium"), 1), fix["title"]),
    )


def _top_risks(fixes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sorted_fixes = _sorted_fixes(fixes)
    high_fixes = [fix for fix in sorted_fixes if fix.get("severity") == "high"]
    return (high_fixes or sorted_fixes)[:3]


def _render_notes(notes: List[Any]) -> str:
    if not notes:
        return ""

    items = "".join(f"<li>{escape(str(note))}</li>" for note in notes)
    return f"""
    <div class="card observation-card">
        <div class="eyebrow">Context</div>
        <h3>Additional Observations</h3>
        <ul>{items}</ul>
    </div>
    """


def _render_top_risks(top_risks: List[Dict[str, Any]]) -> str:
    if not top_risks:
        return """
        <div class="card empty-state">
            No high-impact issues were identified from the provided responses.
        </div>
        """

    cards = ""
    for index, risk in enumerate(top_risks, 1):
        why = risk["why"] or "This item may increase avoidable security or operational risk."
        cards += f"""
        <div class="top-risk-card">
            <div class="top-risk-header">
                <span class="risk-number">{index}</span>
                {_severity_badge(risk["severity"])}
            </div>
            <h3>{escape(risk["title"])}</h3>
            <p>{escape(why)}</p>
        </div>
        """
    return cards


def _render_gate_cards(gates: List[Dict[str, Any]]) -> str:
    if not gates:
        return ""

    cards = ""
    for gate in gates:
        reasons = gate.get("reasons", []) or []
        reason_text = "; ".join(str(reason) for reason in reasons) or "High-impact baseline condition triggered."
        cards += f"""
        <div class="gate-card">
            <div class="gate-meta">
                <span>{escape(str(gate.get("gate_id", "Gate")))}</span>
                <span>Score cap {escape(str(gate.get("cap", "N/A")))}/100</span>
            </div>
            <div class="gate-title">{escape(reason_text)}</div>
        </div>
        """
    return cards


def _render_findings(fixes: List[Dict[str, Any]]) -> str:
    if not fixes:
        return """
        <div class="card empty-state">
            No detailed findings are required for this assessment.
        </div>
        """

    findings = ""
    for index, fix in enumerate(_sorted_fixes(fixes), 1):
        why = fix["why"] or "Addressing this item helps reduce avoidable security and operational risk."
        steps = "".join(f"<li>{escape(step)}</li>" for step in fix["steps"])
        steps_html = f"<ol>{steps}</ol>" if steps else '<p class="muted">No action steps supplied.</p>'

        findings += f"""
        <article class="finding-card">
            <div class="finding-index">{index:02d}</div>
            <div class="finding-content">
                <div class="finding-topline">
                    <div class="control-id">{escape(fix["id"])}</div>
                    {_severity_badge(fix["severity"])}
                </div>
                <h3>{escape(fix["title"])}</h3>
                <div class="finding-label">Why it matters</div>
                <p>{escape(why)}</p>
                <div class="finding-label">Recommended actions</div>
                {steps_html}
            </div>
        </article>
        """
    return findings


def _render_recommended_actions(fixes: List[Dict[str, Any]]) -> str:
    if not fixes:
        return """
        <div class="card empty-state">
            Continue routine review of this baseline and reassess after major environment changes.
        </div>
        """

    action_items = ""
    for fix in _sorted_fixes(fixes)[:5]:
        first_step = fix["steps"][0] if fix["steps"] else "Review this control and define an owner."
        action_items += f"""
        <li>
            <strong>{escape(fix["title"])}</strong>
            <span>{escape(first_step)}</span>
        </li>
        """

    return f"""
    <div class="card action-card">
        <ol>{action_items}</ol>
    </div>
    """


def build_report_html(result: Dict[str, Any], fixes: List[Dict[str, Any]], answers: Dict[str, str]) -> str:
    score = int(result.get("final_score", 0))
    grade = str(result.get("grade", "N/A"))
    cap = result.get("cap_applied", 100)
    gates = result.get("gates", []) or []
    notes = result.get("notes", []) or []
    failed_controls = [
        control_id
        for control_id in (
            _failed_control_id(control)
            for control in result.get("failed_controls", []) or []
        )
        if control_id
    ]
    fixes = _validated_fixes(fixes)
    top_risks = _top_risks(fixes)
    grade_style = _grade_style(grade)
    risk_level = _display_risk_level(result, score)
    risk_style = RISK_LEVEL_STYLES[risk_level]
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    summary = _executive_summary(score, grade, risk_level, fixes)
    business_impact = _business_impact_text(risk_level, top_risks)

    return f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            :root {{
                --primary: #2563eb;
                --primary-soft: #eff6ff;
                --bg: #f8fafc;
                --card: #ffffff;
                --text: #0f172a;
                --muted: #64748b;
                --line: #e2e8f0;
                --shadow: 0 12px 30px rgba(15, 23, 42, 0.06);
                --danger: #dc2626;
                --danger-bg: #fef2f2;
                --danger-border: #fecaca;
            }}

            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                padding: 34px 18px;
                background: var(--bg);
                color: var(--text);
                font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                line-height: 1.55;
            }}

            .report {{
                max-width: 900px;
                margin: 0 auto;
            }}

            .header,
            .score-overview,
            .card,
            .top-risk-card,
            .finding-card,
            .gate-card {{
                background: var(--card);
                border: 1px solid var(--line);
                border-radius: 14px;
                box-shadow: var(--shadow);
            }}

            .header {{
                padding: 30px;
                text-align: center;
            }}

            .product {{
                color: var(--primary);
                font-size: 12px;
                font-weight: 800;
                letter-spacing: 0.08em;
                text-transform: uppercase;
            }}

            h1, h2, h3, p {{
                letter-spacing: 0;
            }}

            .header h1 {{
                margin: 8px 0 8px;
                font-size: 31px;
                line-height: 1.18;
            }}

            .subtitle {{
                margin: 0 auto;
                max-width: 660px;
                color: var(--muted);
                font-size: 15px;
            }}

            .generated {{
                margin-top: 14px;
                color: #94a3b8;
                font-size: 12px;
            }}

            .score-overview {{
                margin-top: 18px;
                padding: 26px;
                display: grid;
                grid-template-columns: minmax(0, 1fr) repeat(3, minmax(120px, 0.42fr));
                gap: 16px;
                align-items: stretch;
            }}

            .score-main {{
                padding: 18px;
                border-radius: 12px;
                background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
                border: 1px solid #dbeafe;
                text-align: center;
            }}

            .metric-tile {{
                padding: 18px;
                border-radius: 12px;
                background: #f8fafc;
                border: 1px solid var(--line);
                text-align: center;
            }}

            .metric-label {{
                color: var(--muted);
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.06em;
                text-transform: uppercase;
            }}

            .score {{
                margin-top: 8px;
                color: #1d4ed8;
                font-size: 72px;
                line-height: 1;
                font-weight: 800;
            }}

            .score span {{
                color: var(--muted);
                font-size: 24px;
                font-weight: 650;
            }}

            .grade-badge,
            .risk-level-badge,
            .severity-badge {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                border-radius: 999px;
                border: 1px solid;
                font-weight: 800;
                white-space: nowrap;
            }}

            .grade-badge {{
                margin-top: 12px;
                padding: 8px 14px;
                color: {grade_style["color"]};
                background: {grade_style["bg"]};
                border-color: {grade_style["border"]};
                font-size: 13px;
            }}

            .risk-level-badge {{
                margin-top: 10px;
                padding: 8px 13px;
                color: {risk_style["color"]};
                background: {risk_style["bg"]};
                border-color: {risk_style["border"]};
                font-size: 13px;
            }}

            .metric-value {{
                margin-top: 10px;
                font-size: 24px;
                font-weight: 800;
            }}

            .section {{
                margin-top: 30px;
            }}

            .section-heading {{
                margin-bottom: 12px;
                display: flex;
                justify-content: space-between;
                align-items: end;
                gap: 16px;
            }}

            .section h2 {{
                margin: 0;
                font-size: 21px;
                line-height: 1.25;
            }}

            .section-copy {{
                margin: 4px 0 0;
                color: var(--muted);
                font-size: 14px;
            }}

            .section-count {{
                color: var(--muted);
                font-size: 13px;
                white-space: nowrap;
            }}

            .card {{
                padding: 21px;
            }}

            .card p {{
                margin: 0;
                color: #334155;
                font-size: 15px;
            }}

            .eyebrow,
            .control-id {{
                color: var(--primary);
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.06em;
                text-transform: uppercase;
                overflow-wrap: anywhere;
            }}

            .observation-card {{
                margin-top: 14px;
            }}

            .observation-card h3 {{
                margin: 5px 0 8px;
                font-size: 16px;
            }}

            .top-risk-grid {{
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 14px;
            }}

            .top-risk-card {{
                padding: 18px;
                min-height: 182px;
            }}

            .top-risk-header,
            .finding-topline {{
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
            }}

            .risk-number {{
                width: 30px;
                height: 30px;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                border-radius: 10px;
                background: var(--primary-soft);
                color: #1d4ed8;
                font-weight: 800;
                font-size: 13px;
            }}

            .top-risk-card h3 {{
                margin: 14px 0 8px;
                font-size: 16px;
                line-height: 1.3;
            }}

            .top-risk-card p {{
                margin: 0;
                color: #475569;
                font-size: 14px;
            }}

            .gate-grid {{
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
                margin-top: 14px;
            }}

            .gate-card {{
                padding: 15px;
                background: var(--danger-bg);
                border-color: var(--danger-border);
                box-shadow: none;
            }}

            .gate-meta {{
                display: flex;
                justify-content: space-between;
                gap: 12px;
                color: var(--danger);
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }}

            .gate-title {{
                margin-top: 8px;
                color: #1e293b;
                font-size: 14px;
                font-weight: 700;
                line-height: 1.35;
            }}

            .finding-card {{
                display: grid;
                grid-template-columns: 46px minmax(0, 1fr);
                gap: 16px;
                padding: 20px;
            }}

            .finding-card + .finding-card {{
                margin-top: 14px;
            }}

            .finding-index {{
                width: 38px;
                height: 38px;
                border-radius: 12px;
                background: var(--primary-soft);
                color: #1d4ed8;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 13px;
                font-weight: 800;
            }}

            .finding-content h3 {{
                margin: 5px 0 13px;
                font-size: 18px;
                line-height: 1.3;
            }}

            .finding-label {{
                margin-top: 12px;
                margin-bottom: 4px;
                color: #334155;
                font-size: 13px;
                font-weight: 800;
            }}

            .finding-content p {{
                margin: 0;
                color: #475569;
                font-size: 14px;
            }}

            .severity-badge {{
                padding: 5px 9px;
                font-size: 11px;
                letter-spacing: 0.04em;
                text-transform: uppercase;
            }}

            ol, ul {{
                margin: 7px 0 0;
                padding-left: 20px;
            }}

            li {{
                margin-bottom: 7px;
                color: #475569;
                font-size: 14px;
            }}

            .action-card li strong {{
                display: block;
                color: #0f172a;
                margin-bottom: 2px;
            }}

            .action-card li span {{
                color: #475569;
            }}

            .muted,
            .empty-state {{
                color: var(--muted);
                font-size: 14px;
            }}

            .footer {{
                margin: 30px 0 4px;
                color: #94a3b8;
                font-size: 12px;
                text-align: center;
            }}

            @media (max-width: 820px) {{
                .score-overview,
                .top-risk-grid,
                .gate-grid {{
                    grid-template-columns: 1fr;
                }}
            }}

            @media (max-width: 720px) {{
                body {{
                    padding: 18px 12px;
                }}

                .header,
                .score-overview,
                .card,
                .finding-card {{
                    border-radius: 12px;
                }}

                .score {{
                    font-size: 58px;
                }}

                .finding-card {{
                    grid-template-columns: 1fr;
                }}

                .section-heading {{
                    display: block;
                }}

                .section-count {{
                    display: block;
                    margin-top: 4px;
                }}
            }}
        </style>
    </head>
    <body>
        <main class="report">
            <header class="header">
                <div class="product">IRONCLAD</div>
                <h1>Security Baseline Report</h1>
                <p class="subtitle">
                    Executive view of security posture, business impact, and prioritized remediation.
                </p>
                <div class="generated">Generated {escape(generated_at)}</div>
            </header>

            <section class="score-overview">
                <div class="score-main">
                    <div class="metric-label">Overall Score</div>
                    <div class="score">{score}<span>/100</span></div>
                    <div class="grade-badge">Grade {escape(grade)} - {escape(grade_style["label"])}</div>
                </div>
                <div class="metric-tile">
                    <div class="metric-label">Risk Level</div>
                    <div class="risk-level-badge">{escape(risk_level)}</div>
                </div>
                <div class="metric-tile">
                    <div class="metric-label">Findings</div>
                    <div class="metric-value">{len(fixes)}</div>
                </div>
                <div class="metric-tile">
                    <div class="metric-label">Score Cap</div>
                    <div class="metric-value">{escape(str(cap))}</div>
                </div>
            </section>

            <section class="section">
                <div class="section-heading">
                    <div>
                        <h2>Executive Summary</h2>
                        <p class="section-copy">Plain-English assessment of current posture.</p>
                    </div>
                </div>
                <div class="card">
                    <p>{summary}</p>
                </div>
                {_render_notes(notes)}
            </section>

            <section class="section">
                <div class="section-heading">
                    <div>
                        <h2>Top Risks</h2>
                        <p class="section-copy">Highest-impact issues to address first.</p>
                    </div>
                    <div class="section-count">Top {len(top_risks)} of {len(fixes)} findings</div>
                </div>
                <div class="top-risk-grid">
                    {_render_top_risks(top_risks)}
                </div>
                <div class="gate-grid">
                    {_render_gate_cards(gates)}
                </div>
            </section>

            <section class="section">
                <div class="section-heading">
                    <div>
                        <h2>Business Impact</h2>
                        <p class="section-copy">What could happen if the top risks are not addressed.</p>
                    </div>
                </div>
                <div class="card">
                    <p>{business_impact}</p>
                </div>
            </section>

            <section class="section">
                <div class="section-heading">
                    <div>
                        <h2>Detailed Findings</h2>
                        <p class="section-copy">Risk severity, rationale, and practical remediation steps.</p>
                    </div>
                    <div class="section-count">{len(failed_controls)} failed controls</div>
                </div>
                {_render_findings(fixes)}
            </section>

            <section class="section">
                <div class="section-heading">
                    <div>
                        <h2>Recommended Actions</h2>
                        <p class="section-copy">Suggested first steps for remediation planning.</p>
                    </div>
                </div>
                {_render_recommended_actions(fixes)}
            </section>

            <div class="footer">
                This report is based on provided responses and is intended as a baseline guide, not a full audit.
            </div>
        </main>
    </body>
    </html>
    """
