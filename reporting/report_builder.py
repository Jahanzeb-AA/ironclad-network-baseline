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
    "high": {"color": "#b91c1c", "bg": "#fee2e2", "border": "#fca5a5"},
    "medium": {"color": "#c2410c", "bg": "#ffedd5", "border": "#fdba74"},
    "low": {"color": "#15803d", "bg": "#dcfce7", "border": "#86efac"},
}

VALID_SEVERITIES = set(SEVERITY_STYLES)


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


def _summary_text(score: int, grade: str, cap: Any, risk_count: int) -> str:
    if risk_count == 0:
        return (
            "The assessment did not identify major baseline gaps from the provided answers. "
            "The environment appears well aligned to the selected baseline, with routine reviews still recommended."
        )

    if score < 55:
        posture = "The current posture needs focused attention."
    elif score < 70:
        posture = "The environment has several important gaps to address."
    elif score < 85:
        posture = "The environment is generally workable, with targeted improvements recommended."
    else:
        posture = "The environment is in a strong position, with a small number of improvements available."

    return (
        f"{posture} The assessment produced grade {escape(grade)} with a score cap of "
        f"{escape(str(cap))}/100. The items below are prioritized to reduce business risk and improve resilience."
    )


def _render_notes(notes: List[Any]) -> str:
    if not notes:
        return ""

    items = "".join(f"<li>{escape(str(note))}</li>" for note in notes)
    return f"""
    <div class="card observation-card">
        <div class="card-eyebrow">Context</div>
        <h3>Additional Observations</h3>
        <ul>{items}</ul>
    </div>
    """


def _render_key_risks(
    fixes: List[Dict[str, Any]],
    gates: List[Dict[str, Any]],
    failed_controls: List[str],
) -> str:
    if not fixes and not gates and not failed_controls:
        return """
        <div class="card empty-state">
            No key risks were identified from the provided responses.
        </div>
        """

    fix_lookup = {fix["id"]: fix for fix in fixes}
    cards = ""

    for gate in gates:
        reasons = gate.get("reasons", []) or []
        reason_text = "; ".join(str(reason) for reason in reasons) or "High-impact baseline gap triggered."
        cards += f"""
        <div class="risk-card risk-critical">
            <div class="risk-meta">
                <span>{escape(str(gate.get("gate_id", "Gate")))}</span>
                <span>Cap {escape(str(gate.get("cap", "N/A")))}/100</span>
            </div>
            <div class="risk-title">{escape(reason_text)}</div>
        </div>
        """

    seen_controls = set()
    for control_id in failed_controls:
        if control_id in seen_controls:
            continue
        seen_controls.add(control_id)

        fix = fix_lookup.get(control_id, {})
        title = fix.get("title", control_id.replace("_", " ").title())
        cards += f"""
        <div class="risk-card risk-warning">
            <div class="risk-meta">
                <span>{escape(control_id)}</span>
            </div>
            <div class="risk-title">{escape(title)}</div>
        </div>
        """

    return cards


def _render_findings(fixes: List[Dict[str, Any]]) -> str:
    if not fixes:
        return """
        <div class="card empty-state">
            No detailed findings are required for this assessment. The submitted responses did not produce remediation items.
        </div>
        """

    findings = ""
    for index, fix in enumerate(fixes, 1):
        severity = str(fix.get("severity", "medium")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"
        severity_style = SEVERITY_STYLES[severity]
        steps = "".join(f"<li>{escape(step)}</li>" for step in fix["steps"])
        steps_html = f"<ol>{steps}</ol>" if steps else '<p class="muted">No action steps supplied.</p>'
        why = fix["why"] or "Addressing this item helps reduce avoidable security and operational risk."

        findings += f"""
        <div class="finding-card">
            <div class="finding-index">{index:02d}</div>
            <div class="finding-content">
                <div class="finding-topline">
                    <div class="control-id">{escape(fix["id"])}</div>
                    <div class="severity-badge" style="color:{severity_style['color']};background:{severity_style['bg']};border-color:{severity_style['border']};">
                        {escape(severity.title())} Severity
                    </div>
                </div>
                <h3>{escape(fix["title"])}</h3>

                <div class="finding-label">Why it matters</div>
                <p>{escape(why)}</p>

                <div class="finding-label">Action steps</div>
                {steps_html}
            </div>
        </div>
        """

    return findings


def _failed_control_id(control: Any) -> str:
    if isinstance(control, dict):
        return str(control.get("id", ""))
    return str(control)


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
    grade_style = _grade_style(grade)
    risk_level = _display_risk_level(result, score)
    risk_style = RISK_LEVEL_STYLES[risk_level]
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    summary = _summary_text(score, grade, cap, len(fixes))

    return f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            :root {{
                --primary: #3b82f6;
                --primary-dark: #1d4ed8;
                --bg: #f8fafc;
                --card: #ffffff;
                --text: #0f172a;
                --muted: #64748b;
                --line: #e2e8f0;
                --soft-shadow: 0 14px 35px rgba(15, 23, 42, 0.07);
                --danger: #dc2626;
                --danger-bg: #fef2f2;
                --danger-border: #fecaca;
                --warning: #ea580c;
                --warning-bg: #fff7ed;
                --warning-border: #fed7aa;
            }}

            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                padding: 32px 18px;
                background: var(--bg);
                color: var(--text);
                font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                line-height: 1.5;
            }}

            .report {{
                max-width: 900px;
                margin: 0 auto;
            }}

            .header {{
                background: var(--card);
                border: 1px solid var(--line);
                border-radius: 18px;
                padding: 28px;
                box-shadow: var(--soft-shadow);
                text-align: center;
            }}

            .product {{
                color: var(--primary);
                font-size: 13px;
                font-weight: 800;
                letter-spacing: 0.08em;
            }}

            .header h1 {{
                margin: 8px 0 6px;
                font-size: 30px;
                line-height: 1.2;
                letter-spacing: 0;
            }}

            .subtitle {{
                margin: 0 auto;
                max-width: 640px;
                color: var(--muted);
                font-size: 15px;
            }}

            .generated {{
                margin-top: 14px;
                color: #94a3b8;
                font-size: 12px;
            }}

            .score-card {{
                margin-top: 18px;
                background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
                border: 1px solid #dbeafe;
                border-radius: 18px;
                padding: 32px 24px;
                box-shadow: var(--soft-shadow);
                text-align: center;
            }}

            .score-grid {{
                display: grid;
                grid-template-columns: minmax(0, 1fr) minmax(220px, 0.55fr);
                gap: 18px;
                align-items: center;
            }}

            .score-main {{
                text-align: center;
            }}

            .risk-panel {{
                background: #ffffff;
                border: 1px solid var(--line);
                border-radius: 14px;
                padding: 18px;
                text-align: center;
            }}

            .score-label {{
                color: var(--muted);
                font-size: 13px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.06em;
            }}

            .score {{
                margin-top: 8px;
                color: var(--primary-dark);
                font-size: 76px;
                line-height: 1;
                font-weight: 800;
                letter-spacing: 0;
            }}

            .score span {{
                color: var(--muted);
                font-size: 24px;
                font-weight: 650;
            }}

            .grade-badge {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                margin-top: 12px;
                padding: 8px 14px;
                border-radius: 999px;
                color: {grade_style["color"]};
                background: {grade_style["bg"]};
                border: 1px solid {grade_style["border"]};
                font-size: 14px;
                font-weight: 750;
            }}

            .risk-level-badge {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                margin-top: 10px;
                padding: 9px 16px;
                border-radius: 999px;
                color: {risk_style["color"]};
                background: {risk_style["bg"]};
                border: 1px solid {risk_style["border"]};
                font-size: 15px;
                font-weight: 800;
                letter-spacing: 0.04em;
            }}

            .risk-panel-copy {{
                margin: 10px 0 0;
                color: var(--muted);
                font-size: 13px;
            }}

            .cap-text {{
                margin-top: 10px;
                color: var(--muted);
                font-size: 13px;
            }}

            .section {{
                margin-top: 28px;
            }}

            .section-heading {{
                margin-bottom: 12px;
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                gap: 16px;
            }}

            .section h2 {{
                margin: 0;
                font-size: 21px;
                line-height: 1.25;
                letter-spacing: 0;
            }}

            .section-count {{
                color: var(--muted);
                font-size: 13px;
                white-space: nowrap;
            }}

            .card {{
                background: var(--card);
                border: 1px solid var(--line);
                border-radius: 14px;
                padding: 20px;
                box-shadow: 0 8px 22px rgba(15, 23, 42, 0.04);
            }}

            .summary-card p {{
                margin: 0;
                color: #334155;
                font-size: 15px;
            }}

            .observation-card {{
                margin-top: 14px;
                background: #ffffff;
            }}

            .card-eyebrow, .control-id {{
                color: var(--primary);
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.06em;
                text-transform: uppercase;
                overflow-wrap: anywhere;
            }}

            .observation-card h3 {{
                margin: 4px 0 8px;
                font-size: 16px;
            }}

            .risk-grid {{
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
            }}

            .risk-card {{
                border-radius: 14px;
                padding: 16px;
                min-height: 112px;
                box-shadow: 0 8px 22px rgba(15, 23, 42, 0.04);
            }}

            .risk-critical {{
                background: var(--danger-bg);
                border: 1px solid var(--danger-border);
            }}

            .risk-warning {{
                background: var(--warning-bg);
                border: 1px solid var(--warning-border);
            }}

            .risk-meta {{
                display: flex;
                justify-content: space-between;
                gap: 12px;
                color: var(--muted);
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }}

            .risk-critical .risk-meta {{
                color: var(--danger);
            }}

            .risk-warning .risk-meta {{
                color: var(--warning);
            }}

            .risk-title {{
                margin-top: 10px;
                color: #1e293b;
                font-size: 15px;
                font-weight: 700;
                line-height: 1.35;
            }}

            .finding-card {{
                display: grid;
                grid-template-columns: 46px minmax(0, 1fr);
                gap: 16px;
                background: var(--card);
                border: 1px solid var(--line);
                border-radius: 14px;
                padding: 20px;
                box-shadow: 0 8px 22px rgba(15, 23, 42, 0.04);
            }}

            .finding-card + .finding-card {{
                margin-top: 14px;
            }}

            .finding-index {{
                width: 38px;
                height: 38px;
                border-radius: 12px;
                background: #eff6ff;
                color: var(--primary-dark);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 13px;
                font-weight: 800;
            }}

            .finding-content h3 {{
                margin: 4px 0 14px;
                font-size: 18px;
                line-height: 1.3;
                letter-spacing: 0;
            }}

            .finding-topline {{
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
            }}

            .severity-badge {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 5px 9px;
                border: 1px solid;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.04em;
                text-transform: uppercase;
                white-space: nowrap;
            }}

            .finding-label {{
                margin-top: 12px;
                margin-bottom: 4px;
                color: #334155;
                font-size: 13px;
                font-weight: 750;
            }}

            .finding-content p {{
                margin: 0;
                color: #475569;
                font-size: 14px;
            }}

            ol, ul {{
                margin: 6px 0 0;
                padding-left: 20px;
            }}

            li {{
                margin-bottom: 6px;
                color: #475569;
                font-size: 14px;
            }}

            .muted, .empty-state {{
                color: var(--muted);
                font-size: 14px;
            }}

            .footer {{
                margin: 28px 0 4px;
                color: #94a3b8;
                font-size: 12px;
                text-align: center;
            }}

            @media (max-width: 720px) {{
                body {{
                    padding: 18px 12px;
                }}

                .header, .score-card, .card, .finding-card {{
                    border-radius: 12px;
                }}

                .score {{
                    font-size: 58px;
                }}

                .risk-grid, .finding-card, .score-grid {{
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
                    A business-friendly overview of your baseline security posture, key risks,
                    and practical remediation steps.
                </p>
                <div class="generated">Generated {escape(generated_at)}</div>
            </header>

            <section class="score-card">
                <div class="score-grid">
                    <div class="score-main">
                        <div class="score-label">Overall Score</div>
                        <div class="score">{score}<span>/100</span></div>
                        <div class="grade-badge">Grade {escape(grade)} - {escape(grade_style["label"])}</div>
                        <div class="cap-text">Score cap applied: {escape(str(cap))}/100</div>
                    </div>
                    <div class="risk-panel">
                        <div class="score-label">Risk Level</div>
                        <div class="risk-level-badge">{escape(risk_level)}</div>
                        <p class="risk-panel-copy">
                            Risk level is based on failed controls and triggered gates for simple executive prioritization.
                        </p>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="section-heading">
                    <h2>Executive Summary</h2>
                </div>
                <div class="card summary-card">
                    <p>{summary}</p>
                </div>
                {_render_notes(notes)}
            </section>

            <section class="section">
                <div class="section-heading">
                    <h2>Key Risks</h2>
                    <div class="section-count">{len(fixes)} failed controls</div>
                </div>
                <div class="risk-grid">
                    {_render_key_risks(fixes, gates, failed_controls)}
                </div>
            </section>

            <section class="section">
                <div class="section-heading">
                    <h2>Detailed Findings</h2>
                    <div class="section-count">{len(fixes)} remediation items</div>
                </div>
                {_render_findings(fixes)}
            </section>

            <div class="footer">
                This report is based on provided responses and is intended as a baseline guide, not a full audit.
            </div>
        </main>
    </body>
    </html>
    """
