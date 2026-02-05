from __future__ import annotations
from typing import Dict, Any, List
from html import escape


def _h(text: str) -> str:
    return escape(text or "")


def _pill(label: str) -> str:
    return (
        "<span style='display:inline-block;padding:2px 8px;border:1px solid #ccc;"
        "border-radius:999px;font-size:12px;margin-right:6px'>"
        f"{_h(label)}</span>"
    )


def _render_alerts(notes: List[str]) -> str:
    if not notes:
        return ""

    items = "".join([f"<li>{_h(n)}</li>" for n in notes])

    return f"""
    <div class="card" style="border-left: 6px solid #111;">
      <h3 style="margin-top:0;">High Priority Alerts</h3>
      <div class="muted">These alerts highlight contradictions, unknowns, or architecture conditions that materially change risk.</div>
      <ul style="margin-top:10px;">
        {items}
      </ul>
    </div>
    """


def build_report_html(result: Dict[str, Any], fixes: Dict[str, Any], answers: Dict[str, str]) -> str:
    score = result["final_score"]
    grade = result["grade"]
    cap = result["cap_applied"]
    multiplier = result["device_multiplier"]
    notes: List[str] = result.get("notes", []) or []

    gate_summaries: List[Dict[str, Any]] = fixes.get("gate_summaries", [])
    critical_fixes: List[Dict[str, Any]] = fixes.get("critical_fixes", [])
    recommended_fixes: List[Dict[str, Any]] = fixes.get("recommended_fixes", [])

    # Executive: choose top 3 critical items by order
    top_exec = critical_fixes[:3]

    # Simple inline CSS (keep it boring and readable)
    css = """
    body { font-family: Arial, sans-serif; color: #111; line-height: 1.35; }
    .container { max-width: 900px; margin: 24px auto; padding: 0 12px; }
    .header { border-bottom: 2px solid #eee; padding-bottom: 12px; margin-bottom: 16px; }
    .muted { color: #555; font-size: 13px; }
    .card { border: 1px solid #eee; border-radius: 10px; padding: 14px; margin: 12px 0; background: #fff; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .kpi { font-size: 34px; font-weight: 700; }
    .kpi_sub { font-size: 13px; color: #555; }
    h2 { margin: 22px 0 8px; }
    h3 { margin: 16px 0 6px; }
    ul { margin: 8px 0 0 18px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; font-size: 13px; }
    .ref { margin-top: 8px; }
    .ref span { margin-right: 8px; }
    """

    # Gate section text
    cap_note = ""
    if cap < 100:
        cap_note = f"Score cap applied due to failed security gates. Maximum possible score in current state: {cap}/100."

    alerts_html = _render_alerts(notes)

    # Build HTML
    html = f"""
    <html>
    <head><style>{css}</style></head>
    <body>
      <div class="container">
        <div class="header">
          <h1>SMB Network Baseline Assessment Report</h1>
          <div class="muted">This report evaluates baseline security architecture controls for small-to-medium business environments.</div>
        </div>

        <div class="card">
          <div class="grid">
            <div>
              <div class="kpi">{score}/100</div>
              <div class="kpi_sub">Overall Score</div>
            </div>
            <div>
              <div class="kpi">{_h(grade)}</div>
              <div class="kpi_sub">Grade</div>
            </div>
          </div>
          <div class="muted" style="margin-top:10px;">
            Device-scale multiplier applied to selected categories: {_h(str(multiplier))}x<br/>
            {_h(cap_note)}
          </div>
        </div>

        <h2>Executive Summary</h2>

        {alerts_html}

        <div class="card">
          <h3>Key Findings</h3>
          <ul>
            {"".join([f"<li><b>{_h(x.get('title',''))}</b>: {_h(x.get('finding',''))}</li>" for x in top_exec]) if top_exec else "<li>No critical findings detected based on provided answers.</li>"}
          </ul>

          <h3 style="margin-top:14px;">Security Gates</h3>
          {"".join([f"<div class='card'><b>{_h(g['gate_id'])} — {_h(g['title'])}</b><div class='muted'>{_h(g['summary'])}</div><ul>" + "".join([f"<li>{_h(r)}</li>" for r in g.get('reasons',[])]) + f"</ul><div class='muted'>Cap: {_h(str(g.get('cap')))}</div></div>" for g in gate_summaries]) if gate_summaries else "<div class='muted'>No failed security gates detected.</div>"}
        </div>

        <h2>Technical Findings</h2>
        <div class="card">
          <h3>Score Breakdown</h3>
          <table>
            <tr><th>Category</th><th>Deduction</th></tr>
            <tr><td>Perimeter</td><td>{result['deductions']['perimeter']}</td></tr>
            <tr><td>Segmentation</td><td>{result['deductions']['segmentation']}</td></tr>
            <tr><td>Wireless</td><td>{result['deductions']['wireless']}</td></tr>
            <tr><td>Hygiene/Operations</td><td>{result['deductions']['hygiene']}</td></tr>
            <tr><td><b>Multiplied total (seg+wifi+hyg)</b></td><td><b>{result['deductions']['multiplied_total']}</b></td></tr>
            <tr><td><b>Total deductions</b></td><td><b>{result['deductions']['total']}</b></td></tr>
            <tr><td><b>Raw score</b></td><td><b>{result['raw_score']}</b></td></tr>
            <tr><td><b>Cap applied</b></td><td><b>{result['cap_applied']}</b></td></tr>
          </table>
        </div>

        <h3>Critical Fixes</h3>
        {"".join([_render_fix_block(b) for b in critical_fixes]) if critical_fixes else "<div class='muted'>No critical fixes triggered.</div>"}

        <h3>Recommended Fixes</h3>
        {"".join([_render_fix_block(b) for b in recommended_fixes]) if recommended_fixes else "<div class='muted'>No additional recommendations triggered.</div>"}

        <h2>Appendix</h2>
        <div class="card">
          <h3>Answers (as provided)</h3>
          <table>
            <tr><th>Question ID</th><th>Answer</th></tr>
            {"".join([f"<tr><td>{_h(k)}</td><td>{_h(v)}</td></tr>" for k,v in sorted(answers.items())])}
          </table>
          <div class="muted" style="margin-top:10px;">
            Note: “Not sure” responses are treated as failing controls in this baseline assessment.
          </div>
        </div>

      </div>
    </body>
    </html>
    """
    return html


def _render_fix_block(b: Dict[str, Any]) -> str:
    refs = b.get("references", [])
    ref_html = "".join([_pill(r) for r in refs])
    gate = b.get("gate")
    gate_txt = f"<div class='muted'>Gate: {_h(gate)}</div>" if gate else ""
    return f"""
      <div class="card">
        <b>{_h(b.get('title',''))}</b>
        {gate_txt}
        <div style="margin-top:8px;"><b>Finding:</b> {_h(b.get('finding',''))}</div>
        <div style="margin-top:6px;"><b>Policy intent:</b> {_h(b.get('policy_intent',''))}</div>
        <div style="margin-top:6px;"><b>Technical rationale:</b> {_h(b.get('technical_rationale',''))}</div>
        <div class="ref" style="margin-top:10px;">{ref_html}</div>
      </div>
    """
