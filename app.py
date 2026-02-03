import json
import streamlit as st

from scoring import score_assessment_dict
from policy_intent import generate_fix_blocks
from report_builder import build_report_html


# =========================
# Branding / Metadata
# =========================
PLATFORM_NAME = "IRONCLAD"
ASSESSMENT_NAME = "Network Baseline (SMB)"
VERSION = "1.0"

APP_TITLE = f"{PLATFORM_NAME} — {ASSESSMENT_NAME}"
APP_SUBTITLE = "Standards-aligned baseline security architecture self-assessment for SMB environments"


# =========================
# Helpers
# =========================
def load_questions(path: str = "questions.json") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def init_state():
    if "section_index" not in st.session_state:
        st.session_state.section_index = 0
    if "answers" not in st.session_state:
        st.session_state.answers = {}
    if "submitted" not in st.session_state:
        st.session_state.submitted = False
    if "result" not in st.session_state:
        st.session_state.result = None
    if "fixes" not in st.session_state:
        st.session_state.fixes = None
    if "report_html" not in st.session_state:
        st.session_state.report_html = None
    if "demo_mode" not in st.session_state:
        st.session_state.demo_mode = False
    if "show_demo_notice" not in st.session_state:
        st.session_state.show_demo_notice = False


def inject_ui_css():
    st.markdown(
        """
        <style>
        /* Question text (bigger than answers, not shouty) */
        label[data-testid="stWidgetLabel"] p {
            font-size: 20px !important;
            font-weight: 400 !important;
            line-height: 1.4 !important;
            margin-bottom: 8px !important;
            color: #111 !important;
        }

        /* Answer options */
        div[data-testid="stRadio"] div[role="radiogroup"] label {
            font-size: 16px !important;
            font-weight: 400 !important;
        }

        /* Spacing between questions */
        div[data-testid="stRadio"] {
            margin-bottom: 24px !important;
        }

        /* Slightly improve header weight */
        h1, h2, h3 {
            font-weight: 700 !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


def render_about_tool():
    with st.expander("About this tool", expanded=False):
        st.markdown(f"""
**{APP_TITLE}** is a lightweight, standards-aligned self-assessment designed to evaluate foundational network security
architecture in small-to-medium business environments.

### What this assessment covers
- Perimeter exposure and remote access approach
- Network segmentation and guest isolation
- Wireless security baseline
- Operational hygiene (backups, updates, logging)

### What this assessment does NOT cover
- Penetration testing or vulnerability scanning
- SIEM / SOC operations
- Enterprise routing designs (BGP, MPLS)
- Cloud security posture management
- Physical security systems (CCTV, biometrics)

### How to use the results
This assessment provides **policy intent and architectural guidance**, not vendor-specific configurations or scripts.
It is intended to highlight material risk and support informed discussions between IT and management.

Recommendations are aligned with:
- CIS Critical Security Controls (IG1)
- NIST SMB security guidance

“Not sure” responses are treated as failing controls, reflecting real-world risk assumptions.
""")


def reset_assessment():
    st.session_state.section_index = 0
    st.session_state.answers = {}
    st.session_state.submitted = False
    st.session_state.result = None
    st.session_state.fixes = None
    st.session_state.report_html = None
    st.session_state.demo_mode = False
    st.session_state.show_demo_notice = False


def set_demo_answers(data: dict):
    """
    Demo mode: fill answers with a 'reasonable SMB baseline' set.
    Label-based heuristics:
    - Prefer "yes/enabled/implemented/segmented/enforced"
    - Avoid "not sure/unknown/no/none/disabled"
    """
    answers = {}
    sections = data.get("sections", [])

    preferred_phrases = [
        "yes", "enabled", "implemented", "in place", "configured", "enforced",
        "required", "segmented", "isolated", "mfa", "2fa", "backup", "offline",
        "immutable", "encrypted", "logged", "monitor", "patched", "updated",
        "least privilege", "separate", "guest", "wpa3", "wpa2"
    ]
    avoid_phrases = ["not sure", "unknown", "no", "none", "disabled", "not implemented"]

    for section in sections:
        for q in section.get("questions", []):
            qid = q.get("id")
            options = q.get("options", [])
            if not qid or not options:
                continue

            option_keys = [o.get("key", "") for o in options]
            option_labels = [o.get("label", "") for o in options]

            best_idx = 0
            best_score = -10_000

            for i, label in enumerate(option_labels):
                l = (label or "").strip().lower()
                score = 0

                for p in preferred_phrases:
                    if p in l:
                        score += 3

                for a in avoid_phrases:
                    if a in l:
                        score -= 5

                if "not sure" in l:
                    score -= 25

                # Small penalty for very long labels (prefer clean)
                score -= min(len(l) / 80, 2)

                if score > best_score:
                    best_score = score
                    best_idx = i

            selected_key = option_keys[best_idx] if best_idx < len(option_keys) else option_keys[0]
            answers[qid] = selected_key

    st.session_state.answers = answers
    st.session_state.demo_mode = True
    st.session_state.section_index = 0
    st.session_state.show_demo_notice = True


def render_section(section: dict, answers: dict):
    st.header(section["title"])
    if not section.get("scored", False):
        st.caption("Informational section (does not directly affect score).")

    for q in section["questions"]:
        qid = q["id"]
        prompt = q["prompt"]
        options = q["options"]

        option_keys = [o["key"] for o in options]
        option_labels = [o["label"] for o in options]

        stored_key = answers.get(qid)

        # If already answered, show that selection by default.
        # If not answered, keep it blank by using index=None (no default selection).
        if stored_key in option_keys:
            default_index = option_keys.index(stored_key)
        else:
            default_index = None  # <-- No default selection

        selected_label = st.radio(
            prompt,
            options=option_labels,
            index=default_index,
            key=f"radio_{qid}",
        )

        # Only store if user selected something (selected_label is None if not selected yet)
        if selected_label is not None:
            selected_key = option_keys[option_labels.index(selected_label)]
            answers[qid] = selected_key


def all_questions_answered(data: dict, answers: dict) -> bool:
    for section in data.get("sections", []):
        for q in section.get("questions", []):
            qid = q.get("id")
            if qid and qid not in answers:
                return False
    return True


# =========================
# Main App
# =========================
def main():
    st.set_page_config(page_title=APP_TITLE, page_icon="🧭", layout="centered")
    init_state()
    inject_ui_css()

    data = load_questions("questions.json")
    sections = data["sections"]

    # Sidebar controls (always available)
    with st.sidebar:
        st.markdown("### Controls")

        if st.button("Load demo answers"):
            set_demo_answers(data)
            st.rerun()

        if st.button("Reset assessment"):
            reset_assessment()
            st.rerun()

        st.markdown("---")
        st.caption("Demo mode fills answers to show the report quickly.")

    st.title(APP_TITLE)
    st.caption(APP_SUBTITLE)

    # Small notice after demo selection
    if st.session_state.show_demo_notice:
        try:
            st.toast("Demo answers have been selected.", icon="✅")
        except Exception:
            st.success("Demo answers have been selected.")
        st.session_state.show_demo_notice = False

    st.write("---")

    # =========================
    # Results view
    # =========================
    if st.session_state.submitted:
        result = st.session_state.result
        fixes = st.session_state.fixes
        report_html = st.session_state.report_html

        st.subheader("Assessment Result")
        col1, col2, col3 = st.columns(3)
        col1.metric("Score", f"{result['final_score']}/100")
        col2.metric("Grade", result["grade"])
        col3.metric("Cap Applied", f"{result['cap_applied']}/100")

        if result.get("notes"):
            with st.expander("Notes / Assumptions", expanded=False):
                for n in result["notes"]:
                    st.write(f"- {n}")
                st.write("- Not sure responses are treated as failing controls in this baseline assessment.")

        st.write("---")

        tab1, tab2 = st.tabs(["Report", "Raw Data"])

        with tab1:
            st.subheader("Report")
            st.caption("This is a baseline architecture assessment for SMB environments. It provides policy intent, not vendor-specific scripts.")
            st.components.v1.html(report_html, height=900, scrolling=True)

            st.download_button(
                label="⬇️ Download report (HTML)",
                data=report_html.encode("utf-8"),
                file_name="baseline_network_smb_report.html",
                mime="text/html",
            )

            st.write("---")
            st.subheader("Optional: Email a copy (not implemented yet)")
            st.caption("Email delivery can be added later. Download is available without email.")
            _ = st.text_input("Email address (optional)", value="")
            _ = st.text_input("Name (optional)", value="")
            st.caption("If enabled later: your email would be used only to send you this report. No marketing. No selling identifiable data.")
            st.button("Send email copy (placeholder)", disabled=True)

        with tab2:
            st.subheader("Scoring Output")
            st.json(result)
            st.subheader("Fix Blocks Output")
            st.json(fixes)

        st.write("---")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Start a new assessment"):
                reset_assessment()
                st.rerun()
        with col_b:
            st.download_button(
                label="⬇️ Download raw scoring JSON",
                data=json.dumps(result, indent=2).encode("utf-8"),
                file_name="baseline_network_smb_scoring.json",
                mime="application/json",
            )

        # About at bottom (best place for UX)
        st.write("---")
        render_about_tool()

        st.write("---")
        st.caption(f"{PLATFORM_NAME} v{VERSION} • {ASSESSMENT_NAME} • Policy intent only • No vendor-specific scripts • No data stored")
        return

    # =========================
    # Wizard view
    # =========================
    current = st.session_state.section_index
    total = len(sections)

    st.progress((current + 1) / total)
    st.caption(f"Section {current + 1} of {total}")

    render_section(sections[current], st.session_state.answers)

    st.write("---")
    col_back, col_next = st.columns(2)

    with col_back:
        if st.button("⬅️ Back", disabled=(current == 0)):
            st.session_state.section_index = max(0, current - 1)
            st.rerun()

    with col_next:
        if current < total - 1:
            if st.button("Next ➡️"):
                st.session_state.section_index = min(total - 1, current + 1)
                st.rerun()
        else:
            can_generate = all_questions_answered(data, st.session_state.answers)

            if st.button("Generate Report 📄", disabled=(not can_generate)):
                answers = st.session_state.answers
                result = score_assessment_dict(answers)
                fixes = generate_fix_blocks(result["failed_controls"], result["gates"])
                report_html = build_report_html(result, fixes, answers)

                st.session_state.result = result
                st.session_state.fixes = fixes
                st.session_state.report_html = report_html
                st.session_state.submitted = True
                st.rerun()

            if not can_generate:
                st.caption("Answer all questions to generate the report. (Or use “Load demo answers” for a quick demo.)")

    # About at bottom so it doesn't push questions unless expanded
    st.write("---")
    render_about_tool()

    st.write("---")
    st.caption("IRONCLAD v1.0 • Network Baseline (SMB) • Policy intent only • No vendor-specific scripts • No data stored")


if __name__ == "__main__":
    main()
