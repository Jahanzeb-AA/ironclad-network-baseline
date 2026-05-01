import streamlit as st

from core.baseline_loader import list_baselines, load_baseline
from core.validation import BaselineValidationError, validate_baseline
from reporting.report_builder import build_report_html
from ui.results import render_results
from ui.wizard import apply_styles, render_intro_card, render_wizard


PLATFORM_NAME = "IRONCLAD"


def init_state() -> None:
    defaults = {
        "section_index": 0,
        "answers": {},
        "submitted": False,
        "result": None,
        "fixes": None,
        "report_html": None,
        "active_baseline": "network",
        "validated_baselines": set(),
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def reset_assessment(active_baseline: str | None = None) -> None:
    st.session_state.clear()
    if active_baseline:
        st.session_state.active_baseline = active_baseline
    st.rerun()


def validate_current_baseline(
    baseline_key: str,
    questions_json: dict,
    scoring_module,
    policy_module,
) -> None:
    if baseline_key in st.session_state.validated_baselines:
        return

    try:
        validate_baseline(questions_json, scoring_module, policy_module)
    except BaselineValidationError as exc:
        st.error(f"Baseline validation failed: {exc}")
        st.stop()

    st.session_state.validated_baselines.add(baseline_key)


def submit_assessment(answers: dict, scoring_module, policy_module) -> None:
    result = scoring_module.score_assessment_dict(answers)
    fixes = policy_module.generate_fix_blocks(
        result["failed_controls"],
        result["gates"],
    )

    st.session_state.result = result
    st.session_state.fixes = fixes
    st.session_state.report_html = build_report_html(result, fixes, answers)
    st.session_state.submitted = True
    st.rerun()


def main() -> None:
    st.set_page_config(page_title=PLATFORM_NAME, page_icon="IC", layout="centered")
    apply_styles()
    init_state()

    baselines = list_baselines()
    baseline_keys = list(baselines.keys())
    if st.session_state.active_baseline not in baseline_keys:
        st.session_state.active_baseline = baseline_keys[0]

    baseline_choice = st.selectbox(
        "Select Assessment Type",
        baseline_keys,
        index=baseline_keys.index(st.session_state.active_baseline),
        format_func=lambda key: baselines[key],
    )

    if baseline_choice != st.session_state.active_baseline:
        reset_assessment(active_baseline=baseline_choice)

    try:
        baseline = load_baseline(baseline_choice)
    except (FileNotFoundError, ImportError, ValueError) as exc:
        st.error(f"Baseline load failed: {exc}")
        st.stop()

    validate_current_baseline(
        baseline_key=baseline_choice,
        questions_json=baseline["questions"],
        scoring_module=baseline["scoring_module"],
        policy_module=baseline["policy_module"],
    )

    st.title(f"{PLATFORM_NAME} - {baseline['name']}")
    st.caption("Baseline security posture assessment for SMB environments")
    render_intro_card()

    if st.session_state.submitted:
        render_results(on_reset=reset_assessment)
        return

    render_wizard(
        sections=baseline["questions"]["sections"],
        on_submit=lambda answers: submit_assessment(
            answers=answers,
            scoring_module=baseline["scoring_module"],
            policy_module=baseline["policy_module"],
        ),
    )


if __name__ == "__main__":
    main()
