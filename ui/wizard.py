from __future__ import annotations

from html import escape
from typing import Callable

import streamlit as st


def apply_styles() -> None:
    st.markdown(
        """
        <style>
            .stApp {
                background: #f8fafc;
            }

            .block-container {
                padding-top: 3rem;
                padding-bottom: 2.5rem;
                max-width: 900px;
            }

            h1 {
                letter-spacing: 0 !important;
                margin-bottom: 0.15rem !important;
            }

            [data-testid="stCaptionContainer"] {
                color: #64748b;
            }

            div[data-testid="stSelectbox"] {
                margin-top: 0.25rem;
                margin-bottom: 0.9rem;
            }

            div.stButton > button {
                border-radius: 8px !important;
                padding: 0.55rem 0.95rem !important;
                font-size: 14px !important;
                font-weight: 600 !important;
                border: 1px solid #dbe3ef !important;
                box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05) !important;
                transition:
                    background 0.16s ease,
                    border-color 0.16s ease,
                    color 0.16s ease,
                    box-shadow 0.16s ease,
                    transform 0.16s ease;
            }

            div.stButton > button:hover {
                border-color: #93c5fd !important;
                box-shadow: 0 4px 12px rgba(37, 99, 235, 0.12) !important;
                transform: translateY(-1px);
            }

            div.stButton > button[kind="primary"] {
                background: #2563eb !important;
                border-color: #2563eb !important;
                color: #ffffff !important;
            }

            div.stButton > button[kind="primary"]:hover {
                background: #1d4ed8 !important;
                border-color: #1d4ed8 !important;
            }

            div.stButton > button:disabled {
                opacity: 0.45 !important;
                cursor: not-allowed !important;
                box-shadow: none !important;
                transform: none !important;
            }

            /* Section title */
            .section-title {
                font-size: 20px;
                font-weight: 700;
                margin-top: 22px;
                margin-bottom: 14px;
                letter-spacing: 0;
                line-height: 1.18;
                color: #0f172a;
            }

            /* Radio question text */
            div[data-testid="stRadio"] > label {
                font-size: 15px !important;
                font-weight: 500 !important;
                margin-bottom: 6px !important;
                line-height: 1.35 !important;
            }

            /* Radio question paragraph */
            div[data-testid="stRadio"] > label p {
                font-size: 15px !important;
                font-weight: 500 !important;
                margin-bottom: 6px !important;
            }

            /* Radio options */
            div[role="radiogroup"] label {
                font-size: 14px !important;
                font-weight: 400 !important;
                margin-bottom: 2px !important;
                padding-top: 1px !important;
                padding-bottom: 1px !important;
            }

            div[role="radiogroup"] label p {
                font-size: 14px !important;
                font-weight: 400 !important;
                line-height: 1.3 !important;
                color: #334155 !important;
            }

            /* Space between questions */
            div[data-testid="stRadio"] {
                margin-bottom: 24px !important;
            }

            .assessment-card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                padding: 15px 17px;
                border-radius: 8px;
                margin: 0.85rem 0 1.05rem;
                box-shadow: 0 8px 20px rgba(15, 23, 42, 0.035);
            }

            .assessment-card-title {
                font-size: 15px;
                font-weight: 600;
                margin-bottom: 0.2rem;
            }

            .assessment-card-copy {
                font-size: 13px;
                color: #64748b;
                line-height: 1.4;
            }

            .step-label {
                text-align: center;
                font-size: 13px;
                font-weight: 600;
                color: #475569;
                margin: 0.5rem 0 0.35rem;
            }

            .progress-track {
                background: #e5e7eb;
                height: 6px;
                border-radius: 999px;
                margin-bottom: 1.25rem;
                overflow: hidden;
            }

            .progress-fill {
                background: linear-gradient(90deg, #3b82f6, #2563eb);
                height: 6px;
                border-radius: 999px;
                transition: width 0.38s ease;
            }

        </style>
        """,
        unsafe_allow_html=True,
    )


def render_intro_card() -> None:
    st.markdown(
        """
        <div class="assessment-card">
            <div class="assessment-card-title">Baseline Assessment</div>
            <div class="assessment-card-copy">
                Answer a few questions to evaluate your current security posture.
                Takes about 3-5 minutes.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_progress(current: int, total: int) -> None:
    progress = int(((current + 1) / total) * 100)

    st.markdown(
        f"""
        <div class="step-label">Step {current + 1} of {total}</div>
        <div class="progress-track">
            <div class="progress-fill" style="width:{progress}%"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_question(q: dict) -> None:
    qid = q["id"]
    labels = [opt["label"] for opt in q["options"]]
    keys = [opt["key"] for opt in q["options"]]

    existing_answer = st.session_state.answers.get(qid)
    default_idx = keys.index(existing_answer) if existing_answer in keys else None

    selected_label = st.radio(
        q["prompt"],
        labels,
        key=qid,
        index=default_idx,
    )

    if selected_label is not None:
        st.session_state.answers[qid] = keys[labels.index(selected_label)]


def section_is_complete(section: dict) -> bool:
    return all(
        st.session_state.answers.get(question["id"]) is not None
        for question in section["questions"]
    )


def render_wizard(sections: list[dict], on_submit: Callable[[dict], None]) -> None:
    current = st.session_state.section_index
    total = len(sections)
    section = sections[current]

    render_progress(current, total)

    st.markdown(
        f'<div class="section-title">{escape(section["title"])}</div>',
        unsafe_allow_html=True,
    )

    for question in section["questions"]:
        render_question(question)

    all_answered = section_is_complete(section)

    st.markdown("<div style='height: 0.25rem'></div>", unsafe_allow_html=True)

    left_col, spacer_col, right_col = st.columns([1.15, 5.85, 1.9], gap="small")

    with left_col:
        if current > 0:
            if st.button("Back", use_container_width=True):
                st.session_state.section_index -= 1
                st.rerun()

    with spacer_col:
        st.empty()

    with right_col:
        if current < total - 1:
            if st.button(
                "Next",
                type="primary",
                use_container_width=True,
                disabled=not all_answered,
            ):
                st.session_state.section_index += 1
                st.rerun()
        else:
            if st.button(
                "Generate Report",
                type="primary",
                use_container_width=True,
                disabled=not all_answered,
            ):
                on_submit(st.session_state.answers)
