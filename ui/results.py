from __future__ import annotations

from typing import Callable

import streamlit as st


REPORT_DOWNLOAD_FILENAME = "ironclad-report.html"
REPORT_DOWNLOAD_MIME = "text/html"


def build_report_download(report_html: str) -> tuple[bytes, str, str]:
    # HTML-first export. Future PDF conversion can be added here without
    # changing the results view or report-generation flow.
    return (
        report_html.encode("utf-8"),
        REPORT_DOWNLOAD_FILENAME,
        REPORT_DOWNLOAD_MIME,
    )


def render_results(on_reset: Callable[[], None]) -> None:
    result = st.session_state.result
    fixes = st.session_state.fixes
    report_html = st.session_state.report_html

    st.subheader("Assessment Result")

    col1, col2, col3 = st.columns(3)
    col1.metric("Score", f"{result['final_score']}/100")
    col2.metric("Grade", result["grade"])
    col3.metric("Cap", f"{result['cap_applied']}")

    st.divider()

    tab1, tab2 = st.tabs(["Report", "Raw Data"])

    with tab1:
        st.components.v1.html(report_html, height=900, scrolling=True)
        download_data, download_name, download_mime = build_report_download(report_html)
        st.markdown("<div style='height: 0.5rem'></div>", unsafe_allow_html=True)
        st.download_button(
            "Download Report",
            data=download_data,
            file_name=download_name,
            mime=download_mime,
            type="primary",
        )

    with tab2:
        st.json(result)
        st.json(fixes)

    if st.button("Start New Assessment", type="primary"):
        on_reset()
