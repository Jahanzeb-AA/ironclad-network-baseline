from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


GATE_CAPS = {
    "G1": 40,  # MFA not enforced for all users
    "G2": 45,  # Legacy authentication not blocked
    "G3": 55,  # External forwarding allowed
    "G4": 65,  # Audit logging disabled
    "G5": 70,  # No independent M365 backup
}


CTRL_MFA = "CTRL_M365_MFA_NOT_ENFORCED"
CTRL_LEGACY_AUTH = "CTRL_M365_LEGACY_AUTH_ALLOWED"
CTRL_ADMIN_SEPARATION = "CTRL_M365_ADMIN_SEPARATION"
CTRL_CONDITIONAL_ACCESS = "CTRL_M365_CONDITIONAL_ACCESS"
CTRL_GLOBAL_ADMINS = "CTRL_M365_TOO_MANY_GLOBAL_ADMINS"
CTRL_EXTERNAL_FORWARDING = "CTRL_M365_EXTERNAL_FORWARDING_ALLOWED"
CTRL_EXTERNAL_BANNER = "CTRL_M365_EXTERNAL_BANNER_MISSING"
CTRL_PHISHING_PROTECTION = "CTRL_M365_PHISHING_PROTECTION_MISSING"
CTRL_EMAIL_AUTH = "CTRL_M365_EMAIL_AUTH_INCOMPLETE"
CTRL_ANONYMOUS_SHARING = "CTRL_M365_ANONYMOUS_SHARING"
CTRL_BACKUPS = "CTRL_M365_BACKUPS_MISSING"
CTRL_AUDIT_LOGGING = "CTRL_M365_AUDIT_LOGGING_DISABLED"
CTRL_DEVICE_COMPLIANCE = "CTRL_M365_DEVICE_COMPLIANCE_MISSING"


@dataclass
class GateResult:
    gate_id: str
    failed: bool
    cap: int
    reasons: List[str]


@dataclass
class FailedControl:
    id: str
    category: str
    severity: str


@dataclass
class ScoreBreakdown:
    raw_score: int
    cap_applied: int
    final_score: int
    grade: str
    gates: List[GateResult]
    deductions: Dict[str, int]
    failed_controls: List[FailedControl]
    risk_level: str
    notes: List[str]


def grade_from_score(score: int) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _is_not_sure(value: Optional[str]) -> bool:
    return value == "NOT_SURE" or value is None


def _add_failed(
    failed_controls: List[FailedControl],
    control_id: str,
    category: str,
    severity: str,
) -> None:
    if not any(control.id == control_id for control in failed_controls):
        failed_controls.append(
            FailedControl(id=control_id, category=category, severity=severity)
        )


def risk_level_from_findings(failed_control_count: int, triggered_gate_count: int) -> str:
    if triggered_gate_count >= 2 or failed_control_count >= 6:
        return "high"
    if triggered_gate_count == 1 or failed_control_count >= 3:
        return "medium"
    return "low"


def _gate(gate_id: str, reasons: List[str]) -> GateResult:
    return GateResult(
        gate_id=gate_id,
        failed=bool(reasons),
        cap=GATE_CAPS[gate_id],
        reasons=reasons,
    )


def score_assessment(answers: Dict[str, str]) -> ScoreBreakdown:
    notes: List[str] = []
    failed_controls: List[FailedControl] = []
    all_gates: List[GateResult] = []

    user_count = answers.get("A1_USER_COUNT")

    if user_count in ("U_301_1000", "U_1000_PLUS"):
        notes.append(
            "Larger Microsoft 365 environments benefit from more formal change control, role review, and monitoring ownership."
        )

    if answers.get("F1_SENSITIVE_DATA") == "YES":
        notes.append(
            "This environment handles sensitive data. Security gaps may have regulatory impact."
        )

    if answers.get("A2_LICENSE_TYPE") == "BASIC_STANDARD":
        notes.append(
            "Some controls, such as Conditional Access, may require Microsoft 365 Business Premium or Enterprise licensing."
        )

    b1_mfa = answers.get("B1_MFA_ENFORCEMENT")
    b2_legacy_auth = answers.get("B2_LEGACY_AUTH")
    b3_admin_accounts = answers.get("B3_ADMIN_ACCOUNTS")
    b4_conditional_access = answers.get("B4_CONDITIONAL_ACCESS")
    b5_global_admins = answers.get("B5_GLOBAL_ADMINS")
    c1_auto_forwarding = answers.get("C1_AUTO_FORWARDING")
    c2_external_banner = answers.get("C2_EXTERNAL_BANNER")
    c3_spam_phishing = answers.get("C3_SPAM_PHISHING")
    c4_email_auth = answers.get("C4_EMAIL_AUTH")
    d1_sharepoint_sharing = answers.get("D1_SHAREPOINT_SHARING")
    d2_m365_backups = answers.get("D2_M365_BACKUPS")
    e1_audit_logging = answers.get("E1_AUDIT_LOGGING")
    e2_device_compliance = answers.get("E2_DEVICE_COMPLIANCE")

    identity = 0
    email = 0
    data = 0
    operations = 0

    # G1 - MFA must be enforced for every user.
    g1_reasons: List[str] = []
    if b1_mfa != "YES":
        g1_reasons.append("MFA is not enforced for all users.")
        _add_failed(failed_controls, CTRL_MFA, "identity", "high")
        identity += 15 if b1_mfa == "ADMIN_ONLY" else 25
    all_gates.append(_gate("G1", g1_reasons))

    # G2 - Legacy authentication must be blocked.
    g2_reasons: List[str] = []
    if b2_legacy_auth != "YES":
        g2_reasons.append("Legacy authentication is not fully blocked.")
        _add_failed(failed_controls, CTRL_LEGACY_AUTH, "identity", "high")
        identity += 20
    all_gates.append(_gate("G2", g2_reasons))

    if b3_admin_accounts != "SEPARATE":
        identity += 8
        _add_failed(failed_controls, CTRL_ADMIN_SEPARATION, "identity", "medium")

    if b4_conditional_access in ("NO", "NOT_SURE", None):
        identity += 10
        _add_failed(failed_controls, CTRL_CONDITIONAL_ACCESS, "identity", "medium")

    if b5_global_admins == "GT_8" or _is_not_sure(b5_global_admins):
        identity += 8
        _add_failed(failed_controls, CTRL_GLOBAL_ADMINS, "identity", "medium")
    elif b5_global_admins == "R_4_8":
        identity += 4
        _add_failed(failed_controls, CTRL_GLOBAL_ADMINS, "identity", "medium")

    # G3 - External forwarding should be blocked.
    g3_reasons: List[str] = []
    if c1_auto_forwarding != "YES_BLOCKED":
        g3_reasons.append("External email forwarding is allowed or unknown.")
        _add_failed(failed_controls, CTRL_EXTERNAL_FORWARDING, "email", "high")
        email += 15
    all_gates.append(_gate("G3", g3_reasons))

    if c2_external_banner != "YES":
        email += 5
        _add_failed(failed_controls, CTRL_EXTERNAL_BANNER, "email", "low")

    if c3_spam_phishing != "YES":
        email += 10
        _add_failed(failed_controls, CTRL_PHISHING_PROTECTION, "email", "high")

    if c4_email_auth == "PARTIAL":
        email += 5
        _add_failed(failed_controls, CTRL_EMAIL_AUTH, "email", "medium")
    elif c4_email_auth == "NO" or _is_not_sure(c4_email_auth):
        email += 12
        _add_failed(failed_controls, CTRL_EMAIL_AUTH, "email", "medium")

    if d1_sharepoint_sharing == "YES_WITH_EXPIRATION":
        data += 5
        _add_failed(failed_controls, CTRL_ANONYMOUS_SHARING, "data", "medium")
    elif d1_sharepoint_sharing == "YES" or _is_not_sure(d1_sharepoint_sharing):
        data += 15
        _add_failed(failed_controls, CTRL_ANONYMOUS_SHARING, "data", "medium")

    # G5 - Independent backups should exist.
    g5_reasons: List[str] = []
    if d2_m365_backups != "YES":
        g5_reasons.append("No independent Microsoft 365 backups are in place.")
        _add_failed(failed_controls, CTRL_BACKUPS, "data", "high")
        data += 20
    all_gates.append(_gate("G5", g5_reasons))

    # G4 - Audit logging should be enabled.
    g4_reasons: List[str] = []
    if e1_audit_logging != "YES":
        g4_reasons.append("Audit logging is not enabled or unknown.")
        _add_failed(failed_controls, CTRL_AUDIT_LOGGING, "operations", "high")
        operations += 15
    all_gates.append(_gate("G4", g4_reasons))

    if e2_device_compliance == "PARTIAL":
        operations += 5
        _add_failed(failed_controls, CTRL_DEVICE_COMPLIANCE, "devices", "medium")
    elif e2_device_compliance == "NO" or _is_not_sure(e2_device_compliance):
        operations += 10
        _add_failed(failed_controls, CTRL_DEVICE_COMPLIANCE, "devices", "medium")

    all_gates = sorted(all_gates, key=lambda gate: gate.gate_id)

    cap = 100
    for gate in all_gates:
        if gate.failed:
            cap = min(cap, gate.cap)

    total_deductions = identity + email + data + operations
    raw_score = max(0, 100 - total_deductions)
    final_score = min(raw_score, cap)
    triggered_gates = [gate for gate in all_gates if gate.failed]
    risk_level = risk_level_from_findings(
        failed_control_count=len(failed_controls),
        triggered_gate_count=len(triggered_gates),
    )

    return ScoreBreakdown(
        raw_score=raw_score,
        cap_applied=cap,
        final_score=final_score,
        grade=grade_from_score(final_score),
        gates=triggered_gates,
        deductions={
            "identity": identity,
            "email": email,
            "data": data,
            "operations": operations,
            "total": total_deductions,
        },
        failed_controls=failed_controls,
        risk_level=risk_level,
        notes=notes,
    )


def score_assessment_dict(answers: Dict[str, str]) -> Dict[str, Any]:
    return asdict(score_assessment(answers))
