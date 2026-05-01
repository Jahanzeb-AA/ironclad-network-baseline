from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


GATE_CAPS = {
    "G1": 45,  # No managed endpoint protection
    "G2": 55,  # Endpoint patching not controlled
    "G3": 60,  # Excessive local administrator access
    "G4": 70,  # No endpoint alert review
}


CTRL_ENDPOINT_PROTECTION = "CTRL_ENDPOINT_PROTECTION_NOT_MANAGED"
CTRL_DISK_ENCRYPTION = "CTRL_ENDPOINT_DISK_ENCRYPTION_MISSING"
CTRL_HOST_FIREWALL = "CTRL_ENDPOINT_HOST_FIREWALL_DISABLED"
CTRL_OS_PATCHING = "CTRL_ENDPOINT_OS_PATCHING_WEAK"
CTRL_THIRD_PARTY_PATCHING = "CTRL_ENDPOINT_THIRD_PARTY_PATCHING_WEAK"
CTRL_UNSUPPORTED_OS = "CTRL_ENDPOINT_UNSUPPORTED_OS"
CTRL_LOCAL_ADMIN = "CTRL_ENDPOINT_LOCAL_ADMIN_EXCESSIVE"
CTRL_SCREEN_LOCK = "CTRL_ENDPOINT_SCREEN_LOCK_WEAK"
CTRL_REMOTE_ACCESS_MFA = "CTRL_ENDPOINT_REMOTE_ACCESS_MFA_MISSING"
CTRL_ALERT_REVIEW = "CTRL_ENDPOINT_ALERT_REVIEW_MISSING"
CTRL_INVENTORY = "CTRL_ENDPOINT_INVENTORY_INCOMPLETE"
CTRL_BACKUP = "CTRL_ENDPOINT_BACKUP_INCOMPLETE"
CTRL_RESTORE_TESTING = "CTRL_ENDPOINT_RESTORE_NOT_TESTED"


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


def _gate(gate_id: str, reasons: List[str]) -> GateResult:
    return GateResult(
        gate_id=gate_id,
        failed=bool(reasons),
        cap=GATE_CAPS[gate_id],
        reasons=reasons,
    )


def risk_level_from_findings(failed_control_count: int, triggered_gate_count: int) -> str:
    if triggered_gate_count >= 2 or failed_control_count >= 6:
        return "high"
    if triggered_gate_count == 1 or failed_control_count >= 3:
        return "medium"
    return "low"


def score_assessment(answers: Dict[str, str]) -> ScoreBreakdown:
    notes: List[str] = []
    failed_controls: List[FailedControl] = []
    all_gates: List[GateResult] = []

    if answers.get("A2_DEVICE_OWNERSHIP") in ("MIXED", "MOSTLY_BYOD", "NOT_SURE"):
        notes.append(
            "Mixed or employee-owned endpoints may need clearer enrollment, access, and data-protection rules."
        )

    b1_endpoint_protection = answers.get("B1_ENDPOINT_PROTECTION")
    b2_disk_encryption = answers.get("B2_DISK_ENCRYPTION")
    b3_firewall_enabled = answers.get("B3_FIREWALL_ENABLED")
    c1_os_patching = answers.get("C1_OS_PATCHING")
    c2_third_party_patching = answers.get("C2_THIRD_PARTY_PATCHING")
    c3_unsupported_os = answers.get("C3_UNSUPPORTED_OS")
    d1_local_admin = answers.get("D1_LOCAL_ADMIN")
    d2_screen_lock = answers.get("D2_SCREEN_LOCK")
    d3_remote_access_mfa = answers.get("D3_REMOTE_ACCESS_MFA")
    e1_security_alerts = answers.get("E1_SECURITY_ALERTS")
    e2_device_inventory = answers.get("E2_DEVICE_INVENTORY")
    f1_endpoint_backup = answers.get("F1_ENDPOINT_BACKUP")
    f2_restore_testing = answers.get("F2_RESTORE_TESTING")

    protection = 0
    patching = 0
    access = 0
    monitoring = 0
    backup = 0

    g1_reasons: List[str] = []
    if b1_endpoint_protection in ("YES_BASIC", "NO", "NOT_SURE", None):
        g1_reasons.append("Managed endpoint protection is missing, basic only, or unknown.")
        _add_failed(failed_controls, CTRL_ENDPOINT_PROTECTION, "protection", "high")
        protection += 10 if b1_endpoint_protection == "YES_BASIC" else 25
    all_gates.append(_gate("G1", g1_reasons))

    if b2_disk_encryption == "PARTIAL":
        protection += 5
        _add_failed(failed_controls, CTRL_DISK_ENCRYPTION, "protection", "medium")
    elif b2_disk_encryption == "NO" or _is_not_sure(b2_disk_encryption):
        protection += 12
        _add_failed(failed_controls, CTRL_DISK_ENCRYPTION, "protection", "medium")

    if b3_firewall_enabled == "PARTIAL":
        protection += 4
        _add_failed(failed_controls, CTRL_HOST_FIREWALL, "protection", "medium")
    elif b3_firewall_enabled == "NO" or _is_not_sure(b3_firewall_enabled):
        protection += 8
        _add_failed(failed_controls, CTRL_HOST_FIREWALL, "protection", "medium")

    g2_reasons: List[str] = []
    if c1_os_patching in ("RARE", "NOT_SURE", None):
        g2_reasons.append("Operating system patching is rare, inconsistent, or unknown.")
        _add_failed(failed_controls, CTRL_OS_PATCHING, "patching", "high")
        patching += 20
    elif c1_os_patching == "MANUAL":
        patching += 8
        _add_failed(failed_controls, CTRL_OS_PATCHING, "patching", "medium")
    all_gates.append(_gate("G2", g2_reasons))

    if c2_third_party_patching == "MANUAL":
        patching += 6
        _add_failed(
            failed_controls,
            CTRL_THIRD_PARTY_PATCHING,
            "patching",
            "medium",
        )
    elif c2_third_party_patching == "NO" or _is_not_sure(c2_third_party_patching):
        patching += 12
        _add_failed(
            failed_controls,
            CTRL_THIRD_PARTY_PATCHING,
            "patching",
            "medium",
        )

    if c3_unsupported_os == "YES_FEW":
        patching += 8
        _add_failed(failed_controls, CTRL_UNSUPPORTED_OS, "patching", "high")
    elif c3_unsupported_os == "YES_MANY" or _is_not_sure(c3_unsupported_os):
        patching += 16
        _add_failed(failed_controls, CTRL_UNSUPPORTED_OS, "patching", "high")

    g3_reasons: List[str] = []
    if d1_local_admin == "YES" or _is_not_sure(d1_local_admin):
        g3_reasons.append("Standard users have local administrator access or status is unknown.")
        _add_failed(failed_controls, CTRL_LOCAL_ADMIN, "access", "high")
        access += 18
    elif d1_local_admin == "LIMITED":
        access += 7
        _add_failed(failed_controls, CTRL_LOCAL_ADMIN, "access", "medium")
    all_gates.append(_gate("G3", g3_reasons))

    if d2_screen_lock == "PARTIAL":
        access += 4
        _add_failed(failed_controls, CTRL_SCREEN_LOCK, "access", "medium")
    elif d2_screen_lock == "NO" or _is_not_sure(d2_screen_lock):
        access += 8
        _add_failed(failed_controls, CTRL_SCREEN_LOCK, "access", "medium")

    if d3_remote_access_mfa == "PARTIAL":
        access += 6
        _add_failed(failed_controls, CTRL_REMOTE_ACCESS_MFA, "access", "medium")
    elif d3_remote_access_mfa == "NO" or _is_not_sure(d3_remote_access_mfa):
        access += 12
        _add_failed(failed_controls, CTRL_REMOTE_ACCESS_MFA, "access", "high")

    g4_reasons: List[str] = []
    if e1_security_alerts == "NO" or _is_not_sure(e1_security_alerts):
        g4_reasons.append("Endpoint security alerts are not reviewed or status is unknown.")
        _add_failed(failed_controls, CTRL_ALERT_REVIEW, "monitoring", "high")
        monitoring += 15
    elif e1_security_alerts == "PARTIAL":
        monitoring += 6
        _add_failed(failed_controls, CTRL_ALERT_REVIEW, "monitoring", "medium")
    all_gates.append(_gate("G4", g4_reasons))

    if e2_device_inventory == "PARTIAL":
        monitoring += 5
        _add_failed(failed_controls, CTRL_INVENTORY, "monitoring", "medium")
    elif e2_device_inventory == "NO" or _is_not_sure(e2_device_inventory):
        monitoring += 10
        _add_failed(failed_controls, CTRL_INVENTORY, "monitoring", "medium")

    if f1_endpoint_backup == "PARTIAL":
        backup += 6
        _add_failed(failed_controls, CTRL_BACKUP, "backup", "medium")
    elif f1_endpoint_backup == "NO" or _is_not_sure(f1_endpoint_backup):
        backup += 12
        _add_failed(failed_controls, CTRL_BACKUP, "backup", "medium")

    if f2_restore_testing == "NO" or _is_not_sure(f2_restore_testing):
        backup += 5
        _add_failed(failed_controls, CTRL_RESTORE_TESTING, "backup", "low")

    all_gates = sorted(all_gates, key=lambda gate: gate.gate_id)

    cap = 100
    for gate in all_gates:
        if gate.failed:
            cap = min(cap, gate.cap)

    total_deductions = protection + patching + access + monitoring + backup
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
            "protection": protection,
            "patching": patching,
            "access": access,
            "monitoring": monitoring,
            "backup": backup,
            "total": total_deductions,
        },
        failed_controls=failed_controls,
        risk_level=risk_level,
        notes=notes,
    )


def score_assessment_dict(answers: Dict[str, str]) -> Dict[str, Any]:
    return asdict(score_assessment(answers))
