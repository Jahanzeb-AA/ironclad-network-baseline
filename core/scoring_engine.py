from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


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


DEVICE_MULTIPLIER = {
    "U_1_25": 1.0,
    "U_26_100": 1.1,
    "U_101_300": 1.25,
    "U_301_1000": 1.5,
    "U_1000_PLUS": 1.75,
    # Backward-compatible aliases from earlier scoring drafts.
    "LT_50": 1.0,
    "R_50_200": 1.1,
    "R_200_500": 1.25,
    "R_500_1000": 1.5,
}


GATE_CAPS = {
    "G1": 40,
    "G2": 50,
    "G3": 55,
    "G4": 65,
    "G5": 70,
}


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
    device_multiplier: float
    gates: List[GateResult]
    deductions: Dict[str, int]
    failed_controls: List[FailedControl]
    risk_level: str
    notes: List[str]


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


def score_assessment(answers: Dict[str, str]) -> ScoreBreakdown:
    notes: List[str] = []
    failed_controls: List[FailedControl] = []
    gates: List[GateResult] = []

    device_bucket = answers.get("A1_DEVICE_COUNT", "U_26_100")
    multiplier = DEVICE_MULTIPLIER.get(device_bucket, 1.1)

    c1 = answers.get("C1_WAN_ADMIN_EXPOSURE")
    c2 = answers.get("C2_REMOTE_ACCESS_METHOD")
    c3 = answers.get("C3_ADMIN_MFA")
    d1 = answers.get("D1_GUEST_INTERNAL_ACCESS")
    d2 = answers.get("D2_VLAN_SEPARATION")
    d3 = answers.get("D3_IOT_WITH_FINANCE")
    e1 = answers.get("E1_CORP_WIFI_SECURITY")
    e2 = answers.get("E2_GUEST_CLIENT_ISOLATION")
    f1 = answers.get("F1_UNUSED_PORTS_RESTRICTED")
    f2 = answers.get("F2_CONFIG_BACKUPS")
    f3 = answers.get("F3_LOGGING_EXISTS")
    f4 = answers.get("F4_FIRMWARE_UPDATES")
    f5 = answers.get("F5_DEFAULT_CREDENTIALS")

    has_local_resources = answers.get("B2_LOCAL_RESOURCES") == "LOCAL_REQUIRED"
    is_flat = d2 == "FLAT" or _is_not_sure(d2)

    if is_flat and has_local_resources:
        notes.append("High risk: internal resources exist on a flat network.")

    if answers.get("G3_SENSITIVE_DATA") == "YES":
        notes.append(
            "This environment processes sensitive data. Security gaps may affect regulatory or contractual obligations."
        )

    g1_reasons = []
    if c1 == "YES" or _is_not_sure(c1):
        g1_reasons.append("Admin interface exposed to the internet or unknown.")
    if c2 == "PORT_FORWARDING" or _is_not_sure(c2):
        g1_reasons.append("Unsafe or unknown remote access method.")
    gates.append(GateResult("G1", bool(g1_reasons), GATE_CAPS["G1"], g1_reasons))

    g2_reasons = []
    if d1 == "YES" or _is_not_sure(d1):
        g2_reasons.append("Guest network can access internal systems or status is unknown.")
    gates.append(GateResult("G2", bool(g2_reasons), GATE_CAPS["G2"], g2_reasons))

    g3_reasons = []
    if is_flat:
        g3_reasons.append("Network is flat or segmentation status is unknown.")
    gates.append(GateResult("G3", bool(g3_reasons), GATE_CAPS["G3"], g3_reasons))

    g4_reasons = []
    if f2 == "NONE" or _is_not_sure(f2):
        g4_reasons.append("No configuration backups or backup status is unknown.")
    gates.append(GateResult("G4", bool(g4_reasons), GATE_CAPS["G4"], g4_reasons))

    g5_reasons = []
    if f3 == "NO" or _is_not_sure(f3):
        g5_reasons.append("No logging or logging status is unknown.")
    gates.append(GateResult("G5", bool(g5_reasons), GATE_CAPS["G5"], g5_reasons))

    cap = 100
    for gate in gates:
        if gate.failed:
            cap = min(cap, gate.cap)

    perimeter = 0
    segmentation = 0
    wireless = 0
    hygiene = 0

    if c1 == "YES" or _is_not_sure(c1):
        perimeter += 25
        _add_failed(
            failed_controls,
            "CTRL_PERIMETER_WAN_ADMIN_EXPOSURE",
            "perimeter",
            "high",
        )

    if c2 == "PORT_FORWARDING" or _is_not_sure(c2):
        perimeter += 25
        _add_failed(
            failed_controls,
            "CTRL_PERIMETER_PORT_FORWARDING",
            "perimeter",
            "high",
        )

    if c3 in ("NO", None, "NOT_SURE"):
        perimeter += 10
        _add_failed(failed_controls, "CTRL_IDENTITY_ADMIN_MFA", "identity", "high")

    if is_flat:
        segmentation += 25
        _add_failed(
            failed_controls,
            "CTRL_SEGMENTATION_FLAT_NETWORK",
            "segmentation",
            "high",
        )
    elif d2 == "PARTIAL":
        segmentation += 10
        _add_failed(
            failed_controls,
            "CTRL_SEGMENTATION_PARTIAL",
            "segmentation",
            "medium",
        )

    if d1 == "YES" or _is_not_sure(d1):
        _add_failed(
            failed_controls,
            "CTRL_SEGMENTATION_GUEST_NOT_ISOLATED",
            "segmentation",
            "high",
        )

    if d3 == "YES" or _is_not_sure(d3):
        segmentation += 10
        _add_failed(
            failed_controls,
            "CTRL_SEGMENTATION_IOT_WITH_CRITICAL",
            "segmentation",
            "medium",
        )

    if e1 == "OPEN_OR_UNKNOWN" or _is_not_sure(e1):
        wireless += 15
        _add_failed(
            failed_controls,
            "CTRL_WIRELESS_OPEN_OR_UNKNOWN",
            "wireless",
            "high",
        )
    elif e1 == "PSK":
        wireless += 7
        _add_failed(failed_controls, "CTRL_WIRELESS_PSK_ONLY", "wireless", "medium")

    if e2 in ("NO", None, "NOT_SURE"):
        wireless += 8
        _add_failed(
            failed_controls,
            "CTRL_WIRELESS_GUEST_CLIENT_ISOLATION",
            "wireless",
            "medium",
        )

    if f1 in ("NO", None, "NOT_SURE"):
        hygiene += 7
        _add_failed(failed_controls, "CTRL_HYGIENE_UNUSED_PORTS", "hygiene", "medium")

    if f2 == "NONE" or _is_not_sure(f2):
        hygiene += 15
        _add_failed(failed_controls, "CTRL_OPERATIONS_NO_BACKUPS", "operations", "high")

    if f3 == "NO" or _is_not_sure(f3):
        hygiene += 15
        _add_failed(failed_controls, "CTRL_OPERATIONS_NO_LOGGING", "operations", "high")

    if f4 in ("RARE", None, "NOT_SURE"):
        hygiene += 7
        _add_failed(
            failed_controls,
            "CTRL_OPERATIONS_FIRMWARE_RARE",
            "operations",
            "medium",
        )

    if f5 in ("NO", None, "NOT_SURE"):
        hygiene += 10
        _add_failed(
            failed_controls,
            "CTRL_HYGIENE_DEFAULT_CREDENTIALS",
            "hygiene",
            "high",
        )

    segmentation_scaled = int(round(segmentation * multiplier))
    total = perimeter + segmentation_scaled + wireless + hygiene
    raw_score = max(0, 100 - total)
    final_score = min(raw_score, cap)
    triggered_gates = [gate for gate in gates if gate.failed]
    risk_level = risk_level_from_findings(
        failed_control_count=len(failed_controls),
        triggered_gate_count=len(triggered_gates),
    )

    return ScoreBreakdown(
        raw_score=raw_score,
        cap_applied=cap,
        final_score=final_score,
        grade=grade_from_score(final_score),
        device_multiplier=multiplier,
        gates=triggered_gates,
        deductions={
            "perimeter": perimeter,
            "segmentation": segmentation,
            "segmentation_scaled": segmentation_scaled,
            "wireless": wireless,
            "hygiene": hygiene,
            "total": total,
            "multiplied_total": total,
        },
        failed_controls=failed_controls,
        risk_level=risk_level,
        notes=notes,
    )


def score_assessment_dict(answers: Dict[str, str]) -> Dict[str, Any]:
    return asdict(score_assessment(answers))
