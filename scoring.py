from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional


# -----------------------------
# Grading bands (LOCKED)
# -----------------------------
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


# -----------------------------
# Device multiplier (LOCKED buckets)
# NOTE (v1 refinement): multiplier applied ONLY to segmentation deductions.
# -----------------------------
DEVICE_MULTIPLIER = {
    "LT_50": 1.0,
    "R_50_200": 1.1,
    "R_200_500": 1.25,
    "R_500_1000": 1.5,
}


# -----------------------------
# Gate caps (LOCKED)
# -----------------------------
GATE_CAPS = {
    "G1": 40,  # Internet Exposure
    "G2": 50,  # Guest Isolation
    "G3": 55,  # No Segmentation / Flat Network
    "G4": 65,  # No Configuration Backups
    "G5": 70,  # No Logging / Visibility
}


# These are the scored questions required for a complete assessment.
# Missing values are treated as NOT_SURE (fail), and we also emit a note.
REQUIRED_SCORED_QIDS = [
    "C1_WAN_ADMIN_EXPOSURE",
    "C2_REMOTE_ACCESS_METHOD",
    "C3_ADMIN_MFA",
    "D1_GUEST_INTERNAL_ACCESS",
    "D2_VLAN_SEPARATION",
    "D3_IOT_WITH_FINANCE",
    "E1_CORP_WIFI_SECURITY",
    "E2_GUEST_CLIENT_ISOLATION",
    "F1_UNUSED_PORTS_RESTRICTED",
    "F2_CONFIG_BACKUPS",
    "F3_LOGGING_EXISTS",
    "F4_FIRMWARE_UPDATES",
]


@dataclass
class GateResult:
    gate_id: str
    failed: bool
    cap: int
    reasons: List[str]


@dataclass
class ScoreBreakdown:
    raw_score: int
    cap_applied: int
    final_score: int
    grade: str

    device_multiplier: float
    gates: List[GateResult]

    # Deductions breakdown
    deductions: Dict[str, int]  # includes totals + segmentation_scaled
    failed_controls: List[str]
    notes: List[str]


def _is_not_sure(value: Optional[str]) -> bool:
    return value == "NOT_SURE" or value is None


def _missing_required_scored_answers(answers: Dict[str, str]) -> List[str]:
    missing = []
    for qid in REQUIRED_SCORED_QIDS:
        if qid not in answers or answers.get(qid) is None:
            missing.append(qid)
    return missing


def score_assessment(answers: Dict[str, str]) -> ScoreBreakdown:
    """
    answers: dict of question_id -> option_key
    """
    notes: List[str] = []
    failed_controls: List[str] = []

    # -----------------------------
    # Missing answer handling (transparent)
    # -----------------------------
    missing = _missing_required_scored_answers(answers)
    if missing:
        notes.append(
            "Some scored questions were not answered; missing/unknown responses are treated as failing controls: "
            + ", ".join(missing)
        )

    # -----------------------------
    # Device multiplier
    # -----------------------------
    device_bucket = answers.get("A1_DEVICE_COUNT", "R_50_200")
    multiplier = DEVICE_MULTIPLIER.get(device_bucket, 1.1)
    if device_bucket not in DEVICE_MULTIPLIER:
        notes.append("Unknown device bucket; default multiplier applied (1.1x).")

    # -----------------------------
    # Gate evaluation (LOCKED logic)
    # -----------------------------
    gates: List[GateResult] = []

    # Gate G1: Internet Exposure
    g1_reasons: List[str] = []
    c1 = answers.get("C1_WAN_ADMIN_EXPOSURE")
    c2 = answers.get("C2_REMOTE_ACCESS_METHOD")
    # C3 (MFA) is a deduction, not a gate failure.
    if c1 in ("YES",) or _is_not_sure(c1):
        g1_reasons.append("Admin interface reachable from internet (or unknown).")
    if c2 == "PORT_FORWARDING":
        g1_reasons.append("Remote access uses port forwarding/exposed services.")
    g1_failed = len(g1_reasons) > 0
    gates.append(GateResult("G1", g1_failed, GATE_CAPS["G1"], g1_reasons))

    # Gate G2: Guest Isolation
    g2_reasons: List[str] = []
    d1 = answers.get("D1_GUEST_INTERNAL_ACCESS")
    if d1 == "YES" or _is_not_sure(d1):
        g2_reasons.append("Guest devices can access internal systems (or unknown).")
    g2_failed = len(g2_reasons) > 0
    gates.append(GateResult("G2", g2_failed, GATE_CAPS["G2"], g2_reasons))

    # Gate G3: No Segmentation / Flat Network
    g3_reasons: List[str] = []
    d2 = answers.get("D2_VLAN_SEPARATION")
    if d2 == "FLAT" or _is_not_sure(d2):
        g3_reasons.append("Network is flat / not segmented (or unknown).")
    g3_failed = len(g3_reasons) > 0
    gates.append(GateResult("G3", g3_failed, GATE_CAPS["G3"], g3_reasons))

    # Gate G4: No Configuration Backups
    g4_reasons: List[str] = []
    f2 = answers.get("F2_CONFIG_BACKUPS")
    if f2 == "NONE" or _is_not_sure(f2):
        g4_reasons.append("No configuration backups (or unknown).")
    g4_failed = len(g4_reasons) > 0
    gates.append(GateResult("G4", g4_failed, GATE_CAPS["G4"], g4_reasons))

    # Gate G5: No Logging / Visibility
    g5_reasons: List[str] = []
    f3 = answers.get("F3_LOGGING_EXISTS")
    if f3 == "NO" or _is_not_sure(f3):
        g5_reasons.append("No network/firewall logging (or unknown).")
    g5_failed = len(g5_reasons) > 0
    gates.append(GateResult("G5", g5_failed, GATE_CAPS["G5"], g5_reasons))

    # Determine cap
    cap = 100
    for g in gates:
        if g.failed:
            cap = min(cap, g.cap)

    # -----------------------------
    # Deductions (LOCKED weights)
    # Refinement: multiplier applies ONLY to segmentation deductions.
    # -----------------------------
    # Perimeter (NOT multiplied)
    perimeter_ded = 0

    # Admin interface exposed: -25 (YES or NOT_SURE)
    if c1 == "YES" or _is_not_sure(c1):
        perimeter_ded += 25
        failed_controls.append("CTRL_PERIMETER_WAN_ADMIN_EXPOSURE")

    # Port forwarding: -25
    if c2 == "PORT_FORWARDING":
        perimeter_ded += 25
        failed_controls.append("CTRL_PERIMETER_PORT_FORWARDING")

    # No admin MFA: -10 (NO or NOT_SURE)
    c3 = answers.get("C3_ADMIN_MFA")
    if c3 == "NO" or _is_not_sure(c3):
        perimeter_ded += 10
        failed_controls.append("CTRL_IDENTITY_ADMIN_MFA")

    # Segmentation (MULTIPLIED)
    segmentation_ded = 0

    # VLAN separation:
    #   FLAT/UNKNOWN: -25
    #   PARTIAL: -10
    if d2 == "FLAT" or _is_not_sure(d2):
        segmentation_ded += 25
        failed_controls.append("CTRL_SEGMENTATION_FLAT_NETWORK")
    elif d2 == "PARTIAL":
        segmentation_ded += 10
        failed_controls.append("CTRL_SEGMENTATION_PARTIAL")

    # Guest isolation is a gate; include for intent blocks (no extra deduction)
    if d1 == "YES" or _is_not_sure(d1):
        failed_controls.append("CTRL_SEGMENTATION_GUEST_NOT_ISOLATED")

    # IoT with critical: -10 (YES)
    d3 = answers.get("D3_IOT_WITH_FINANCE")
    if d3 == "YES":
        segmentation_ded += 10
        failed_controls.append("CTRL_SEGMENTATION_IOT_WITH_CRITICAL")

    # Wireless (NOT multiplied)
    wireless_ded = 0
    e1 = answers.get("E1_CORP_WIFI_SECURITY")

    if e1 == "OPEN_OR_UNKNOWN" or _is_not_sure(e1):
        wireless_ded += 15
        failed_controls.append("CTRL_WIRELESS_OPEN_OR_UNKNOWN")
    elif e1 == "PSK":
        wireless_ded += 7
        failed_controls.append("CTRL_WIRELESS_PSK_ONLY")

    e2 = answers.get("E2_GUEST_CLIENT_ISOLATION")
    if e2 == "NO" or _is_not_sure(e2):
        wireless_ded += 8
        failed_controls.append("CTRL_WIRELESS_GUEST_CLIENT_ISOLATION")

    # Hygiene & Ops (NOT multiplied)
    hygiene_ded = 0

    f1 = answers.get("F1_UNUSED_PORTS_RESTRICTED")
    if f1 == "NO" or _is_not_sure(f1):
        hygiene_ded += 7
        failed_controls.append("CTRL_HYGIENE_UNUSED_PORTS")

    # Backups: -15 (NONE or NOT_SURE)
    if f2 == "NONE" or _is_not_sure(f2):
        hygiene_ded += 15
        failed_controls.append("CTRL_OPERATIONS_NO_BACKUPS")

    # Logging: -15 (NO or NOT_SURE)
    if f3 == "NO" or _is_not_sure(f3):
        hygiene_ded += 15
        failed_controls.append("CTRL_OPERATIONS_NO_LOGGING")

    # Firmware: -7 if RARE or NOT_SURE
    f4 = answers.get("F4_FIRMWARE_UPDATES")
    if f4 == "RARE" or _is_not_sure(f4):
        hygiene_ded += 7
        failed_controls.append("CTRL_OPERATIONS_FIRMWARE_RARE")

    # Apply multiplier ONLY to segmentation deductions
    segmentation_scaled = int(round(segmentation_ded * multiplier))

    # For backward compatibility with report_builder:
    # - multiplied_total = segmentation_scaled + wireless + hygiene (only seg is scaled)
    multiplied_total = segmentation_scaled + wireless_ded + hygiene_ded

    total_deductions = perimeter_ded + multiplied_total

    raw_score = 100 - total_deductions
    if raw_score < 0:
        raw_score = 0
    if raw_score > 100:
        raw_score = 100

    final_score = min(raw_score, cap)
    grade = grade_from_score(final_score)

    # Deduplicate failed_controls while preserving order
    seen = set()
    failed_controls_dedup = []
    for cid in failed_controls:
        if cid not in seen:
            seen.add(cid)
            failed_controls_dedup.append(cid)

    return ScoreBreakdown(
        raw_score=raw_score,
        cap_applied=cap,
        final_score=final_score,
        grade=grade,
        device_multiplier=multiplier,
        gates=gates,
        deductions={
            "perimeter": perimeter_ded,
            "segmentation": segmentation_ded,          # raw
            "segmentation_scaled": segmentation_scaled,
            "wireless": wireless_ded,
            "hygiene": hygiene_ded,
            "multiplied_total": multiplied_total,      # scaled seg + wifi + hygiene
            "total": total_deductions,
        },
        failed_controls=failed_controls_dedup,
        notes=notes,
    )


def score_assessment_dict(answers: Dict[str, str]) -> Dict[str, Any]:
    """Convenience for JSON serialization."""
    result = score_assessment(answers)
    data = asdict(result)
    data["gates"] = [asdict(g) for g in result.gates]
    return data
