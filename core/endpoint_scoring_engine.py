from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


DEVICE_MULTIPLIER = {
    "LT_25": 1.0,
    "R_25_100": 1.1,
    "R_100_300": 1.25,
    "R_300_1000": 1.5,
}

GATE_CAPS = {
    "G1": 40,
    "G2": 50,
    "G3": 55,
    "G4": 65,
    "G5": 70,
}


CTRL_AV_EDR_MISSING = "CTRL_ENDPOINT_AV_EDR_MISSING"
CTRL_REALTIME_PROTECTION = "CTRL_ENDPOINT_REALTIME_PROTECTION_DISABLED"
CTRL_CENTRAL_VISIBILITY = "CTRL_ENDPOINT_CENTRAL_VISIBILITY_MISSING"
CTRL_PATCH_MANAGEMENT = "CTRL_ENDPOINT_PATCH_MANAGEMENT_MISSING"
CTRL_THIRD_PARTY_PATCHING = "CTRL_ENDPOINT_THIRD_PARTY_PATCHING_MISSING"
CTRL_PATCH_CADENCE = "CTRL_ENDPOINT_PATCH_CADENCE_WEAK"
CTRL_DISK_ENCRYPTION = "CTRL_ENDPOINT_DISK_ENCRYPTION_MISSING"
CTRL_RECOVERY_KEYS = "CTRL_ENDPOINT_RECOVERY_KEYS_UNMANAGED"
CTRL_LOCAL_ADMIN = "CTRL_ENDPOINT_LOCAL_ADMIN_BROAD"
CTRL_ADMIN_RIGHTS_CONTROL = "CTRL_ENDPOINT_ADMIN_RIGHTS_CONTROL_WEAK"
CTRL_USER_INSTALLS = "CTRL_ENDPOINT_USER_INSTALLS_UNRESTRICTED"
CTRL_APPLICATION_RESTRICTIONS = "CTRL_ENDPOINT_APPLICATION_RESTRICTIONS_MISSING"
CTRL_USB_CONTROL = "CTRL_ENDPOINT_USB_CONTROL_MISSING"
CTRL_REMOVABLE_MEDIA_ENCRYPTION = "CTRL_ENDPOINT_REMOVABLE_MEDIA_ENCRYPTION_MISSING"
CTRL_BACKUP = "CTRL_ENDPOINT_BACKUP_MISSING"
CTRL_RESTORE_TESTING = "CTRL_ENDPOINT_RESTORE_NOT_TESTED"


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
    deductions: Dict[str, int]
    failed_controls: List[Dict[str, str]]
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
    failed_controls: List[Dict[str, str]],
    control_id: str,
    category: str,
    severity: str,
) -> None:
    if not any(control.get("id") == control_id for control in failed_controls):
        failed_controls.append(
            {"id": control_id, "category": category, "severity": severity}
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


def _includes_macos(os_mix: Optional[str]) -> bool:
    return os_mix in ("MACOS", "MIXED") or _is_not_sure(os_mix)


def _byod_in_scope(byod: Optional[str]) -> bool:
    return byod == "YES" or _is_not_sure(byod)


def score_assessment(answers: Dict[str, str]) -> ScoreBreakdown:
    notes: List[str] = []
    failed_controls: List[Dict[str, str]] = []

    endpoint_count = answers.get("A1_ENDPOINT_COUNT", "R_25_100")
    os_mix = answers.get("A2_OS_MIX")
    byod = answers.get("A3_BYOD")
    device_management = answers.get("A4_DEVICE_MANAGEMENT")
    if endpoint_count in DEVICE_MULTIPLIER:
        multiplier = DEVICE_MULTIPLIER[endpoint_count]
    else:
        multiplier = 1.1
        notes.append("Endpoint count unknown; default multiplier applied (1.1x).")

    if endpoint_count == "R_300_1000":
        notes.append(
            "Larger endpoint estates benefit from centralized management, clear ownership, and regular compliance review."
        )
    if _includes_macos(os_mix):
        notes.append("macOS endpoints are in scope or unknown; encryption and patch coverage should include macOS controls.")
    if _byod_in_scope(byod):
        notes.append("BYOD is in scope or unknown; personal devices may require clearer access and data protection rules.")
    if device_management in ("PARTIAL", "UNMANAGED", "NOT_SURE", None):
        notes.append("Partially managed or unmanaged devices reduce visibility and make consistent control enforcement harder.")

    b1_av_coverage = answers.get("B1_AV_COVERAGE")
    b2_realtime = answers.get("B2_REALTIME_PROTECTION")
    b3_visibility = answers.get("B3_CENTRAL_VISIBILITY")
    c1_os_patching = answers.get("C1_OS_PATCHING")
    c2_third_party = answers.get("C2_THIRD_PARTY_PATCHING")
    c3_cadence = answers.get("C3_PATCH_CADENCE")
    d1_encryption = answers.get("D1_DISK_ENCRYPTION")
    d2_recovery_keys = answers.get("D2_RECOVERY_KEY_STORAGE")
    e1_local_admin = answers.get("E1_LOCAL_ADMIN_RIGHTS")
    e2_admin_control = answers.get("E2_ADMIN_RIGHTS_CONTROL")
    f1_user_installs = answers.get("F1_USER_INSTALLS")
    f2_app_restrictions = answers.get("F2_APPLICATION_RESTRICTIONS")
    g1_usb_control = answers.get("G1_USB_CONTROL")
    g2_media_encryption = answers.get("G2_REMOVABLE_MEDIA_ENCRYPTION")
    h1_backup = answers.get("H1_ENDPOINT_BACKUP")
    h2_restore = answers.get("H2_RESTORE_TESTING")

    antivirus_edr = 0
    patch_management = 0
    local_admin = 0
    encryption = 0
    application_control = 0
    removable_media = 0
    endpoint_backup = 0

    g1_reasons: List[str] = []
    if b1_av_coverage == "MOST":
        antivirus_edr += 10
        _add_failed(failed_controls, CTRL_AV_EDR_MISSING, "antivirus_edr", "medium")
    elif b1_av_coverage == "SOME":
        antivirus_edr += 20
        _add_failed(failed_controls, CTRL_AV_EDR_MISSING, "antivirus_edr", "high")
    elif b1_av_coverage == "NONE" or _is_not_sure(b1_av_coverage):
        g1_reasons.append("No AV/EDR coverage exists or coverage is unknown.")
        antivirus_edr += 30
        _add_failed(failed_controls, CTRL_AV_EDR_MISSING, "antivirus_edr", "high")

    if b2_realtime == "PARTIAL":
        antivirus_edr += 7
        _add_failed(failed_controls, CTRL_REALTIME_PROTECTION, "antivirus_edr", "medium")
    elif b2_realtime == "NO" or _is_not_sure(b2_realtime):
        antivirus_edr += 15
        _add_failed(failed_controls, CTRL_REALTIME_PROTECTION, "antivirus_edr", "high")

    if b3_visibility == "PARTIAL":
        antivirus_edr += 5
        _add_failed(failed_controls, CTRL_CENTRAL_VISIBILITY, "antivirus_edr", "medium")
    elif b3_visibility == "NO" or _is_not_sure(b3_visibility):
        antivirus_edr += 10
        _add_failed(failed_controls, CTRL_CENTRAL_VISIBILITY, "antivirus_edr", "medium")

    g4_reasons: List[str] = []
    if c1_os_patching == "PARTIAL":
        patch_management += 7
        _add_failed(failed_controls, CTRL_PATCH_MANAGEMENT, "patch_management", "medium")
    elif c1_os_patching == "NO" or _is_not_sure(c1_os_patching):
        g4_reasons.append("No patch management process exists or status is unknown.")
        patch_management += 15
        _add_failed(failed_controls, CTRL_PATCH_MANAGEMENT, "patch_management", "high")

    if c2_third_party == "PARTIAL":
        patch_management += 5
        _add_failed(failed_controls, CTRL_THIRD_PARTY_PATCHING, "patch_management", "medium")
    elif c2_third_party == "NO" or _is_not_sure(c2_third_party):
        patch_management += 10
        _add_failed(failed_controls, CTRL_THIRD_PARTY_PATCHING, "patch_management", "medium")

    if c3_cadence == "OCCASIONAL":
        patch_management += 7
        _add_failed(failed_controls, CTRL_PATCH_CADENCE, "patch_management", "medium")
    elif c3_cadence == "RARE" or _is_not_sure(c3_cadence):
        patch_management += 15
        _add_failed(failed_controls, CTRL_PATCH_CADENCE, "patch_management", "high")

    g2_reasons: List[str] = []
    if e1_local_admin == "LIMITED":
        local_admin += 8
        _add_failed(failed_controls, CTRL_LOCAL_ADMIN, "local_admin", "medium")
    elif e1_local_admin == "ALL_USERS" or _is_not_sure(e1_local_admin):
        g2_reasons.append("Local administrator rights are widely allowed or status is unknown.")
        local_admin += 20
        _add_failed(failed_controls, CTRL_LOCAL_ADMIN, "local_admin", "high")

    if e2_admin_control == "PARTIAL":
        local_admin += 5
        _add_failed(failed_controls, CTRL_ADMIN_RIGHTS_CONTROL, "local_admin", "medium")
    elif e2_admin_control == "NO" or _is_not_sure(e2_admin_control):
        local_admin += 10
        _add_failed(failed_controls, CTRL_ADMIN_RIGHTS_CONTROL, "local_admin", "medium")

    g3_reasons: List[str] = []
    if d1_encryption == "PARTIAL":
        encryption += 12
        _add_failed(failed_controls, CTRL_DISK_ENCRYPTION, "encryption", "medium")
    elif d1_encryption == "NONE" or _is_not_sure(d1_encryption):
        g3_reasons.append("Disk encryption is not enabled or status is unknown.")
        encryption += 20
        _add_failed(failed_controls, CTRL_DISK_ENCRYPTION, "encryption", "high")

    if d2_recovery_keys == "PARTIAL":
        encryption += 4
        _add_failed(failed_controls, CTRL_RECOVERY_KEYS, "encryption", "medium")
    elif d2_recovery_keys == "NO" or _is_not_sure(d2_recovery_keys):
        encryption += 8
        _add_failed(failed_controls, CTRL_RECOVERY_KEYS, "encryption", "medium")

    if f1_user_installs == "LIMITED":
        application_control += 4
        _add_failed(failed_controls, CTRL_USER_INSTALLS, "application_control", "medium")
    elif f1_user_installs == "YES" or _is_not_sure(f1_user_installs):
        application_control += 10
        _add_failed(failed_controls, CTRL_USER_INSTALLS, "application_control", "medium")

    if f2_app_restrictions == "PARTIAL":
        application_control += 5
        _add_failed(failed_controls, CTRL_APPLICATION_RESTRICTIONS, "application_control", "medium")
    elif f2_app_restrictions == "NO" or _is_not_sure(f2_app_restrictions):
        application_control += 10
        _add_failed(failed_controls, CTRL_APPLICATION_RESTRICTIONS, "application_control", "medium")

    if g1_usb_control == "PARTIAL":
        removable_media += 4
        _add_failed(failed_controls, CTRL_USB_CONTROL, "removable_media", "medium")
    elif g1_usb_control == "NO" or _is_not_sure(g1_usb_control):
        removable_media += 8
        _add_failed(failed_controls, CTRL_USB_CONTROL, "removable_media", "medium")

    if g2_media_encryption == "PARTIAL":
        removable_media += 3
        _add_failed(
            failed_controls,
            CTRL_REMOVABLE_MEDIA_ENCRYPTION,
            "removable_media",
            "low",
        )
    elif g2_media_encryption == "NO" or _is_not_sure(g2_media_encryption):
        removable_media += 6
        _add_failed(
            failed_controls,
            CTRL_REMOVABLE_MEDIA_ENCRYPTION,
            "removable_media",
            "medium",
        )

    g5_reasons: List[str] = []
    if h1_backup == "PARTIAL":
        endpoint_backup += 6
        _add_failed(failed_controls, CTRL_BACKUP, "endpoint_backup", "medium")
    elif h1_backup == "NO" or _is_not_sure(h1_backup):
        g5_reasons.append("Endpoint backup is not in place or status is unknown.")
        endpoint_backup += 12
        _add_failed(failed_controls, CTRL_BACKUP, "endpoint_backup", "high")

    if h2_restore == "NO" or _is_not_sure(h2_restore):
        endpoint_backup += 5
        _add_failed(failed_controls, CTRL_RESTORE_TESTING, "endpoint_backup", "low")

    patch_management_scaled = int(round(patch_management * multiplier))
    local_admin_scaled = int(round(local_admin * multiplier))
    total_deductions = (
        antivirus_edr
        + patch_management_scaled
        + local_admin_scaled
        + encryption
        + application_control
        + removable_media
        + endpoint_backup
    )

    all_gates = [
        _gate("G1", g1_reasons),
        _gate("G2", g2_reasons),
        _gate("G3", g3_reasons),
        _gate("G4", g4_reasons),
        _gate("G5", g5_reasons),
    ]
    cap = 100
    for gate in all_gates:
        if gate.failed:
            cap = min(cap, gate.cap)

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
        device_multiplier=multiplier,
        gates=triggered_gates,
        deductions={
            "antivirus_edr": antivirus_edr,
            "patch_management": patch_management,
            "patch_management_scaled": patch_management_scaled,
            "local_admin": local_admin,
            "local_admin_scaled": local_admin_scaled,
            "encryption": encryption,
            "application_control": application_control,
            "removable_media": removable_media,
            "endpoint_backup": endpoint_backup,
            "total": total_deductions,
        },
        failed_controls=failed_controls,
        risk_level=risk_level,
        notes=notes,
    )


def score_assessment_dict(answers: Dict[str, str]) -> Dict[str, Any]:
    return asdict(score_assessment(answers))
