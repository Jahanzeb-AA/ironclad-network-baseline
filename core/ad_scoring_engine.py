from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


USER_MULTIPLIER = {
    "LT_50": 1.0,
    "R_50_200": 1.1,
    "R_200_500": 1.25,
    "R_500_1000": 1.5,
}

GATE_CAPS = {
    "G1": 40,
    "G2": 50,
    "G3": 55,
    "G4": 60,
    "G5": 65,
    "G6": 70,
    "G7": 75,
}


CTRL_STALE_USERS = "CTRL_AD_STALE_USERS"
CTRL_STALE_COMPUTERS = "CTRL_AD_STALE_COMPUTERS"
CTRL_SHARED_ACCOUNTS = "CTRL_AD_SHARED_ACCOUNTS"
CTRL_GUEST_ENABLED = "CTRL_AD_GUEST_ACCOUNT_ENABLED"
CTRL_DA_COUNT = "CTRL_AD_DOMAIN_ADMIN_COUNT_HIGH"
CTRL_DA_DAILY_USE = "CTRL_AD_DOMAIN_ADMIN_DAILY_USE"
CTRL_DEFAULT_ADMIN_EXPOSED = "CTRL_AD_DEFAULT_ADMIN_EXPOSED"
CTRL_SERVICE_ACCOUNT_DA = "CTRL_AD_SERVICE_ACCOUNT_DOMAIN_ADMIN"
CTRL_PASSWORD_POLICY = "CTRL_AD_PASSWORD_POLICY_WEAK"
CTRL_ACCOUNT_LOCKOUT = "CTRL_AD_ACCOUNT_LOCKOUT_MISSING"
CTRL_PASSWORD_NEVER_EXPIRES = "CTRL_AD_PASSWORD_NEVER_EXPIRES"
CTRL_ASREP = "CTRL_AD_ASREP_ROASTING_EXPOSURE"
CTRL_WEAK_SPN = "CTRL_AD_WEAK_SPN_ACCOUNTS"
CTRL_NTLMV1 = "CTRL_AD_NTLMV1_ALLOWED"
CTRL_LAPS = "CTRL_AD_LAPS_MISSING"
CTRL_GPO_REVIEW = "CTRL_AD_GPO_REVIEW_MISSING"
CTRL_RESTRICTED_GROUPS = "CTRL_AD_RESTRICTED_GROUPS_MISSING"
CTRL_DC_EOL_OS = "CTRL_AD_DC_EOL_OS"
CTRL_DC_PATCHING = "CTRL_AD_DC_PATCHING_MISSING"
CTRL_DC_MIXED_ROLES = "CTRL_AD_DC_MIXED_ROLES"
CTRL_DC_ACCESS = "CTRL_AD_DC_ACCESS_NOT_RESTRICTED"
CTRL_AD_LOGGING = "CTRL_AD_AUDIT_LOGGING_MISSING"
CTRL_LOG_REVIEW = "CTRL_AD_LOG_REVIEW_MISSING"
CTRL_AD_BACKUP = "CTRL_AD_BACKUP_MISSING"


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
    privileged_multiplier: float
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


def _service_accounts_in_scope(value: Optional[str]) -> bool:
    return value == "YES" or _is_not_sure(value)


def score_assessment(answers: Dict[str, str]) -> ScoreBreakdown:
    notes: List[str] = []
    failed_controls: List[Dict[str, str]] = []

    domain_count = answers.get("A1_DOMAIN_COUNT")
    dc_count = answers.get("A2_DC_COUNT")
    hybrid = answers.get("A3_HYBRID")
    user_count = answers.get("A4_USER_COUNT", "R_50_200")
    service_accounts = answers.get("A5_SERVICE_ACCOUNTS")

    if user_count in USER_MULTIPLIER:
        multiplier = USER_MULTIPLIER[user_count]
    else:
        multiplier = 1.1
        notes.append("AD user count unknown; default privileged access multiplier applied (1.1x).")

    if domain_count in ("MULTIPLE", "NOT_SURE"):
        notes.append("Multiple or unknown AD domains may require broader administrative review.")
    if dc_count in ("ONE", "NOT_SURE"):
        notes.append("A single or unknown domain controller count can affect resilience planning.")
    if hybrid == "YES":
        notes.append("Hybrid AD + M365 environments should also complete the M365 baseline.")
    if _service_accounts_in_scope(service_accounts):
        notes.append("Service accounts are in scope or unknown; Kerberos and privilege controls should include them.")

    b1_stale_users = answers.get("B1_STALE_USERS")
    b2_stale_computers = answers.get("B2_STALE_COMPUTERS")
    b3_shared_accounts = answers.get("B3_SHARED_ACCOUNTS")
    b4_guest_account = answers.get("B4_GUEST_ACCOUNT")
    c1_da_count = answers.get("C1_DA_COUNT")
    c2_da_daily_use = answers.get("C2_DA_DAILY_USE")
    c3_default_admin = answers.get("C3_DEFAULT_ADMIN_EXPOSED")
    c4_service_account_da = answers.get("C4_SERVICE_ACCOUNT_DA")
    d1_password_policy = answers.get("D1_PASSWORD_POLICY")
    d2_lockout = answers.get("D2_ACCOUNT_LOCKOUT")
    d3_never_expires = answers.get("D3_PASSWORD_NEVER_EXPIRES")
    e1_asrep = answers.get("E1_ASREP_ROASTING")
    e2_weak_spn = answers.get("E2_WEAK_SPN")
    e3_ntlmv1 = answers.get("E3_NTLMV1")
    f1_laps = answers.get("F1_LAPS")
    f2_gpo_review = answers.get("F2_GPO_REVIEW")
    f3_restricted_groups = answers.get("F3_RESTRICTED_GROUPS")
    g1_dc_os = answers.get("G1_DC_OS")
    g2_dc_patching = answers.get("G2_DC_PATCHING")
    g3_mixed_roles = answers.get("G3_MIXED_ROLES")
    g4_dc_access = answers.get("G4_DC_ACCESS_RESTRICTED")
    h1_logging = answers.get("H1_AD_AUDIT_LOGGING")
    h2_log_review = answers.get("H2_LOG_REVIEW")
    h3_backup = answers.get("H3_AD_BACKUP")

    account_hygiene = 0
    privileged_access = 0
    password_policy = 0
    kerberos_auth = 0
    laps_gpo = 0
    dc_hygiene = 0
    monitoring_backup = 0

    if b1_stale_users == "YES" or _is_not_sure(b1_stale_users):
        account_hygiene += 15
        _add_failed(failed_controls, CTRL_STALE_USERS, "account_hygiene", "medium")

    if b2_stale_computers == "YES" or _is_not_sure(b2_stale_computers):
        account_hygiene += 8
        _add_failed(failed_controls, CTRL_STALE_COMPUTERS, "account_hygiene", "medium")

    if b3_shared_accounts == "YES" or _is_not_sure(b3_shared_accounts):
        account_hygiene += 10
        _add_failed(failed_controls, CTRL_SHARED_ACCOUNTS, "account_hygiene", "medium")

    if b4_guest_account == "YES" or _is_not_sure(b4_guest_account):
        account_hygiene += 7
        _add_failed(failed_controls, CTRL_GUEST_ENABLED, "account_hygiene", "low")

    g1_reasons: List[str] = []
    if c1_da_count == "R_3_5":
        privileged_access += 10
        _add_failed(failed_controls, CTRL_DA_COUNT, "privileged_access", "medium")
    elif c1_da_count == "DA_6_PLUS" or _is_not_sure(c1_da_count):
        g1_reasons.append("Domain Admin count is 6+ or unknown.")
        privileged_access += 20
        _add_failed(failed_controls, CTRL_DA_COUNT, "privileged_access", "high")

    if c2_da_daily_use == "YES" or _is_not_sure(c2_da_daily_use):
        g1_reasons.append("Domain Admin accounts are used for daily work or status is unknown.")
        privileged_access += 20
        _add_failed(failed_controls, CTRL_DA_DAILY_USE, "privileged_access", "high")

    if c3_default_admin == "YES" or _is_not_sure(c3_default_admin):
        privileged_access += 10
        _add_failed(
            failed_controls,
            CTRL_DEFAULT_ADMIN_EXPOSED,
            "privileged_access",
            "medium",
        )

    if _service_accounts_in_scope(service_accounts) and c4_service_account_da != "NA":
        if c4_service_account_da == "YES" or _is_not_sure(c4_service_account_da):
            privileged_access += 15
            _add_failed(
                failed_controls,
                CTRL_SERVICE_ACCOUNT_DA,
                "privileged_access",
                "high",
            )

    g2_reasons: List[str] = []
    if d1_password_policy == "WEAK":
        password_policy += 8
        _add_failed(failed_controls, CTRL_PASSWORD_POLICY, "password_policy", "medium")
    elif d1_password_policy == "NO" or _is_not_sure(d1_password_policy):
        g2_reasons.append("Password policy is missing or unknown.")
        password_policy += 18
        _add_failed(failed_controls, CTRL_PASSWORD_POLICY, "password_policy", "high")

    if d2_lockout == "NO" or _is_not_sure(d2_lockout):
        password_policy += 12
        _add_failed(failed_controls, CTRL_ACCOUNT_LOCKOUT, "password_policy", "medium")

    if d3_never_expires == "YES" or _is_not_sure(d3_never_expires):
        password_policy += 10
        _add_failed(
            failed_controls,
            CTRL_PASSWORD_NEVER_EXPIRES,
            "password_policy",
            "medium",
        )

    g3_reasons: List[str] = []
    if _service_accounts_in_scope(service_accounts):
        if e1_asrep == "YES" or _is_not_sure(e1_asrep):
            g3_reasons.append("AS-REP exposure exists or status is unknown for service-account scope.")
            kerberos_auth += 20
            _add_failed(failed_controls, CTRL_ASREP, "kerberos_auth", "high")

        if e2_weak_spn == "YES" or _is_not_sure(e2_weak_spn):
            kerberos_auth += 15
            _add_failed(failed_controls, CTRL_WEAK_SPN, "kerberos_auth", "high")

    if e3_ntlmv1 == "YES" or _is_not_sure(e3_ntlmv1):
        kerberos_auth += 10
        _add_failed(failed_controls, CTRL_NTLMV1, "kerberos_auth", "medium")

    g4_reasons: List[str] = []
    if f1_laps == "NO" or _is_not_sure(f1_laps):
        g4_reasons.append("LAPS is not in use or status is unknown.")
        laps_gpo += 20
        _add_failed(failed_controls, CTRL_LAPS, "laps_gpo", "high")

    if f2_gpo_review == "NO" or _is_not_sure(f2_gpo_review):
        laps_gpo += 8
        _add_failed(failed_controls, CTRL_GPO_REVIEW, "laps_gpo", "medium")

    if f3_restricted_groups == "NO" or _is_not_sure(f3_restricted_groups):
        laps_gpo += 10
        _add_failed(failed_controls, CTRL_RESTRICTED_GROUPS, "laps_gpo", "medium")

    g5_reasons: List[str] = []
    if g1_dc_os == "NO" or _is_not_sure(g1_dc_os):
        g5_reasons.append("Domain controllers are on EOL/unsupported OS or status is unknown.")
        dc_hygiene += 20
        _add_failed(failed_controls, CTRL_DC_EOL_OS, "dc_hygiene", "high")

    if g2_dc_patching == "NO" or _is_not_sure(g2_dc_patching):
        g5_reasons.append("Domain controller patching is missing or unknown.")
        dc_hygiene += 15
        _add_failed(failed_controls, CTRL_DC_PATCHING, "dc_hygiene", "high")

    if g3_mixed_roles == "YES" or _is_not_sure(g3_mixed_roles):
        dc_hygiene += 12
        _add_failed(failed_controls, CTRL_DC_MIXED_ROLES, "dc_hygiene", "medium")

    if g4_dc_access == "NO" or _is_not_sure(g4_dc_access):
        dc_hygiene += 10
        _add_failed(failed_controls, CTRL_DC_ACCESS, "dc_hygiene", "medium")

    g6_reasons: List[str] = []
    if h1_logging == "NO" or _is_not_sure(h1_logging):
        g6_reasons.append("AD audit logging is missing or unknown.")
        monitoring_backup += 15
        _add_failed(failed_controls, CTRL_AD_LOGGING, "monitoring_backup", "high")

    if h2_log_review == "NO" or _is_not_sure(h2_log_review):
        monitoring_backup += 8
        _add_failed(failed_controls, CTRL_LOG_REVIEW, "monitoring_backup", "medium")

    g7_reasons: List[str] = []
    if h3_backup == "NO" or _is_not_sure(h3_backup):
        g7_reasons.append("AD backup is missing or unknown.")
        monitoring_backup += 18
        _add_failed(failed_controls, CTRL_AD_BACKUP, "monitoring_backup", "high")

    privileged_access_scaled = int(round(privileged_access * multiplier))
    total_deductions = (
        account_hygiene
        + privileged_access_scaled
        + password_policy
        + kerberos_auth
        + laps_gpo
        + dc_hygiene
        + monitoring_backup
    )

    all_gates = [
        _gate("G1", g1_reasons),
        _gate("G2", g2_reasons),
        _gate("G3", g3_reasons),
        _gate("G4", g4_reasons),
        _gate("G5", g5_reasons),
        _gate("G6", g6_reasons),
        _gate("G7", g7_reasons),
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
        privileged_multiplier=multiplier,
        gates=triggered_gates,
        deductions={
            "account_hygiene": account_hygiene,
            "privileged_access": privileged_access,
            "privileged_access_scaled": privileged_access_scaled,
            "password_policy": password_policy,
            "kerberos_auth": kerberos_auth,
            "laps_gpo": laps_gpo,
            "dc_hygiene": dc_hygiene,
            "monitoring_backup": monitoring_backup,
            "total": total_deductions,
        },
        failed_controls=failed_controls,
        risk_level=risk_level,
        notes=notes,
    )


def score_assessment_dict(answers: Dict[str, str]) -> Dict[str, Any]:
    return asdict(score_assessment(answers))
