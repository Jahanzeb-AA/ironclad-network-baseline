from __future__ import annotations

from typing import Any, Dict, List


CONTROL_FIX_LIBRARY: Dict[str, Dict[str, Any]] = {
    "CTRL_AD_STALE_USERS": {
        "id": "CTRL_AD_STALE_USERS",
        "severity": "medium",
        "title": "Remove or disable stale user accounts",
        "why": "Inactive user accounts can be abused if passwords are guessed, reused, or previously compromised.",
        "steps": [
            "Identify users with no recent logon activity.",
            "Disable stale accounts before deletion where business ownership is unclear.",
            "Add stale-account review to the joiner, mover, and leaver process.",
        ],
    },
    "CTRL_AD_STALE_COMPUTERS": {
        "id": "CTRL_AD_STALE_COMPUTERS",
        "severity": "medium",
        "title": "Clean up stale computer accounts",
        "why": "Old computer accounts make inventory unreliable and can leave unnecessary trust objects in AD.",
        "steps": [
            "Identify computers with no recent domain activity.",
            "Disable or quarantine stale computer objects.",
            "Review stale computer cleanup on a recurring schedule.",
        ],
    },
    "CTRL_AD_SHARED_ACCOUNTS": {
        "id": "CTRL_AD_SHARED_ACCOUNTS",
        "severity": "medium",
        "title": "Eliminate shared user accounts",
        "why": "Shared accounts reduce accountability and make it harder to investigate activity or remove access cleanly.",
        "steps": [
            "Replace shared accounts with named user accounts.",
            "Use groups or delegated access for shared business functions.",
            "Monitor for remaining shared-account use.",
        ],
    },
    "CTRL_AD_GUEST_ACCOUNT_ENABLED": {
        "id": "CTRL_AD_GUEST_ACCOUNT_ENABLED",
        "severity": "low",
        "title": "Disable the Guest account",
        "why": "The built-in Guest account should not be available in normal business environments.",
        "steps": [
            "Confirm the built-in Guest account is disabled.",
            "Monitor for attempts to re-enable it.",
            "Document any exception if a legacy dependency exists.",
        ],
    },
    "CTRL_AD_DOMAIN_ADMIN_COUNT_HIGH": {
        "id": "CTRL_AD_DOMAIN_ADMIN_COUNT_HIGH",
        "severity": "high",
        "title": "Reduce Domain Admin membership",
        "why": "Too many Domain Admins increases the chance that one compromised account can affect the entire domain.",
        "steps": [
            "Review all Domain Admin members and remove unnecessary accounts.",
            "Use delegated administration instead of broad domain-wide privileges.",
            "Review privileged group membership regularly.",
        ],
    },
    "CTRL_AD_DOMAIN_ADMIN_DAILY_USE": {
        "id": "CTRL_AD_DOMAIN_ADMIN_DAILY_USE",
        "severity": "high",
        "title": "Stop daily use of Domain Admin accounts",
        "why": "Using highly privileged accounts for routine work increases exposure to phishing, malware, and credential theft.",
        "steps": [
            "Create separate admin accounts for privileged work.",
            "Use standard accounts for email, browsing, and daily business activity.",
            "Restrict where Domain Admin accounts can log on.",
        ],
    },
    "CTRL_AD_DEFAULT_ADMIN_EXPOSED": {
        "id": "CTRL_AD_DEFAULT_ADMIN_EXPOSED",
        "severity": "medium",
        "title": "Protect the default Administrator account",
        "why": "The default Administrator account is predictable and often targeted during attacks.",
        "steps": [
            "Disable, rename, or tightly restrict the default Administrator account where practical.",
            "Monitor for use of the account.",
            "Ensure emergency access is documented and controlled.",
        ],
    },
    "CTRL_AD_SERVICE_ACCOUNT_DOMAIN_ADMIN": {
        "id": "CTRL_AD_SERVICE_ACCOUNT_DOMAIN_ADMIN",
        "severity": "high",
        "title": "Remove Domain Admin rights from service accounts",
        "why": "Service accounts with Domain Admin privileges create a high-impact path to domain compromise.",
        "steps": [
            "Identify service accounts with privileged group membership.",
            "Replace broad privileges with least-privilege delegation.",
            "Use managed service accounts where supported.",
        ],
    },
    "CTRL_AD_PASSWORD_POLICY_WEAK": {
        "id": "CTRL_AD_PASSWORD_POLICY_WEAK",
        "severity": "high",
        "title": "Strengthen the AD password policy",
        "why": "Weak or missing password policy increases the risk of password guessing and account takeover.",
        "steps": [
            "Define a password policy aligned to business and security needs.",
            "Use length and lockout controls appropriate for the environment.",
            "Consider banned-password or password-protection features where available.",
        ],
    },
    "CTRL_AD_ACCOUNT_LOCKOUT_MISSING": {
        "id": "CTRL_AD_ACCOUNT_LOCKOUT_MISSING",
        "severity": "medium",
        "title": "Configure account lockout",
        "why": "Account lockout helps slow password guessing and password spray attempts.",
        "steps": [
            "Configure lockout threshold, duration, and reset settings.",
            "Balance lockout controls against operational support impact.",
            "Monitor lockout events for attack patterns.",
        ],
    },
    "CTRL_AD_PASSWORD_NEVER_EXPIRES": {
        "id": "CTRL_AD_PASSWORD_NEVER_EXPIRES",
        "severity": "medium",
        "title": "Review passwords set to never expire",
        "why": "Accounts with passwords that never expire can retain old or exposed credentials indefinitely.",
        "steps": [
            "Identify accounts with password-never-expires enabled.",
            "Remove the setting where it is not explicitly required.",
            "Use managed service account patterns for service needs.",
        ],
    },
    "CTRL_AD_ASREP_ROASTING_EXPOSURE": {
        "id": "CTRL_AD_ASREP_ROASTING_EXPOSURE",
        "severity": "high",
        "title": "Remove AS-REP roasting exposure",
        "why": "Accounts without Kerberos pre-authentication can expose material for offline password cracking.",
        "steps": [
            "Identify accounts with Kerberos pre-authentication disabled.",
            "Re-enable pre-authentication unless there is a documented legacy requirement.",
            "Prioritize service and privileged accounts.",
        ],
    },
    "CTRL_AD_WEAK_SPN_ACCOUNTS": {
        "id": "CTRL_AD_WEAK_SPN_ACCOUNTS",
        "severity": "high",
        "title": "Harden SPN and service accounts",
        "why": "Weak service accounts with SPNs are common Kerberoasting targets.",
        "steps": [
            "Inventory SPN-bearing accounts.",
            "Use long, unique passwords or managed service accounts.",
            "Remove stale SPNs and unused service accounts.",
        ],
    },
    "CTRL_AD_NTLMV1_ALLOWED": {
        "id": "CTRL_AD_NTLMV1_ALLOWED",
        "severity": "medium",
        "title": "Disable NTLMv1",
        "why": "NTLMv1 is an outdated authentication protocol and should not be used in modern AD environments.",
        "steps": [
            "Audit NTLMv1 usage before enforcement.",
            "Remediate legacy systems that require NTLMv1.",
            "Disable NTLMv1 through policy once dependencies are addressed.",
        ],
    },
    "CTRL_AD_LAPS_MISSING": {
        "id": "CTRL_AD_LAPS_MISSING",
        "severity": "high",
        "title": "Deploy LAPS or Windows LAPS",
        "why": "LAPS reduces the risk of shared local administrator passwords across joined machines.",
        "steps": [
            "Deploy Windows LAPS or Microsoft LAPS.",
            "Ensure local administrator passwords are unique and rotated.",
            "Restrict who can read LAPS passwords.",
        ],
    },
    "CTRL_AD_GPO_REVIEW_MISSING": {
        "id": "CTRL_AD_GPO_REVIEW_MISSING",
        "severity": "medium",
        "title": "Review Group Policies regularly",
        "why": "Old or conflicting GPOs can weaken security controls or create operational surprises.",
        "steps": [
            "Inventory linked and unlinked GPOs.",
            "Review high-impact policies first.",
            "Remove or document stale policies.",
        ],
    },
    "CTRL_AD_RESTRICTED_GROUPS_MISSING": {
        "id": "CTRL_AD_RESTRICTED_GROUPS_MISSING",
        "severity": "medium",
        "title": "Control local admin groups through policy",
        "why": "Uncontrolled local administrator groups can allow privilege creep across endpoints and servers.",
        "steps": [
            "Use Restricted Groups, Group Policy Preferences, or endpoint management controls.",
            "Define approved local administrator membership.",
            "Monitor drift from the approved configuration.",
        ],
    },
    "CTRL_AD_DC_EOL_OS": {
        "id": "CTRL_AD_DC_EOL_OS",
        "severity": "high",
        "title": "Upgrade unsupported domain controllers",
        "why": "Domain controllers on unsupported operating systems expose the core identity platform to known risks.",
        "steps": [
            "Identify domain controllers on unsupported operating systems.",
            "Plan migration to supported versions.",
            "Remove or isolate legacy domain controllers during transition.",
        ],
    },
    "CTRL_AD_DC_PATCHING_MISSING": {
        "id": "CTRL_AD_DC_PATCHING_MISSING",
        "severity": "high",
        "title": "Patch domain controllers regularly",
        "why": "Unpatched domain controllers increase the risk of compromise to the identity foundation.",
        "steps": [
            "Define a patch cadence for domain controllers.",
            "Test and apply security updates promptly.",
            "Monitor patch compliance after maintenance windows.",
        ],
    },
    "CTRL_AD_DC_MIXED_ROLES": {
        "id": "CTRL_AD_DC_MIXED_ROLES",
        "severity": "medium",
        "title": "Keep domain controllers dedicated",
        "why": "Running extra roles on domain controllers increases attack surface and operational risk.",
        "steps": [
            "Identify non-AD roles running on domain controllers.",
            "Move business applications and file services to separate servers.",
            "Restrict domain controllers to identity services where practical.",
        ],
    },
    "CTRL_AD_DC_ACCESS_NOT_RESTRICTED": {
        "id": "CTRL_AD_DC_ACCESS_NOT_RESTRICTED",
        "severity": "medium",
        "title": "Restrict domain controller access",
        "why": "Domain controllers should only be accessed by authorized administrators from appropriate admin workstations.",
        "steps": [
            "Restrict interactive logon to approved administrators.",
            "Limit network access to management paths that are required.",
            "Monitor logons to domain controllers.",
        ],
    },
    "CTRL_AD_AUDIT_LOGGING_MISSING": {
        "id": "CTRL_AD_AUDIT_LOGGING_MISSING",
        "severity": "high",
        "title": "Enable AD audit logging",
        "why": "Without audit logging, suspicious identity activity and administrative changes may go unseen.",
        "steps": [
            "Enable auditing for logons, group changes, account changes, and policy changes.",
            "Forward important events to a central location where possible.",
            "Confirm logs are retained long enough for investigation.",
        ],
    },
    "CTRL_AD_LOG_REVIEW_MISSING": {
        "id": "CTRL_AD_LOG_REVIEW_MISSING",
        "severity": "medium",
        "title": "Review AD security logs",
        "why": "Logs only reduce risk when important events are reviewed and acted on.",
        "steps": [
            "Assign ownership for AD log review.",
            "Define alerts for high-impact changes and suspicious activity.",
            "Review privileged group changes and failed logon patterns.",
        ],
    },
    "CTRL_AD_BACKUP_MISSING": {
        "id": "CTRL_AD_BACKUP_MISSING",
        "severity": "high",
        "title": "Maintain AD backups",
        "why": "AD backup improves recovery options after ransomware, corruption, accidental deletion, or domain controller failure.",
        "steps": [
            "Back up domain controllers or system state regularly.",
            "Protect backups from deletion or tampering.",
            "Test recovery procedures periodically.",
        ],
    },
}


def _control_id(control: Any) -> str:
    if isinstance(control, dict):
        return str(control.get("id", ""))
    return str(control)


def _control_severity(control: Any) -> str:
    if isinstance(control, dict):
        severity = str(control.get("severity", "")).lower()
        if severity in {"high", "medium", "low"}:
            return severity
    return ""


def generate_fix_blocks(failed_controls: List[Any], gates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # The app passes gates for every baseline; AD fixes are control-driven today.
    fixes = []
    seen = set()

    for control in failed_controls:
        control_id = _control_id(control)
        if not control_id:
            continue
        if control_id in seen:
            continue
        seen.add(control_id)

        fix = CONTROL_FIX_LIBRARY.get(control_id)
        if fix:
            normalized_fix = fix.copy()
            normalized_fix["severity"] = _control_severity(control) or str(
                normalized_fix.get("severity", "medium")
            ).lower()
            fixes.append(normalized_fix)

    return fixes
