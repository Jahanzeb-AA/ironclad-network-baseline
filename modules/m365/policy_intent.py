from __future__ import annotations

from typing import Any, Dict, List


CONTROL_FIX_LIBRARY: Dict[str, Dict[str, Any]] = {
    "CTRL_M365_MFA_NOT_ENFORCED": {
        "id": "CTRL_M365_MFA_NOT_ENFORCED",
        "severity": "high",
        "title": "Enforce multi-factor authentication for all users",
        "why": "MFA lowers the risk of account takeover when passwords are guessed, reused, or stolen.",
        "steps": [
            "Require MFA for every user account, not only administrators.",
            "Use Conditional Access or security defaults depending on licensing.",
            "Review MFA registration and follow up with users who are not enrolled.",
        ],
    },
    "CTRL_M365_LEGACY_AUTH_ALLOWED": {
        "id": "CTRL_M365_LEGACY_AUTH_ALLOWED",
        "severity": "high",
        "title": "Block legacy authentication",
        "why": "Legacy protocols can bypass modern controls such as MFA and are frequently abused in password-spray attacks.",
        "steps": [
            "Disable POP, IMAP, SMTP AUTH, and other legacy authentication where not explicitly required.",
            "Use Conditional Access authentication policies or Exchange Online authentication settings.",
            "Monitor sign-in logs for legacy authentication attempts after rollout.",
        ],
    },
    "CTRL_M365_ADMIN_SEPARATION": {
        "id": "CTRL_M365_ADMIN_SEPARATION",
        "severity": "medium",
        "title": "Use dedicated administrator accounts",
        "why": "Separate admin accounts reduce the chance that daily email or browsing activity exposes privileged access.",
        "steps": [
            "Create dedicated accounts for administrative work.",
            "Remove privileged roles from daily-use mailbox accounts.",
            "Require stronger controls for admin accounts, including MFA and restricted login conditions.",
        ],
    },
    "CTRL_M365_CONDITIONAL_ACCESS": {
        "id": "CTRL_M365_CONDITIONAL_ACCESS",
        "severity": "medium",
        "title": "Implement Conditional Access policies",
        "why": "Conditional Access helps reduce risky sign-ins by enforcing requirements based on user, device, location, and risk.",
        "steps": [
            "Start with policies for MFA, admin protection, and blocking legacy authentication.",
            "Use report-only mode before enforcement where practical.",
            "Document exclusions and keep break-glass accounts tightly controlled.",
        ],
    },
    "CTRL_M365_TOO_MANY_GLOBAL_ADMINS": {
        "id": "CTRL_M365_TOO_MANY_GLOBAL_ADMINS",
        "severity": "medium",
        "title": "Limit Global Administrator accounts",
        "why": "Too many highly privileged accounts increases the impact of credential compromise or misconfiguration.",
        "steps": [
            "Reduce Global Administrators to the smallest practical number.",
            "Use least-privilege roles for routine administration.",
            "Review privileged role assignments on a recurring schedule.",
        ],
    },
    "CTRL_M365_EXTERNAL_FORWARDING_ALLOWED": {
        "id": "CTRL_M365_EXTERNAL_FORWARDING_ALLOWED",
        "severity": "high",
        "title": "Block external email auto-forwarding",
        "why": "External forwarding can silently leak business email after account compromise or misconfiguration.",
        "steps": [
            "Disable automatic external forwarding by default.",
            "Allow exceptions only when there is a documented business need.",
            "Monitor mailbox forwarding rules and transport rules regularly.",
        ],
    },
    "CTRL_M365_EXTERNAL_BANNER_MISSING": {
        "id": "CTRL_M365_EXTERNAL_BANNER_MISSING",
        "severity": "low",
        "title": "Add external email indicators",
        "why": "External indicators help users recognize messages that originated outside the organization.",
        "steps": [
            "Enable native external sender tagging or a concise transport-rule banner.",
            "Test with common business workflows before broad rollout.",
        ],
    },
    "CTRL_M365_PHISHING_PROTECTION_MISSING": {
        "id": "CTRL_M365_PHISHING_PROTECTION_MISSING",
        "severity": "high",
        "title": "Enable phishing and malware protection",
        "why": "Phishing protection reduces the likelihood that malicious links or attachments reach users unchecked.",
        "steps": [
            "Enable Microsoft Defender for Office 365 or equivalent protections where licensed.",
            "Configure safe links, safe attachments, and anti-phishing policies.",
            "Review quarantine and detection reports regularly.",
        ],
    },
    "CTRL_M365_EMAIL_AUTH_INCOMPLETE": {
        "id": "CTRL_M365_EMAIL_AUTH_INCOMPLETE",
        "severity": "medium",
        "title": "Configure SPF, DKIM, and DMARC",
        "why": "Email authentication reduces spoofing risk and improves trust in messages sent from your domain.",
        "steps": [
            "Publish or correct SPF records for approved senders.",
            "Enable DKIM signing for each accepted domain.",
            "Deploy DMARC gradually, moving toward quarantine or reject after monitoring.",
        ],
    },
    "CTRL_M365_ANONYMOUS_SHARING": {
        "id": "CTRL_M365_ANONYMOUS_SHARING",
        "severity": "medium",
        "title": "Restrict anonymous file sharing",
        "why": "Anonymous links can expose business data beyond intended recipients, especially when links are forwarded.",
        "steps": [
            "Disable or restrict Anyone links in SharePoint and OneDrive.",
            "Require expiration dates and least-privilege permissions for external sharing.",
            "Review existing anonymous links and remove unnecessary access.",
        ],
    },
    "CTRL_M365_BACKUPS_MISSING": {
        "id": "CTRL_M365_BACKUPS_MISSING",
        "severity": "high",
        "title": "Implement independent Microsoft 365 backups",
        "why": "Independent backups improve recovery options for accidental deletion, ransomware, and retention gaps.",
        "steps": [
            "Select a backup solution covering Exchange, SharePoint, OneDrive, and Teams as needed.",
            "Define retention based on business and compliance needs.",
            "Test restore workflows for mailbox and file recovery.",
        ],
    },
    "CTRL_M365_AUDIT_LOGGING_DISABLED": {
        "id": "CTRL_M365_AUDIT_LOGGING_DISABLED",
        "severity": "high",
        "title": "Enable audit logging",
        "why": "Audit logs are essential for investigating account activity, administrative changes, and suspicious behavior.",
        "steps": [
            "Ensure Microsoft 365 audit logging is enabled.",
            "Review user and administrator activity logs periodically.",
            "Send important security events to a monitoring process or ticket workflow where practical.",
        ],
    },
    "CTRL_M365_DEVICE_COMPLIANCE_MISSING": {
        "id": "CTRL_M365_DEVICE_COMPLIANCE_MISSING",
        "severity": "medium",
        "title": "Enforce device compliance for access",
        "why": "Device compliance controls reduce access from unmanaged, outdated, or risky endpoints.",
        "steps": [
            "Define baseline device requirements such as encryption, screen lock, and supported OS versions.",
            "Use Intune and Conditional Access where licensing supports it.",
            "Apply controls gradually, starting with higher-risk users and admin accounts.",
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
