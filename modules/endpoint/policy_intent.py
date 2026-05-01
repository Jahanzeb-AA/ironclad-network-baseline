from __future__ import annotations

from typing import Any, Dict, List


CONTROL_FIX_LIBRARY: Dict[str, Dict[str, Any]] = {
    "CTRL_ENDPOINT_PROTECTION_NOT_MANAGED": {
        "id": "CTRL_ENDPOINT_PROTECTION_NOT_MANAGED",
        "severity": "high",
        "title": "Deploy managed endpoint protection",
        "why": "Managed endpoint protection helps detect malware, suspicious behavior, and risky activity before it becomes a wider business incident.",
        "steps": [
            "Choose an endpoint protection or EDR tool appropriate for the business size.",
            "Install and verify protection on all business endpoints.",
            "Enable centralized policy management, alerting, and tamper protection where available.",
        ],
    },
    "CTRL_ENDPOINT_DISK_ENCRYPTION_MISSING": {
        "id": "CTRL_ENDPOINT_DISK_ENCRYPTION_MISSING",
        "severity": "medium",
        "title": "Enable full-disk encryption",
        "why": "Encryption reduces the chance of business data exposure if a laptop or portable device is lost or stolen.",
        "steps": [
            "Enable BitLocker, FileVault, or equivalent encryption on portable endpoints.",
            "Store recovery keys in a controlled administrative location.",
            "Review encryption status regularly for new and existing devices.",
        ],
    },
    "CTRL_ENDPOINT_HOST_FIREWALL_DISABLED": {
        "id": "CTRL_ENDPOINT_HOST_FIREWALL_DISABLED",
        "severity": "medium",
        "title": "Enable endpoint firewalls",
        "why": "Host firewalls reduce unnecessary inbound exposure and help limit movement between devices.",
        "steps": [
            "Enable the operating system firewall on business endpoints.",
            "Apply a standard firewall profile through device management where possible.",
            "Document any required exceptions for approved business applications.",
        ],
    },
    "CTRL_ENDPOINT_OS_PATCHING_WEAK": {
        "id": "CTRL_ENDPOINT_OS_PATCHING_WEAK",
        "severity": "high",
        "title": "Control operating system updates",
        "why": "Unpatched endpoints are easier to compromise through known vulnerabilities.",
        "steps": [
            "Use a managed update process for Windows, macOS, and other endpoint operating systems.",
            "Set a regular patching cadence with faster handling for critical security updates.",
            "Monitor update compliance and follow up on devices that fall behind.",
        ],
    },
    "CTRL_ENDPOINT_THIRD_PARTY_PATCHING_WEAK": {
        "id": "CTRL_ENDPOINT_THIRD_PARTY_PATCHING_WEAK",
        "severity": "medium",
        "title": "Patch common third-party applications",
        "why": "Browsers, PDF tools, and collaboration apps are common attack paths when updates are missed.",
        "steps": [
            "Inventory common third-party applications used across endpoints.",
            "Use automated update tools where practical.",
            "Remove unsupported or unnecessary applications.",
        ],
    },
    "CTRL_ENDPOINT_UNSUPPORTED_OS": {
        "id": "CTRL_ENDPOINT_UNSUPPORTED_OS",
        "severity": "high",
        "title": "Retire unsupported operating systems",
        "why": "Unsupported operating systems no longer receive normal security updates and can expose the business to avoidable compromise.",
        "steps": [
            "Identify endpoints running unsupported operating systems.",
            "Upgrade, replace, or isolate unsupported devices.",
            "Create an exception register for any device that cannot be upgraded immediately.",
        ],
    },
    "CTRL_ENDPOINT_LOCAL_ADMIN_EXCESSIVE": {
        "id": "CTRL_ENDPOINT_LOCAL_ADMIN_EXCESSIVE",
        "severity": "high",
        "title": "Reduce local administrator rights",
        "why": "Local administrator access makes malware and account compromise more damaging on endpoints.",
        "steps": [
            "Remove routine local administrator rights from standard users.",
            "Use separate privileged accounts or just-in-time elevation for support tasks.",
            "Review exceptions and remove access that is no longer needed.",
        ],
    },
    "CTRL_ENDPOINT_SCREEN_LOCK_WEAK": {
        "id": "CTRL_ENDPOINT_SCREEN_LOCK_WEAK",
        "severity": "medium",
        "title": "Enforce screen lock requirements",
        "why": "Screen lock policies reduce exposure when devices are unattended or used in shared spaces.",
        "steps": [
            "Require passwords, PINs, or biometrics on business endpoints.",
            "Set automatic lock after a short idle period.",
            "Apply the policy through endpoint management where possible.",
        ],
    },
    "CTRL_ENDPOINT_REMOTE_ACCESS_MFA_MISSING": {
        "id": "CTRL_ENDPOINT_REMOTE_ACCESS_MFA_MISSING",
        "severity": "high",
        "title": "Require MFA for remote endpoint access",
        "why": "MFA lowers the chance that stolen passwords can be used to access endpoints or management tools remotely.",
        "steps": [
            "Require MFA for remote access tools, VPN, and endpoint management portals.",
            "Remove direct remote desktop exposure where possible.",
            "Review remote access users and disable stale accounts.",
        ],
    },
    "CTRL_ENDPOINT_ALERT_REVIEW_MISSING": {
        "id": "CTRL_ENDPOINT_ALERT_REVIEW_MISSING",
        "severity": "high",
        "title": "Review endpoint security alerts",
        "why": "Endpoint alerts only reduce risk when someone reviews and acts on important events.",
        "steps": [
            "Assign ownership for endpoint security alert review.",
            "Define a simple response process for high-priority alerts.",
            "Tune alert notifications so important events are visible without overwhelming the team.",
        ],
    },
    "CTRL_ENDPOINT_INVENTORY_INCOMPLETE": {
        "id": "CTRL_ENDPOINT_INVENTORY_INCOMPLETE",
        "severity": "medium",
        "title": "Maintain an endpoint inventory",
        "why": "A current inventory helps the business know what must be protected, patched, and recovered.",
        "steps": [
            "Build an inventory of laptops, desktops, and shared workstations.",
            "Track owner, operating system, protection status, and last check-in.",
            "Review the inventory during onboarding, offboarding, and device replacement.",
        ],
    },
    "CTRL_ENDPOINT_BACKUP_INCOMPLETE": {
        "id": "CTRL_ENDPOINT_BACKUP_INCOMPLETE",
        "severity": "medium",
        "title": "Protect important endpoint data",
        "why": "Endpoint backup or cloud redirection reduces downtime and data loss after device failure, theft, or ransomware.",
        "steps": [
            "Redirect important user folders to protected cloud storage or deploy endpoint backup.",
            "Confirm backup coverage for users who store important data locally.",
            "Set retention that matches business recovery needs.",
        ],
    },
    "CTRL_ENDPOINT_RESTORE_NOT_TESTED": {
        "id": "CTRL_ENDPOINT_RESTORE_NOT_TESTED",
        "severity": "low",
        "title": "Test endpoint recovery",
        "why": "Recovery tests confirm that files and devices can be restored when the business needs them.",
        "steps": [
            "Test file restore for a sample endpoint or user.",
            "Document recovery steps for common device loss or replacement scenarios.",
            "Repeat testing periodically or after backup process changes.",
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
