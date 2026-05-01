from __future__ import annotations

from typing import Any, Dict, List


CONTROL_FIX_LIBRARY: Dict[str, Dict[str, Any]] = {
    "CTRL_ENDPOINT_AV_EDR_MISSING": {
        "id": "CTRL_ENDPOINT_AV_EDR_MISSING",
        "severity": "high",
        "title": "Deploy AV/EDR across endpoints",
        "why": "Endpoints without AV or EDR are more exposed to malware, credential theft, and ransomware activity.",
        "steps": [
            "Deploy endpoint protection to all business laptops, desktops, and shared workstations.",
            "Confirm all endpoints report as protected.",
            "Prioritize devices used by administrators, finance, and leadership.",
        ],
    },
    "CTRL_ENDPOINT_REALTIME_PROTECTION_DISABLED": {
        "id": "CTRL_ENDPOINT_REALTIME_PROTECTION_DISABLED",
        "severity": "high",
        "title": "Enable real-time protection",
        "why": "Real-time protection helps block malicious files and behavior before users or systems are affected.",
        "steps": [
            "Enable real-time protection in the endpoint security platform.",
            "Prevent users from disabling protection where supported.",
            "Review endpoints where protection is disabled or unhealthy.",
        ],
    },
    "CTRL_ENDPOINT_CENTRAL_VISIBILITY_MISSING": {
        "id": "CTRL_ENDPOINT_CENTRAL_VISIBILITY_MISSING",
        "severity": "medium",
        "title": "Centralize endpoint visibility",
        "why": "Central visibility helps IT confirm protection status, spot missing devices, and respond to alerts quickly.",
        "steps": [
            "Use a central console for endpoint protection health and alerts.",
            "Review devices that have not checked in recently.",
            "Assign ownership for weekly endpoint security review.",
        ],
    },
    "CTRL_ENDPOINT_PATCH_MANAGEMENT_MISSING": {
        "id": "CTRL_ENDPOINT_PATCH_MANAGEMENT_MISSING",
        "severity": "high",
        "title": "Establish OS patch management",
        "why": "Unpatched operating systems are a common entry point for compromise and business disruption.",
        "steps": [
            "Define a regular operating system update process.",
            "Use automated patch deployment where possible.",
            "Track update compliance and follow up on devices that fall behind.",
        ],
    },
    "CTRL_ENDPOINT_THIRD_PARTY_PATCHING_MISSING": {
        "id": "CTRL_ENDPOINT_THIRD_PARTY_PATCHING_MISSING",
        "severity": "medium",
        "title": "Patch third-party applications",
        "why": "Browsers, PDF readers, and collaboration tools are frequently targeted when updates are missed.",
        "steps": [
            "Inventory common third-party applications.",
            "Enable automatic updates or use a patching tool.",
            "Remove unsupported or unnecessary software.",
        ],
    },
    "CTRL_ENDPOINT_PATCH_CADENCE_WEAK": {
        "id": "CTRL_ENDPOINT_PATCH_CADENCE_WEAK",
        "severity": "medium",
        "title": "Improve patch cadence",
        "why": "Long patch delays leave known vulnerabilities available to attackers for longer than necessary.",
        "steps": [
            "Set target timelines for important and critical patches.",
            "Prioritize executive, finance, administrator, and remote-user endpoints.",
            "Review patch status at least monthly.",
        ],
    },
    "CTRL_ENDPOINT_DISK_ENCRYPTION_MISSING": {
        "id": "CTRL_ENDPOINT_DISK_ENCRYPTION_MISSING",
        "severity": "high",
        "title": "Enable full-disk encryption",
        "why": "Encryption reduces the chance of business data exposure if a laptop or endpoint is lost or stolen.",
        "steps": [
            "Enable BitLocker, FileVault, or equivalent encryption on endpoints.",
            "Prioritize laptops and portable devices first.",
            "Monitor encryption status through device management where possible.",
        ],
    },
    "CTRL_ENDPOINT_RECOVERY_KEYS_UNMANAGED": {
        "id": "CTRL_ENDPOINT_RECOVERY_KEYS_UNMANAGED",
        "severity": "medium",
        "title": "Control encryption recovery keys",
        "why": "Recovery keys are needed for support and recovery, but unmanaged keys can create avoidable data exposure.",
        "steps": [
            "Store recovery keys in a controlled administrative location.",
            "Restrict who can view or export recovery keys.",
            "Review devices that do not have escrowed recovery keys.",
        ],
    },
    "CTRL_ENDPOINT_LOCAL_ADMIN_BROAD": {
        "id": "CTRL_ENDPOINT_LOCAL_ADMIN_BROAD",
        "severity": "high",
        "title": "Reduce local administrator rights",
        "why": "Broad local administrator rights make malware, ransomware, and account compromise more damaging.",
        "steps": [
            "Remove routine local administrator rights from standard users.",
            "Use separate privileged accounts or approved elevation workflows.",
            "Document and review exceptions regularly.",
        ],
    },
    "CTRL_ENDPOINT_ADMIN_RIGHTS_CONTROL_WEAK": {
        "id": "CTRL_ENDPOINT_ADMIN_RIGHTS_CONTROL_WEAK",
        "severity": "medium",
        "title": "Control and approve admin rights",
        "why": "A formal approval process helps prevent privilege creep and reduces the impact of compromised accounts.",
        "steps": [
            "Define who may approve local administrator access.",
            "Make access temporary where possible.",
            "Review existing administrator memberships and remove stale entries.",
        ],
    },
    "CTRL_ENDPOINT_USER_INSTALLS_UNRESTRICTED": {
        "id": "CTRL_ENDPOINT_USER_INSTALLS_UNRESTRICTED",
        "severity": "medium",
        "title": "Restrict unapproved software installs",
        "why": "Uncontrolled software installation increases exposure to malware, unsupported tools, and licensing issues.",
        "steps": [
            "Require approval for new software installation.",
            "Remove local admin rights where they enable unapproved installs.",
            "Publish a list of approved business applications.",
        ],
    },
    "CTRL_ENDPOINT_APPLICATION_RESTRICTIONS_MISSING": {
        "id": "CTRL_ENDPOINT_APPLICATION_RESTRICTIONS_MISSING",
        "severity": "medium",
        "title": "Use application restrictions",
        "why": "Application restrictions reduce the chance that unauthorized or risky software can run on business endpoints.",
        "steps": [
            "Start with blocking known unwanted applications and script abuse paths.",
            "Use allow lists for sensitive or high-risk user groups where practical.",
            "Test policy impact before broad enforcement.",
        ],
    },
    "CTRL_ENDPOINT_USB_CONTROL_MISSING": {
        "id": "CTRL_ENDPOINT_USB_CONTROL_MISSING",
        "severity": "medium",
        "title": "Control USB and removable media use",
        "why": "USB and removable media can introduce malware or lead to unmanaged data movement.",
        "steps": [
            "Define whether removable media is allowed for business use.",
            "Restrict removable media for users who do not need it.",
            "Monitor or approve exceptions for legitimate workflows.",
        ],
    },
    "CTRL_ENDPOINT_REMOVABLE_MEDIA_ENCRYPTION_MISSING": {
        "id": "CTRL_ENDPOINT_REMOVABLE_MEDIA_ENCRYPTION_MISSING",
        "severity": "medium",
        "title": "Require encryption for removable media",
        "why": "Encrypted removable media reduces data exposure if a USB drive or external disk is lost.",
        "steps": [
            "Require encryption for approved removable storage.",
            "Document acceptable removable media use cases.",
            "Train users not to move sensitive data to unmanaged devices.",
        ],
    },
    "CTRL_ENDPOINT_BACKUP_MISSING": {
        "id": "CTRL_ENDPOINT_BACKUP_MISSING",
        "severity": "high",
        "title": "Protect endpoint data with backup",
        "why": "Endpoint backup helps recover from device failure, theft, accidental deletion, and ransomware.",
        "steps": [
            "Redirect important folders to protected cloud storage or deploy endpoint backup.",
            "Confirm critical users are covered.",
            "Define retention that matches business recovery needs.",
        ],
    },
    "CTRL_ENDPOINT_RESTORE_NOT_TESTED": {
        "id": "CTRL_ENDPOINT_RESTORE_NOT_TESTED",
        "severity": "low",
        "title": "Test endpoint restore",
        "why": "Restore testing confirms that backup or cloud recovery will work when the business needs it.",
        "steps": [
            "Test restoring files for a sample endpoint or user.",
            "Document common restore steps.",
            "Repeat testing after backup or storage changes.",
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
    # The app passes gates for every baseline; endpoint fixes are control-driven today.
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
