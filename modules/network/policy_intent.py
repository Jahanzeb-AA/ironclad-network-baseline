from __future__ import annotations

from typing import Any, Dict, List


CONTROL_FIX_LIBRARY: Dict[str, Dict[str, Any]] = {
    "CTRL_PERIMETER_WAN_ADMIN_EXPOSURE": {
        "id": "CTRL_PERIMETER_WAN_ADMIN_EXPOSURE",
        "severity": "high",
        "title": "Restrict public access to management interfaces",
        "why": "Publicly exposed management interfaces increase the risk of unauthorized access through credential attacks or software vulnerabilities.",
        "steps": [
            "Disable WAN or internet-facing management on firewalls, routers, switches, and wireless controllers.",
            "Allow administrative access only from trusted internal networks or through a secure VPN.",
            "Review firewall rules and vendor cloud-management settings for unintended public exposure.",
        ],
    },
    "CTRL_PERIMETER_PORT_FORWARDING": {
        "id": "CTRL_PERIMETER_PORT_FORWARDING",
        "severity": "high",
        "title": "Remove direct internet exposure of internal services",
        "why": "Port forwarding to internal systems weakens the network boundary and is a common entry point for compromise.",
        "steps": [
            "Remove exposed RDP, SSH, web admin, and similar port-forwarding rules.",
            "Provide remote access through a client-to-site VPN with strong authentication.",
            "Prefer SaaS or zero-trust access patterns where they fit the business workflow.",
        ],
    },
    "CTRL_IDENTITY_ADMIN_MFA": {
        "id": "CTRL_IDENTITY_ADMIN_MFA",
        "severity": "high",
        "title": "Enforce MFA for administrative access",
        "why": "MFA reduces the impact of password compromise and improves protection for privileged access.",
        "steps": [
            "Require MFA for firewall, switch, Wi-Fi controller, VPN, and management portal administrators.",
            "Use app-based or hardware-backed MFA methods where supported.",
            "Review admin accounts periodically and remove stale access.",
        ],
    },
    "CTRL_SEGMENTATION_GUEST_NOT_ISOLATED": {
        "id": "CTRL_SEGMENTATION_GUEST_NOT_ISOLATED",
        "severity": "high",
        "title": "Isolate guest access from internal systems",
        "why": "Guest devices should be treated as untrusted; isolation limits visibility of internal systems and reduces lateral movement risk.",
        "steps": [
            "Place guest access on a dedicated network segment or SSID.",
            "Apply default-deny rules from guest networks to internal networks.",
            "Allow only required services such as DHCP, DNS, and internet-bound traffic.",
        ],
    },
    "CTRL_SEGMENTATION_FLAT_NETWORK": {
        "id": "CTRL_SEGMENTATION_FLAT_NETWORK",
        "severity": "high",
        "title": "Implement basic network segmentation",
        "why": "Segmentation limits lateral movement and reduces the business impact of a compromised endpoint.",
        "steps": [
            "Create separate segments for staff, guest, IoT, and management where possible.",
            "Enforce inter-segment traffic rules through firewall or layer-3 controls.",
            "Start with high-risk separations first, especially guest and IoT from business systems.",
        ],
    },
    "CTRL_SEGMENTATION_PARTIAL": {
        "id": "CTRL_SEGMENTATION_PARTIAL",
        "severity": "medium",
        "title": "Strengthen segmentation boundaries",
        "why": "Partial segmentation can still leave unnecessary paths between user groups, devices, or sensitive systems.",
        "steps": [
            "Identify which device groups still share networks unnecessarily.",
            "Complete separation for staff, guest, and IoT networks.",
            "Document allowed traffic between segments and deny everything else by default.",
        ],
    },
    "CTRL_SEGMENTATION_IOT_WITH_CRITICAL": {
        "id": "CTRL_SEGMENTATION_IOT_WITH_CRITICAL",
        "severity": "medium",
        "title": "Contain IoT and unmanaged devices",
        "why": "IoT devices often have weaker patching and security controls, so keeping them away from critical systems reduces exposure.",
        "steps": [
            "Move IoT and unmanaged devices to a restricted network segment.",
            "Block access from IoT networks to finance, payroll, servers, and administrator workstations unless explicitly required.",
            "Review device inventory and remove unknown devices.",
        ],
    },
    "CTRL_WIRELESS_OPEN_OR_UNKNOWN": {
        "id": "CTRL_WIRELESS_OPEN_OR_UNKNOWN",
        "severity": "high",
        "title": "Use modern Wi-Fi security",
        "why": "Open or unknown Wi-Fi security increases the chance of unauthorized network access.",
        "steps": [
            "Use WPA2 or WPA3 with a strong configuration for corporate Wi-Fi.",
            "Consider WPA2/WPA3 Enterprise with 802.1X for managed business devices.",
            "Keep guest Wi-Fi separate from corporate access.",
        ],
    },
    "CTRL_WIRELESS_PSK_ONLY": {
        "id": "CTRL_WIRELESS_PSK_ONLY",
        "severity": "medium",
        "title": "Harden shared-password Wi-Fi",
        "why": "Shared Wi-Fi passwords are harder to revoke and audit when employees or devices change.",
        "steps": [
            "Use a strong corporate Wi-Fi password and rotate it when staff or vendor access changes.",
            "Avoid sharing the corporate password with guests or unmanaged devices.",
            "Plan a move to 802.1X where licensing and equipment support it.",
        ],
    },
    "CTRL_WIRELESS_GUEST_CLIENT_ISOLATION": {
        "id": "CTRL_WIRELESS_GUEST_CLIENT_ISOLATION",
        "severity": "medium",
        "title": "Enable guest client isolation",
        "why": "Client isolation reduces peer-to-peer attacks and limits spread between guest devices.",
        "steps": [
            "Enable client isolation on the guest SSID.",
            "Confirm guests cannot discover or connect to each other.",
            "Combine client isolation with network-level guest isolation from internal systems.",
        ],
    },
    "CTRL_HYGIENE_UNUSED_PORTS": {
        "id": "CTRL_HYGIENE_UNUSED_PORTS",
        "severity": "medium",
        "title": "Restrict unused network ports",
        "why": "Open unused ports increase the risk of unauthorized physical access and rogue devices joining the network.",
        "steps": [
            "Disable unused switch ports and wall jacks where practical.",
            "Place unused ports into a safe non-production VLAN if they cannot be disabled.",
            "Review active ports periodically against the device inventory.",
        ],
    },
    "CTRL_OPERATIONS_NO_BACKUPS": {
        "id": "CTRL_OPERATIONS_NO_BACKUPS",
        "severity": "high",
        "title": "Establish configuration backups",
        "why": "Configuration backups reduce downtime and enable recovery after device failure or misconfiguration.",
        "steps": [
            "Back up firewall, router, switch, and Wi-Fi configurations.",
            "Store backups securely away from the device itself.",
            "Test restore steps periodically so recovery is practical during an outage.",
        ],
    },
    "CTRL_OPERATIONS_NO_LOGGING": {
        "id": "CTRL_OPERATIONS_NO_LOGGING",
        "severity": "high",
        "title": "Enable basic logging and retention",
        "why": "Without logs, troubleshooting and incident response are limited and security events may go undetected.",
        "steps": [
            "Enable firewall and network device logging.",
            "Store logs locally or centrally with reasonable retention.",
            "Include authentication events, configuration changes, and security-relevant traffic where supported.",
        ],
    },
    "CTRL_OPERATIONS_FIRMWARE_RARE": {
        "id": "CTRL_OPERATIONS_FIRMWARE_RARE",
        "severity": "medium",
        "title": "Adopt a regular update cadence",
        "why": "Regular firmware and software updates reduce exposure to known vulnerabilities and improve stability.",
        "steps": [
            "Review network device firmware versions on a regular schedule.",
            "Apply urgent security updates promptly after vendor review.",
            "Track changes and keep rollback information for critical devices.",
        ],
    },
    "CTRL_HYGIENE_DEFAULT_CREDENTIALS": {
        "id": "CTRL_HYGIENE_DEFAULT_CREDENTIALS",
        "severity": "high",
        "title": "Replace default device credentials",
        "why": "Default credentials are widely known and can allow quick unauthorized access to network equipment.",
        "steps": [
            "Change default passwords on routers, switches, access points, firewalls, and controllers.",
            "Use unique administrator credentials for each management plane where possible.",
            "Disable or remove unused default accounts.",
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
