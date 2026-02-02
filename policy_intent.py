from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional


# -----------------------------
# Fix Block data structure
# -----------------------------
@dataclass
class FixBlock:
    severity: str                 # "critical" | "high" | "medium"
    gate: Optional[str]           # "G1".."G5" or None for non-gate findings
    control_id: str               # stable ID from scoring.py
    title: str                    # short heading
    finding: str                  # what is wrong (plain, factual)
    policy_intent: str            # what should be true (vendor-agnostic)
    technical_rationale: str      # why it matters (short, not alarmist)
    references: List[str]         # e.g. ["CIS IG1", "NIST SMB Baseline", "Vendor Best Practice"]


# -----------------------------
# Reference tags (reputation shield)
# Keep them generic; don't cite deep document numbers in v1.
# -----------------------------
REF_CIS_IG1 = "CIS Controls (IG1)"
REF_NIST_SMB = "NIST SMB Baseline"
REF_VENDOR = "Vendor Best Practice"


# -----------------------------
# Canonical fix blocks (control_id -> FixBlock template)
# -----------------------------
CONTROL_FIX_LIBRARY: Dict[str, FixBlock] = {
    # --- G1 Perimeter / Remote Access ---
    "CTRL_PERIMETER_WAN_ADMIN_EXPOSURE": FixBlock(
        severity="critical",
        gate="G1",
        control_id="CTRL_PERIMETER_WAN_ADMIN_EXPOSURE",
        title="Restrict public access to management interfaces",
        finding="Administrative login interfaces for network equipment are reachable from the public internet (or this is unknown).",
        policy_intent=(
            "Administrative access to network infrastructure should be reachable only from trusted internal networks "
            "or through a secure VPN. Public (WAN) management access should be disabled."
        ),
        technical_rationale=(
            "Publicly exposed management interfaces significantly increase the likelihood of unauthorized access "
            "through credential attacks or software vulnerabilities."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_PERIMETER_PORT_FORWARDING": FixBlock(
        severity="critical",
        gate="G1",
        control_id="CTRL_PERIMETER_PORT_FORWARDING",
        title="Remove direct internet exposure of internal services",
        finding="Remote access to internal systems is provided via port forwarding / exposed services.",
        policy_intent=(
            "Remove direct internet exposure of internal services. Provide remote access using a client-to-site VPN "
            "with strong authentication. Prefer cloud/SaaS access where possible."
        ),
        technical_rationale=(
            "Direct exposure of internal services removes a key security boundary and is a common entry point for compromise in SMB environments."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_IDENTITY_ADMIN_MFA": FixBlock(
        severity="high",
        gate="G1",
        control_id="CTRL_IDENTITY_ADMIN_MFA",
        title="Enforce MFA for administrative access",
        finding="Multi-factor authentication (MFA) is not enforced for network administrative access (or this is unknown).",
        policy_intent=(
            "Require MFA for all administrative access to firewalls, switches, Wi-Fi controllers, and management portals. "
            "Use app-based TOTP or hardware-backed methods where supported."
        ),
        technical_rationale=(
            "MFA reduces the impact of password compromise and significantly improves the security of privileged access."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),

    # --- Segmentation ---
    "CTRL_SEGMENTATION_GUEST_NOT_ISOLATED": FixBlock(
        severity="critical",
        gate="G2",
        control_id="CTRL_SEGMENTATION_GUEST_NOT_ISOLATED",
        title="Isolate guest access from internal systems",
        finding="Guest/untrusted devices can access internal systems (or this is unknown).",
        policy_intent=(
            "Place guest access on a dedicated network segment and enforce default-deny rules from guest to internal networks. "
            "Allow only necessary services (e.g., DHCP/DNS) and internet-bound traffic."
        ),
        technical_rationale=(
            "Guest devices should be treated as untrusted. Isolation reduces risk and limits visibility of internal assets."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_SEGMENTATION_FLAT_NETWORK": FixBlock(
        severity="critical",
        gate="G3",
        control_id="CTRL_SEGMENTATION_FLAT_NETWORK",
        title="Implement basic network segmentation",
        finding="The network is flat (no meaningful segmentation), or segmentation status is unknown.",
        policy_intent=(
            "Implement at least basic segmentation suitable for SMBs (e.g., Staff, Guest, IoT, and optionally Management). "
            "Enforce inter-segment access rules via firewall/L3 controls using least privilege."
        ),
        technical_rationale=(
            "Segmentation limits lateral movement and reduces blast radius when endpoints are compromised."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_SEGMENTATION_PARTIAL": FixBlock(
        severity="high",
        gate="G3",
        control_id="CTRL_SEGMENTATION_PARTIAL",
        title="Strengthen segmentation boundaries",
        finding="Segmentation exists but is partial (not all groups are separated).",
        policy_intent=(
            "Complete separation for at least Staff, Guest, and IoT. Ensure inter-segment policies are explicit and follow least privilege."
        ),
        technical_rationale=(
            "Partial segmentation can still allow unnecessary lateral movement. Clear boundaries reduce risk and simplify policy control."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_SEGMENTATION_IOT_WITH_CRITICAL": FixBlock(
        severity="high",
        gate=None,
        control_id="CTRL_SEGMENTATION_IOT_WITH_CRITICAL",
        title="Contain IoT/unmanaged devices",
        finding="IoT/unmanaged devices share the same network as business-critical systems.",
        policy_intent=(
            "Move IoT/unmanaged devices to a restricted segment and allow only explicitly required communication "
            "to necessary internal services."
        ),
        technical_rationale=(
            "IoT devices often have weaker security controls and may not be patched regularly; containment reduces exposure to critical systems."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),

    # --- Wireless ---
    "CTRL_WIRELESS_OPEN_OR_UNKNOWN": FixBlock(
        severity="high",
        gate=None,
        control_id="CTRL_WIRELESS_OPEN_OR_UNKNOWN",
        title="Use modern Wi-Fi security",
        finding="Corporate Wi-Fi security is open/unknown.",
        policy_intent=(
            "Use WPA2/WPA3 with a strong configuration. For business devices, consider WPA2/WPA3-Enterprise (802.1X) where feasible. "
            "Ensure guest access is separate from corporate access."
        ),
        technical_rationale=(
            "Open or unknown Wi-Fi security materially increases the risk of unauthorized network access."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_WIRELESS_PSK_ONLY": FixBlock(
        severity="medium",
        gate=None,
        control_id="CTRL_WIRELESS_PSK_ONLY",
        title="Harden Wi-Fi authentication and separation",
        finding="Corporate Wi-Fi uses a shared password (PSK).",
        policy_intent=(
            "Maintain strong PSK hygiene (rotation, unique per-site) and ensure separation between corporate and guest access. "
            "Where feasible, adopt 802.1X (Enterprise) for managed corporate devices."
        ),
        technical_rationale=(
            "Shared passwords are harder to manage and revoke. Strong separation and tighter identity controls reduce risk."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_WIRELESS_GUEST_CLIENT_ISOLATION": FixBlock(
        severity="medium",
        gate=None,
        control_id="CTRL_WIRELESS_GUEST_CLIENT_ISOLATION",
        title="Enable guest client isolation",
        finding="Guest Wi-Fi client isolation is disabled or unknown.",
        policy_intent=(
            "Enable guest client isolation to prevent guest devices from communicating directly with each other. "
            "Combine this with network-level guest isolation from internal systems."
        ),
        technical_rationale=(
            "Client isolation reduces opportunistic peer-to-peer attacks and limits lateral spread on guest networks."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),

    # --- Hygiene / Ops ---
    "CTRL_HYGIENE_UNUSED_PORTS": FixBlock(
        severity="medium",
        gate=None,
        control_id="CTRL_HYGIENE_UNUSED_PORTS",
        title="Restrict unused network ports",
        finding="Unused switch ports or wall jacks are not disabled/restricted (or this is unknown).",
        policy_intent=(
            "Disable unused switch ports or restrict them to a safe, non-production configuration. "
            "Document and review active ports periodically."
        ),
        technical_rationale=(
            "Open unused ports increase risk of unauthorized physical access and rogue devices joining the network."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_OPERATIONS_NO_BACKUPS": FixBlock(
        severity="high",
        gate="G4",
        control_id="CTRL_OPERATIONS_NO_BACKUPS",
        title="Establish configuration backups",
        finding="No recent configuration backups are available (or this is unknown).",
        policy_intent=(
            "Maintain backups of firewall/router/switch/Wi-Fi configurations. Store backups securely off-device "
            "and test restore procedures periodically."
        ),
        technical_rationale=(
            "Backups reduce downtime and enable fast recovery after device failure or misconfiguration."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_OPERATIONS_NO_LOGGING": FixBlock(
        severity="high",
        gate="G5",
        control_id="CTRL_OPERATIONS_NO_LOGGING",
        title="Enable basic logging and retention",
        finding="Network/firewall logs are not stored anywhere (or this is unknown).",
        policy_intent=(
            "Enable firewall/network logging and store logs locally or centrally with reasonable retention. "
            "Ensure logs cover authentication events, configuration changes, and security-relevant traffic."
        ),
        technical_rationale=(
            "Without logs, troubleshooting and incident response are severely limited, and security events may go undetected."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
    "CTRL_OPERATIONS_FIRMWARE_RARE": FixBlock(
        severity="medium",
        gate=None,
        control_id="CTRL_OPERATIONS_FIRMWARE_RARE",
        title="Adopt a regular update cadence",
        finding="Network device firmware/software is rarely updated (or update cadence is unknown).",
        policy_intent=(
            "Adopt a regular update process appropriate for SMBs (e.g., quarterly review with urgent security updates applied sooner). "
            "Track versions and changes."
        ),
        technical_rationale=(
            "Regular updates reduce exposure to known vulnerabilities and improve stability over time."
        ),
        references=[REF_CIS_IG1, REF_NIST_SMB, REF_VENDOR],
    ),
}


# -----------------------------
# Gate-level executive summaries (optional)
# Useful for the report header if gates fail.
# -----------------------------
GATE_EXEC_SUMMARIES: Dict[str, Dict[str, str]] = {
    "G1": {
        "title": "Perimeter Exposure",
        "summary": "Public exposure of administrative interfaces or internal services materially increases compromise risk.",
    },
    "G2": {
        "title": "Guest Isolation",
        "summary": "Guest or untrusted devices should not have access to internal systems.",
    },
    "G3": {
        "title": "Segmentation",
        "summary": "Basic segmentation is required to limit lateral movement and reduce blast radius.",
    },
    "G4": {
        "title": "Configuration Backups",
        "summary": "Backups are necessary for recovery and operational resilience.",
    },
    "G5": {
        "title": "Logging & Visibility",
        "summary": "Logging is necessary for troubleshooting and incident detection.",
    },
}


def generate_fix_blocks(failed_controls: List[str], gates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Inputs:
      failed_controls: list of control IDs from scoring.py
      gates: list of gate dicts (as in score_assessment_dict), each includes:
        { gate_id, failed, cap, reasons[] }

    Output:
      {
        "critical_fixes": [FixBlock...],   # severity critical/high, gate-related first
        "recommended_fixes": [FixBlock...],
        "gate_summaries": [{"gate_id","title","summary","reasons","cap"}...]
      }
    """
    # Gate summaries (for top of report)
    gate_summaries: List[Dict[str, Any]] = []
    for g in gates:
        gid = g.get("gate_id")
        if not gid:
            continue
        meta = GATE_EXEC_SUMMARIES.get(gid, {"title": gid, "summary": ""})
        if g.get("failed"):
            gate_summaries.append({
                "gate_id": gid,
                "title": meta["title"],
                "summary": meta["summary"],
                "cap": g.get("cap", None),
                "reasons": g.get("reasons", []),
            })

    # Build blocks in stable order (dedup, preserve input order)
    seen = set()
    blocks: List[FixBlock] = []
    for cid in failed_controls:
        if cid in seen:
            continue
        seen.add(cid)
        b = CONTROL_FIX_LIBRARY.get(cid)
        if b:
            blocks.append(b)

    # Sort blocks: gate-related critical/high first, then non-gate, then medium
    def sort_key(b: FixBlock):
        gate_rank = 0 if b.gate in ("G1", "G2", "G3", "G4", "G5") else 1
        severity_rank = {"critical": 0, "high": 1, "medium": 2}.get(b.severity, 3)
        return (severity_rank, gate_rank, b.control_id)

    blocks_sorted = sorted(blocks, key=sort_key)

    critical_fixes: List[Dict[str, Any]] = []
    recommended_fixes: List[Dict[str, Any]] = []

    for b in blocks_sorted:
        payload = asdict(b)
        if b.severity in ("critical", "high"):
            critical_fixes.append(payload)
        else:
            recommended_fixes.append(payload)

    return {
        "gate_summaries": gate_summaries,
        "critical_fixes": critical_fixes,
        "recommended_fixes": recommended_fixes,
    }
