from core.scoring_engine import score_assessment_dict
from modules.network.policy_intent import generate_fix_blocks
from reporting.report_builder import build_report_html


answers = {
    "A1_DEVICE_COUNT": "U_101_300",
    "B2_LOCAL_RESOURCES": "LOCAL_REQUIRED",
    "C1_WAN_ADMIN_EXPOSURE": "YES",
    "C2_REMOTE_ACCESS_METHOD": "PORT_FORWARDING",
    "C3_ADMIN_MFA": "NO",
    "D1_GUEST_INTERNAL_ACCESS": "YES",
    "D2_VLAN_SEPARATION": "FLAT",
    "D3_IOT_WITH_FINANCE": "YES",
    "E1_CORP_WIFI_SECURITY": "OPEN_OR_UNKNOWN",
    "E2_GUEST_CLIENT_ISOLATION": "NO",
    "F1_UNUSED_PORTS_RESTRICTED": "NO",
    "F2_CONFIG_BACKUPS": "NONE",
    "F3_LOGGING_EXISTS": "NO",
    "F4_FIRMWARE_UPDATES": "RARE",
    "F5_DEFAULT_CREDENTIALS": "NO",
    "G3_SENSITIVE_DATA": "YES",
}

result = score_assessment_dict(answers)
fixes = generate_fix_blocks(result["failed_controls"], result["gates"])
html = build_report_html(result, fixes, answers)

with open("report.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Generated report.html - open it in your browser.")
print("Final score:", result["final_score"], "Grade:", result["grade"])
print("Failed controls:", len(result["failed_controls"]))
print("Fixes:", len(fixes))
