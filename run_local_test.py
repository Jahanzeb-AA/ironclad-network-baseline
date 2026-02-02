from scoring import score_assessment_dict
from policy_intent import generate_fix_blocks
from report_builder import build_report_html

# Example answers (intentionally weak)
answers = {
    "A1_DEVICE_COUNT": "R_200_500",
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
    "F4_FIRMWARE_UPDATES": "RARE"
}

result = score_assessment_dict(answers)
fixes = generate_fix_blocks(result["failed_controls"], result["gates"])

html = build_report_html(result, fixes, answers)

with open("report.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Generated report.html - open it in your browser.")
print("Final score:", result["final_score"], "Grade:", result["grade"])
