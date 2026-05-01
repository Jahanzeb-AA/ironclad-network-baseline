from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, Dict


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.validation import validate_baseline  # noqa: E402


BASELINES = {
    "network": {
        "questions_path": "modules/network/questions.json",
        "policy_module": "modules.network.policy_intent",
        "scoring_module": "core.scoring_engine",
    },
    "m365": {
        "questions_path": "modules/m365/questions.json",
        "policy_module": "modules.m365.policy_intent",
        "scoring_module": "core.m365_scoring_engine",
    },
    "endpoint": {
        "questions_path": "modules/endpoint/questions.json",
        "policy_module": "modules.endpoint.policy_intent",
        "scoring_module": "core.endpoint_scoring_engine",
    },
}


SECURE_ANSWERS = {
    "network": {
        "A1_DEVICE_COUNT": "U_26_100",
        "A2_VENDOR_PROFILE": "SINGLE",
        "A3_SITE_COUNT": "SINGLE_SITE",
        "B1_USER_GROUPS": "STAFF_ONLY",
        "B2_LOCAL_RESOURCES": "CLOUD_ONLY",
        "B3_BYOD_WIFI": "NO",
        "C1_WAN_ADMIN_EXPOSURE": "NO",
        "C2_REMOTE_ACCESS_METHOD": "VPN",
        "C3_ADMIN_MFA": "YES",
        "D1_GUEST_INTERNAL_ACCESS": "NO",
        "D2_VLAN_SEPARATION": "FULL",
        "D3_IOT_WITH_FINANCE": "NO",
        "E1_CORP_WIFI_SECURITY": "ENTERPRISE",
        "E2_GUEST_CLIENT_ISOLATION": "YES",
        "F1_UNUSED_PORTS_RESTRICTED": "YES",
        "F2_CONFIG_BACKUPS": "AUTOMATED",
        "F3_LOGGING_EXISTS": "YES",
        "F4_FIRMWARE_UPDATES": "REGULAR",
        "F5_DEFAULT_CREDENTIALS": "YES",
        "F6_DNS_FILTERING": "YES",
        "G1_PUBLIC_SERVICES_ISOLATED": "NA",
        "G2_PHYSICAL_SECURITY": "YES",
        "G3_SENSITIVE_DATA": "NO",
    },
    "m365": {
        "A1_USER_COUNT": "U_26_100",
        "A2_LICENSE_TYPE": "PREMIUM",
        "B1_MFA_ENFORCEMENT": "YES",
        "B2_LEGACY_AUTH": "YES",
        "B3_ADMIN_ACCOUNTS": "SEPARATE",
        "B4_CONDITIONAL_ACCESS": "YES",
        "B5_GLOBAL_ADMINS": "LT_3",
        "C1_AUTO_FORWARDING": "YES_BLOCKED",
        "C2_EXTERNAL_BANNER": "YES",
        "C3_SPAM_PHISHING": "YES",
        "C4_EMAIL_AUTH": "YES",
        "D1_SHAREPOINT_SHARING": "NO_RESTRICTED",
        "D2_M365_BACKUPS": "YES",
        "E1_AUDIT_LOGGING": "YES",
        "E2_DEVICE_COMPLIANCE": "YES",
        "F1_SENSITIVE_DATA": "NO",
    },
    "endpoint": {
        "A1_ENDPOINT_COUNT": "U_26_100",
        "A2_DEVICE_OWNERSHIP": "COMPANY_OWNED",
        "B1_ENDPOINT_PROTECTION": "YES_MANAGED",
        "B2_DISK_ENCRYPTION": "YES",
        "B3_FIREWALL_ENABLED": "YES",
        "C1_OS_PATCHING": "AUTOMATED",
        "C2_THIRD_PARTY_PATCHING": "AUTOMATED",
        "C3_UNSUPPORTED_OS": "NO",
        "D1_LOCAL_ADMIN": "NO",
        "D2_SCREEN_LOCK": "YES",
        "D3_REMOTE_ACCESS_MFA": "YES",
        "E1_SECURITY_ALERTS": "YES",
        "E2_DEVICE_INVENTORY": "YES",
        "F1_ENDPOINT_BACKUP": "YES",
        "F2_RESTORE_TESTING": "YES",
    },
}


MIXED_OVERRIDES = {
    "network": {
        "C2_REMOTE_ACCESS_METHOD": "PORT_FORWARDING",
        "D2_VLAN_SEPARATION": "PARTIAL",
        "E1_CORP_WIFI_SECURITY": "PSK",
        "F4_FIRMWARE_UPDATES": "RARE",
    },
    "m365": {
        "B1_MFA_ENFORCEMENT": "ADMIN_ONLY",
        "C4_EMAIL_AUTH": "PARTIAL",
        "D1_SHAREPOINT_SHARING": "YES_WITH_EXPIRATION",
        "E2_DEVICE_COMPLIANCE": "PARTIAL",
    },
    "endpoint": {
        "B1_ENDPOINT_PROTECTION": "YES_BASIC",
        "B2_DISK_ENCRYPTION": "PARTIAL",
        "C1_OS_PATCHING": "MANUAL",
        "D1_LOCAL_ADMIN": "LIMITED",
        "E1_SECURITY_ALERTS": "PARTIAL",
        "F1_ENDPOINT_BACKUP": "PARTIAL",
    },
}


def load_questions(relative_path: str) -> Dict[str, Any]:
    with (PROJECT_ROOT / relative_path).open("r", encoding="utf-8") as file:
        return json.load(file)


def option_keys_by_question(questions_json: Dict[str, Any]) -> Dict[str, set[str]]:
    option_keys: Dict[str, set[str]] = {}
    for section in questions_json.get("sections", []):
        for question in section.get("questions", []):
            qid = question.get("id")
            if not qid:
                continue
            option_keys[qid] = {
                str(option["key"])
                for option in question.get("options", [])
                if "key" in option
            }
    return option_keys


def all_not_sure_answers(option_keys: Dict[str, set[str]]) -> Dict[str, str]:
    answers: Dict[str, str] = {}
    for qid, keys in option_keys.items():
        answers[qid] = "NOT_SURE" if "NOT_SURE" in keys else sorted(keys)[0]
    return answers


def assert_answers_are_valid(
    baseline_name: str,
    case_name: str,
    answers: Dict[str, str],
    option_keys: Dict[str, set[str]],
) -> None:
    for qid, answer in answers.items():
        if qid not in option_keys:
            raise AssertionError(
                f"{baseline_name}/{case_name}: answer provided for unknown question {qid}"
            )
        if answer not in option_keys[qid]:
            raise AssertionError(
                f"{baseline_name}/{case_name}: invalid answer {answer} for question {qid}"
            )


def assert_score_result(result: Dict[str, Any], baseline_name: str, case_name: str) -> None:
    for key in (
        "final_score",
        "grade",
        "cap_applied",
        "failed_controls",
        "gates",
        "risk_level",
    ):
        if key not in result:
            raise AssertionError(f"{baseline_name}/{case_name}: missing result key {key}")

    if result["risk_level"] not in {"low", "medium", "high"}:
        raise AssertionError(f"{baseline_name}/{case_name}: invalid risk_level")

    if not isinstance(result["failed_controls"], list):
        raise AssertionError(f"{baseline_name}/{case_name}: failed_controls is not a list")

    for control in result["failed_controls"]:
        if not isinstance(control, dict):
            raise AssertionError(
                f"{baseline_name}/{case_name}: failed control is not structured"
            )
        for key in ("id", "category", "severity"):
            if key not in control:
                raise AssertionError(
                    f"{baseline_name}/{case_name}: failed control missing {key}"
                )
        if control["severity"] not in {"high", "medium", "low"}:
            raise AssertionError(
                f"{baseline_name}/{case_name}: invalid failed control severity"
            )


def run_scoring_case(
    baseline_name: str,
    case_name: str,
    answers: Dict[str, str],
    option_keys: Dict[str, set[str]],
    scoring_module: Any,
    policy_module: Any,
) -> None:
    assert_answers_are_valid(baseline_name, case_name, answers, option_keys)
    result = scoring_module.score_assessment_dict(answers)
    assert_score_result(result, baseline_name, case_name)

    fixes = policy_module.generate_fix_blocks(
        result["failed_controls"],
        result["gates"],
    )
    if not isinstance(fixes, list):
        raise AssertionError(f"{baseline_name}/{case_name}: fixes is not a list")

    failed_ids = {control["id"] for control in result["failed_controls"]}
    fix_ids = {fix.get("id") for fix in fixes}
    missing_fixes = failed_ids - fix_ids
    if missing_fixes:
        raise AssertionError(
            f"{baseline_name}/{case_name}: missing fixes for {sorted(missing_fixes)}"
        )


def run_baseline(baseline_name: str, config: Dict[str, str]) -> None:
    questions_json = load_questions(config["questions_path"])
    policy_module = importlib.import_module(config["policy_module"])
    scoring_module = importlib.import_module(config["scoring_module"])
    option_keys = option_keys_by_question(questions_json)

    validate_baseline(questions_json, scoring_module, policy_module)

    secure_answers = dict(SECURE_ANSWERS[baseline_name])
    not_sure_answers = all_not_sure_answers(option_keys)
    mixed_answers = dict(secure_answers)
    mixed_answers.update(MIXED_OVERRIDES[baseline_name])

    cases = {
        "all secure": secure_answers,
        "all NOT_SURE": not_sure_answers,
        "mixed answers": mixed_answers,
    }

    for case_name, answers in cases.items():
        run_scoring_case(
            baseline_name=baseline_name,
            case_name=case_name,
            answers=answers,
            option_keys=option_keys,
            scoring_module=scoring_module,
            policy_module=policy_module,
        )


def main() -> int:
    failures: list[str] = []

    for baseline_name, config in BASELINES.items():
        try:
            run_baseline(baseline_name, config)
            print(f"PASS {baseline_name}: validation and scoring cases passed")
        except Exception as exc:
            failures.append(f"{baseline_name}: {exc}")
            print(f"FAIL {baseline_name}: {exc}")

    if failures:
        print("\nBaseline validation failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nAll baseline validation tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
