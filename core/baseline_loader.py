from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any, Dict


APP_ROOT = Path(__file__).resolve().parents[1]


BASELINE_CONFIG: Dict[str, Dict[str, str]] = {
    "network": {
        "name": "Network Baseline (SMB)",
        "questions_path": "modules/network/questions.json",
        "policy_module": "modules.network.policy_intent",
        "scoring_module": "core.scoring_engine",
    },
    "m365": {
        "name": "Microsoft 365 Baseline",
        "questions_path": "modules/m365/questions.json",
        "policy_module": "modules.m365.policy_intent",
        "scoring_module": "core.m365_scoring_engine",
    },
    "endpoint": {
        "name": "Endpoint Security Baseline",
        "questions_path": "modules/endpoint/questions.json",
        "policy_module": "modules.endpoint.policy_intent",
        "scoring_module": "core.endpoint_scoring_engine",
    },
    "ad": {
        "name": "Active Directory (on-prem)",
        "questions_path": "modules/ad/questions.json",
        "policy_module": "modules.ad.policy_intent",
        "scoring_module": "core.ad_scoring_engine",
    },
}


def _title_from_key(key: str) -> str:
    return key.replace("_", " ").replace("-", " ").title()


def _default_config_for_module(module_dir: Path) -> Dict[str, str]:
    baseline_key = module_dir.name

    return {
        "name": f"{_title_from_key(baseline_key)} Baseline",
        "questions_path": f"modules/{baseline_key}/questions.json",
        "policy_module": f"modules.{baseline_key}.policy_intent",
        "scoring_module": f"core.{baseline_key}_scoring_engine",
    }


def get_baseline_config() -> Dict[str, Dict[str, str]]:
    config = dict(BASELINE_CONFIG)
    modules_root = APP_ROOT / "modules"

    if not modules_root.exists():
        return config

    for module_dir in modules_root.iterdir():
        if not module_dir.is_dir():
            continue
        if not (module_dir / "questions.json").exists():
            continue

        config.setdefault(module_dir.name, _default_config_for_module(module_dir))

    return config


def list_baselines() -> Dict[str, str]:
    return {
        baseline_key: config["name"]
        for baseline_key, config in get_baseline_config().items()
    }


def _load_questions(relative_path: str) -> Dict[str, Any]:
    path = APP_ROOT / relative_path
    if not path.exists():
        raise FileNotFoundError(f"Question file not found: {relative_path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_baseline(name: str) -> Dict[str, Any]:
    config = get_baseline_config()
    if name not in config:
        available = ", ".join(sorted(config)) or "none"
        raise ValueError(f"Unknown baseline '{name}'. Available baselines: {available}")

    baseline_config = config[name]
    questions = _load_questions(baseline_config["questions_path"])
    scoring_module: ModuleType = importlib.import_module(
        baseline_config["scoring_module"]
    )
    policy_module: ModuleType = importlib.import_module(baseline_config["policy_module"])

    return {
        "key": name,
        "name": baseline_config["name"],
        "questions": questions,
        "scoring_module": scoring_module,
        "policy_module": policy_module,
    }
