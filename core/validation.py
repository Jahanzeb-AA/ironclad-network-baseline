from __future__ import annotations

import ast
import inspect
from types import ModuleType
from typing import Any, Dict, List, Optional, Set


VALID_SEVERITIES = {"high", "medium", "low"}


class BaselineValidationError(ValueError):
    """Raised when a baseline has mismatched questions, scoring, or fixes."""


def _question_maps(questions_json: Dict[str, Any]) -> tuple[Dict[str, Set[str]], Set[str], Set[str]]:
    option_keys_by_qid: Dict[str, Set[str]] = {}
    all_question_ids: Set[str] = set()
    scored_question_ids: Set[str] = set()

    for section in questions_json.get("sections", []):
        for question in section.get("questions", []):
            qid = question.get("id")
            if not qid:
                continue

            all_question_ids.add(qid)
            if question.get("scored"):
                scored_question_ids.add(qid)

            option_keys_by_qid[qid] = {
                str(option.get("key"))
                for option in question.get("options", [])
                if option.get("key") is not None
            }

    return option_keys_by_qid, all_question_ids, scored_question_ids


def _module_tree(module: ModuleType) -> ast.Module:
    return ast.parse(inspect.getsource(module))


def _is_answers_get(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "answers"
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    )


def _answers_get_qid(node: ast.AST) -> Optional[str]:
    if _is_answers_get(node):
        return str(node.args[0].value)  # type: ignore[index, union-attr]
    return None


def _string_literals(node: ast.AST) -> Set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values: Set[str] = set()
        for element in node.elts:
            values.update(_string_literals(element))
        return values
    return set()


def _validate_key(qid: str, key: str, option_keys_by_qid: Dict[str, Set[str]]) -> None:
    if qid not in option_keys_by_qid:
        raise BaselineValidationError(f"Unknown question ID in scoring: {qid}")

    if key not in option_keys_by_qid[qid]:
        raise BaselineValidationError(
            f"Unknown option key in scoring: {key} for question: {qid}"
        )


def _validate_scoring_references(
    scoring_module: ModuleType,
    option_keys_by_qid: Dict[str, Set[str]],
    all_question_ids: Set[str],
    scored_question_ids: Set[str],
) -> None:
    tree = _module_tree(scoring_module)
    answer_vars: Dict[str, str] = {}
    referenced_qids: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            qid = _answers_get_qid(node.value)
            if qid:
                referenced_qids.add(qid)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        answer_vars[target.id] = qid

                if len(node.value.args) >= 2:  # type: ignore[union-attr]
                    for key in _string_literals(node.value.args[1]):  # type: ignore[union-attr]
                        _validate_key(qid, key, option_keys_by_qid)

        direct_qid = _answers_get_qid(node)
        if direct_qid:
            referenced_qids.add(direct_qid)

    missing_scored = sorted(scored_question_ids - referenced_qids)
    if missing_scored:
        raise BaselineValidationError(
            "Scored question is not referenced in scoring logic: "
            + ", ".join(missing_scored)
        )

    unknown_qids = sorted(referenced_qids - all_question_ids)
    if unknown_qids:
        raise BaselineValidationError(
            "Unknown question ID in scoring: " + ", ".join(unknown_qids)
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            qids = _qids_for_expression(node.left, answer_vars)
            comparison_literals: Set[str] = set()

            for comparator in node.comparators:
                qids.update(_qids_for_expression(comparator, answer_vars))
                comparison_literals.update(_string_literals(comparator))

            comparison_literals.update(_string_literals(node.left))

            for qid in qids:
                for key in comparison_literals:
                    _validate_key(qid, key, option_keys_by_qid)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "_is_not_sure":
                for arg in node.args:
                    for qid in _qids_for_expression(arg, answer_vars):
                        _validate_key(qid, "NOT_SURE", option_keys_by_qid)


def _qids_for_expression(node: ast.AST, answer_vars: Dict[str, str]) -> Set[str]:
    if isinstance(node, ast.Name) and node.id in answer_vars:
        return {answer_vars[node.id]}

    qid = _answers_get_qid(node)
    if qid:
        return {qid}

    return set()


def _policy_mapping_ids(policy_module: ModuleType) -> Set[str]:
    library = getattr(policy_module, "CONTROL_FIX_LIBRARY", None)
    if not isinstance(library, dict):
        raise BaselineValidationError("Policy module is missing CONTROL_FIX_LIBRARY")

    policy_ids: Set[str] = set()
    for control_id, fix in library.items():
        policy_ids.add(str(control_id))
        if not isinstance(fix, dict):
            raise BaselineValidationError(
                f"Policy mapping must be a dictionary for control: {control_id}"
            )

        for required_key in ("id", "title", "why", "steps", "severity"):
            if required_key not in fix:
                raise BaselineValidationError(
                    f"Missing policy field '{required_key}' for control: {control_id}"
                )

        if str(fix.get("id")) != str(control_id):
            raise BaselineValidationError(
                f"Policy id does not match mapping key for control: {control_id}"
            )

        if str(fix.get("severity", "")).lower() not in VALID_SEVERITIES:
            raise BaselineValidationError(
                f"Invalid policy severity for control: {control_id}"
            )

        if not isinstance(fix.get("steps"), list):
            raise BaselineValidationError(
                f"Policy steps must be a list for control: {control_id}"
            )

    return policy_ids


def _base_answers(option_keys_by_qid: Dict[str, Set[str]]) -> Dict[str, str]:
    answers: Dict[str, str] = {}
    for qid, keys in option_keys_by_qid.items():
        preferred = ["YES", "NO", "FULL", "ENTERPRISE", "AUTOMATED", "REGULAR"]
        answers[qid] = next((key for key in preferred if key in keys), sorted(keys)[0])
    return answers


def _emitted_failed_controls(
    option_keys_by_qid: Dict[str, Set[str]],
    scoring_module: ModuleType,
) -> Set[str]:
    emitted: Set[str] = set()
    base = _base_answers(option_keys_by_qid)

    test_answer_sets: List[Dict[str, str]] = [base]
    for qid, keys in option_keys_by_qid.items():
        for key in keys:
            answers = dict(base)
            answers[qid] = key
            test_answer_sets.append(answers)

    for answers in test_answer_sets:
        result = scoring_module.score_assessment_dict(answers)
        for control in result.get("failed_controls", []):
            _validate_failed_control_schema(control)
            control_id = _failed_control_id(control)
            if control_id:
                emitted.add(control_id)

    return emitted


def _failed_control_id(control: Any) -> str:
    if isinstance(control, dict):
        return str(control.get("id", ""))
    return str(control)


def _validate_failed_control_schema(control: Any) -> None:
    if not isinstance(control, dict):
        return

    for required_key in ("id", "category", "severity"):
        if required_key not in control:
            raise BaselineValidationError(
                f"Missing failed control field '{required_key}' for control: {control}"
            )

    if not str(control.get("id", "")).strip():
        raise BaselineValidationError("Failed control id cannot be empty")

    if not str(control.get("category", "")).strip():
        raise BaselineValidationError(
            f"Failed control category cannot be empty for control: {control.get('id')}"
        )

    if str(control.get("severity", "")).lower() not in VALID_SEVERITIES:
        raise BaselineValidationError(
            f"Invalid failed control severity for control: {control.get('id')}"
        )


def validate_baseline(
    questions_json: Dict[str, Any],
    scoring_module: ModuleType,
    policy_module: ModuleType,
) -> None:
    option_keys_by_qid, all_question_ids, scored_question_ids = _question_maps(questions_json)

    _validate_scoring_references(
        scoring_module=scoring_module,
        option_keys_by_qid=option_keys_by_qid,
        all_question_ids=all_question_ids,
        scored_question_ids=scored_question_ids,
    )

    emitted_controls = _emitted_failed_controls(option_keys_by_qid, scoring_module)
    policy_ids = _policy_mapping_ids(policy_module)

    missing_policy = sorted(emitted_controls - policy_ids)
    if missing_policy:
        raise BaselineValidationError(
            "Missing policy mapping for control: " + ", ".join(missing_policy)
        )

    unused_policy = sorted(policy_ids - emitted_controls)
    if unused_policy:
        raise BaselineValidationError(
            "Unused policy mapping for control: " + ", ".join(unused_policy)
        )
