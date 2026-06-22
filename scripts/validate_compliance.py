from __future__ import annotations

"""validate_compliance.py - Validate LLM security filter against compliance rules.

Loads compliance verification rules, checks security policies and filters,
runs injection vector tests, and generates a compliance report.
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from jsonschema import validate, ValidationError
except ImportError:
    print("Error: jsonschema is required. Run: pip install jsonschema", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security.filter import SecurityFilter


def fail(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


def load_json(path: Path) -> dict:
    if not path.is_file():
        fail(f"File not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        fail(f"Failed to parse JSON from {path}: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify LLM security compliance against verification rules"
    )
    parser.add_argument("--rules", type=str, help="Path to compliance rules JSON file")
    parser.add_argument("--schema", type=str, help="Path to compliance rules JSON schema")
    parser.add_argument("--policy", type=str, help="Path to security policy JSON file")
    parser.add_argument("--vectors", type=str, help="Path to prompt injection vectors JSON file")
    parser.add_argument("--report", type=str, help="Path to output compliance report JSON file")

    args = parser.parse_args()

    # Default paths
    rules_path = Path(args.rules) if args.rules else ROOT / "security" / "mock_compliance_rules.json"
    schema_path = (
        Path(args.schema) if args.schema else ROOT / "security" / "schemas" / "compliance_rules.json"
    )
    policy_path = Path(args.policy) if args.policy else ROOT / "security" / "mock_policy.json"
    vectors_path = (
        Path(args.vectors) if args.vectors else ROOT / "security" / "mock_injection_vectors.json"
    )
    report_path = Path(args.report) if args.report else ROOT / "security" / "compliance_report.json"

    # 1. Load and validate rules against schema
    rules = load_json(rules_path)
    schema = load_json(schema_path)

    try:
        validate(instance=rules, schema=schema)
    except ValidationError as e:
        fail(f"Compliance rules schema validation failed: {e.message}")

    # 2. Load policy and safety filter
    policy_data = load_json(policy_path)
    try:
        sec_filter = SecurityFilter(policy_data)
    except Exception as e:
        fail(f"Failed to initialize SecurityFilter: {e}")

    # 3. Load vectors and run tests
    vectors_data = load_json(vectors_path)
    vectors = vectors_data.get("vectors", [])

    total_safe = 0
    false_positives = 0
    total_unsafe = 0
    blocked_unsafe = 0

    results = []

    for vec in vectors:
        prompt = vec.get("prompt", "")
        expected_safe = vec.get("expected_safe", True)
        is_safe = sec_filter.is_prompt_safe(prompt)

        passed = True
        if expected_safe:
            total_safe += 1
            if not is_safe:
                false_positives += 1
                passed = False
        else:
            total_unsafe += 1
            if not is_safe:
                blocked_unsafe += 1
            else:
                passed = False

        results.append(
            {
                "prompt": prompt,
                "expected_safe": expected_safe,
                "actual_safe": is_safe,
                "passed": passed,
                "category": vec.get("category", "unknown"),
            }
        )

    # Calculate actual rates
    block_rate = blocked_unsafe / total_unsafe if total_unsafe > 0 else 1.0
    false_positive_rate = false_positives / total_safe if total_safe > 0 else 0.0

    # 4. Evaluate compliance rules
    checks_config = rules.get("checks", {})
    failed_checks = []

    # Check 1: safety filter active
    if checks_config.get("require_filter_active"):
        if not hasattr(sec_filter, "is_prompt_safe"):
            failed_checks.append("require_filter_active")

    # Check 2: command blocking enabled
    if checks_config.get("require_command_blocking"):
        if not sec_filter.denied_commands:
            failed_checks.append("require_command_blocking")

    # Check 3: tool prefix blocking enabled
    if checks_config.get("require_tool_prefix_blocking"):
        if not sec_filter.denied_tool_prefixes:
            failed_checks.append("require_tool_prefix_blocking")

    # Check 4: minimum injection block rate
    min_block_rate = checks_config.get("minimum_injection_block_rate", 0.0)
    if block_rate < min_block_rate:
        failed_checks.append(
            f"minimum_injection_block_rate (actual: {block_rate:.2f}, required: >= {min_block_rate:.2f})"
        )

    # Check 5: allowed false positive rate
    max_fpr = checks_config.get("allowed_false_positive_rate", 1.0)
    if false_positive_rate > max_fpr:
        failed_checks.append(
            f"allowed_false_positive_rate (actual: {false_positive_rate:.2f}, required: <= {max_fpr:.2f})"
        )

    # 5. Generate Compliance Report
    compliance_passed = len(failed_checks) == 0
    report = {
        "rule_id": rules.get("rule_id"),
        "enforcement_level": rules.get("enforcement_level"),
        "compliance_status": "PASSED" if compliance_passed else "FAILED",
        "failed_checks": failed_checks,
        "metrics": {
            "total_prompts_checked": len(vectors),
            "total_safe_prompts": total_safe,
            "false_positives": false_positives,
            "actual_false_positive_rate": false_positive_rate,
            "total_unsafe_prompts": total_unsafe,
            "blocked_unsafe_prompts": blocked_unsafe,
            "actual_injection_block_rate": block_rate,
        },
        "details": results,
    }

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Compliance report saved to {report_path.relative_to(ROOT)}")
    except Exception as e:
        print(f"Warning: Failed to save compliance report: {e}", file=sys.stderr)

    # Report results
    print("\n--- Compliance Verification ---")
    print(f"Status:             {report['compliance_status']}")
    print(f"Injection Block:    {block_rate:.2%} (Target: >= {min_block_rate:.0%})")
    print(f"False Positive:     {false_positive_rate:.2%} (Target: <= {max_fpr:.0%})")
    print("--------------------------------")

    if not compliance_passed:
        fail(f"Compliance verification failed on: {', '.join(failed_checks)}")

    print("Compliance verification successful!")
    sys.exit(0)


if __name__ == "__main__":
    main()
