from __future__ import annotations

import argparse
import json
from pathlib import Path

def generate_mock_data(policy_path: Path, taxonomy_path: Path) -> None:
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    taxonomy_path.parent.mkdir(parents=True, exist_ok=True)

    mock_policy = {
        "version": "1.0.0",
        "denied_tool_prefixes": ["system", "unsafe_execute", "file_delete"],
        "denied_commands": ["rm -rf", "format", "sh", "bash", "powershell"],
        "prompt_injection_patterns": [
            "ignore previous instructions",
            "system override",
            "you are now in developer mode",
            "jailbreak"
        ]
    }

    mock_taxonomy = {
        "risks": [
            {
                "id": "RISK-001",
                "name": "Prompt Injection",
                "severity": "high",
                "description": "User prompts that override system instructions or modify safety guards."
            },
            {
                "id": "RISK-002",
                "name": "Unsafe Command Execution",
                "severity": "critical",
                "description": "Execution of blocked system commands or files that modify the local workspace."
            },
            {
                "id": "RISK-003",
                "name": "Unauthorized Data Leak",
                "severity": "medium",
                "description": "Leak of api keys, credentials, or sensitive files in output responses."
            }
        ]
    }

    with open(policy_path, "w", encoding="utf-8") as f:
        json.dump(mock_policy, f, indent=2)

    with open(taxonomy_path, "w", encoding="utf-8") as f:
        json.dump(mock_taxonomy, f, indent=2)

    print(f"Generated mock policy file: {policy_path}")
    print(f"Generated mock taxonomy file: {taxonomy_path}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic security policy and taxonomy logs for testing")
    parser.add_argument("--policy-out", type=str, help="Destination path for the mock policy JSON")
    parser.add_argument("--taxonomy-out", type=str, help="Destination path for the mock taxonomy JSON")
    
    args = parser.parse_args()
    
    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent
    
    policy_path = Path(args.policy_out) if args.policy_out else root_dir / "security" / "mock_policy.json"
    taxonomy_path = Path(args.taxonomy_out) if args.taxonomy_out else root_dir / "security" / "mock_risk_taxonomy.json"
    
    generate_mock_data(policy_path, taxonomy_path)

if __name__ == "__main__":
    main()
