from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from jsonschema import validate, ValidationError

ROOT = Path(__file__).resolve().parents[1]

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

def validate_file(file_path: Path, schema_path: Path, label: str) -> None:
    schema = load_json(schema_path)
    data = load_json(file_path)
    try:
        validate(instance=data, schema=schema)
    except ValidationError as e:
        fail(f"{label} validation error for {file_path.name}: {e.message}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Validate LLM security governance files against schemas")
    parser.add_argument("--policy", type=str, help="Path to a security policy JSON file to validate")
    parser.add_argument("--taxonomy", type=str, help="Path to a risk taxonomy JSON file to validate")
    
    args = parser.parse_args()
    
    policy_schema = ROOT / "security" / "schemas" / "policy.json"
    taxonomy_schema = ROOT / "security" / "schemas" / "risk_taxonomy.json"
    
    if args.policy:
        validate_file(Path(args.policy), policy_schema, "Policy")
        print(f"Successfully validated policy file: {args.policy}")
    elif args.taxonomy:
        validate_file(Path(args.taxonomy), taxonomy_schema, "Risk Taxonomy")
        print(f"Successfully validated taxonomy file: {args.taxonomy}")
    else:
        # Find all JSON files in security/ excluding schemas/
        sec_dir = ROOT / "security"
        found = False
        for path in sec_dir.rglob("*.json"):
            if "schemas" in path.parts:
                continue
                
            name_lower = path.name.lower()
            if "policy" in name_lower:
                validate_file(path, policy_schema, "Policy")
                print(f"Successfully validated policy file: {path.relative_to(ROOT)}")
                found = True
            elif "taxonomy" in name_lower or "risk" in name_lower:
                validate_file(path, taxonomy_schema, "Risk Taxonomy")
                print(f"Successfully validated taxonomy file: {path.relative_to(ROOT)}")
                found = True
                
        if not found:
            print("No security policy or risk taxonomy files found to validate.")

if __name__ == "__main__":
    main()
