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

def validate_traces_file(traces_path: Path, span_schema_path: Path) -> None:
    schema = load_json(span_schema_path)
    data = load_json(traces_path)
    if not isinstance(data, list):
        fail(f"Traces file {traces_path.name} must be a JSON array of spans.")
    for idx, span in enumerate(data):
        try:
            validate(instance=span, schema=schema)
        except ValidationError as e:
            fail(f"Trace span validation error in {traces_path.name} at index {idx}: {e.message}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Validate LLM security governance files against schemas")
    parser.add_argument("--policy", type=str, help="Path to a security policy JSON file to validate")
    parser.add_argument("--taxonomy", type=str, help="Path to a risk taxonomy JSON file to validate")
    parser.add_argument("--span-schema", type=str, help="Path to the core span JSON schema")
    
    args = parser.parse_args()
    
    policy_schema = ROOT / "security" / "schemas" / "policy.json"
    taxonomy_schema = ROOT / "security" / "schemas" / "risk_taxonomy.json"
    span_schema_path = Path(args.span_schema) if args.span_schema else ROOT.parent / "llm-systems-core" / "schemas" / "span.json"
    
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
                
            if path.name == "traces.json" or path.name.endswith("_traces.json"):
                validate_traces_file(path, span_schema_path)
                print(f"Successfully validated traces file: {path.relative_to(ROOT)}")
                found = True
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
            print("No security policy, risk taxonomy, or trace files found to validate.")

if __name__ == "__main__":
    main()
