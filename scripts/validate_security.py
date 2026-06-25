from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from jsonschema import validate, ValidationError

ROOT = Path(__file__).resolve().parents[1]

class SecurityValidationError(Exception):
    pass

def load_json(path: Path) -> dict:
    if not path.is_file():
        raise SecurityValidationError(f"File not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise SecurityValidationError(f"Failed to parse JSON from {path}: {e}")

def validate_file(file_path: Path, schema_path: Path, label: str) -> None:
    schema = load_json(schema_path)
    data = load_json(file_path)
    try:
        validate(instance=data, schema=schema)
    except ValidationError as e:
        raise SecurityValidationError(f"{label} validation error for {file_path.name}: {e.message}")

def validate_traces_file(traces_path: Path, span_schema_path: Path) -> None:
    schema = load_json(span_schema_path)
    data = load_json(traces_path)
    if not isinstance(data, list):
        raise SecurityValidationError(f"Traces file {traces_path.name} must be a JSON array of spans.")
    for idx, span in enumerate(data):
        try:
            validate(instance=span, schema=schema)
        except ValidationError as e:
            raise SecurityValidationError(f"Trace span validation error in {traces_path.name} at index {idx}: {e.message}")
            
        # Agentic security-specific validation checks
        if span.get("service_name") == "security":
            name = span.get("name")
            attrs = span.get("attributes", {})
            if name == "is_prompt_safe":
                if "safe" not in attrs:
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} is 'is_prompt_safe' but missing 'safe' attribute.")
                if not isinstance(attrs["safe"], bool):
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} 'safe' attribute must be boolean.")
                if "scan_type" in attrs and attrs["scan_type"] != "input_prompt":
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} has invalid 'scan_type': {attrs['scan_type']}")
            elif name == "check_tool_call":
                if "safe" not in attrs:
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} is 'check_tool_call' but missing 'safe' attribute.")
                if not isinstance(attrs["safe"], bool):
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} 'safe' attribute must be boolean.")
                if "tool_name" not in attrs:
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} is 'check_tool_call' but missing 'tool_name' attribute.")
            elif name == "check_tool_response":
                if "injection_detected" not in attrs:
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} is 'check_tool_response' but missing 'injection_detected' attribute.")
                if not isinstance(attrs["injection_detected"], bool):
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} 'injection_detected' attribute must be boolean.")
                if "tool_name" not in attrs:
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} is 'check_tool_response' but missing 'tool_name' attribute.")
                if "scan_type" in attrs and attrs["scan_type"] != "tool_output":
                    raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} has invalid 'scan_type': {attrs['scan_type']}")
            else:
                raise SecurityValidationError(f"Trace span at index {idx} in {traces_path.name} has unknown name for security service: {name}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Validate LLM security governance files against schemas")
    parser.add_argument("--policy", type=str, help="Path to a security policy JSON file to validate")
    parser.add_argument("--taxonomy", type=str, help="Path to a risk taxonomy JSON file to validate")
    parser.add_argument("--span-schema", type=str, help="Path to the core span JSON schema")
    
    args = parser.parse_args()
    
    policy_schema = ROOT / "security" / "schemas" / "policy.json"
    taxonomy_schema = ROOT / "security" / "schemas" / "risk_taxonomy.json"
    span_schema_path = Path(args.span_schema) if args.span_schema else ROOT.parent / "llm-systems-core" / "schemas" / "span.json"
    
    try:
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
    except SecurityValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
