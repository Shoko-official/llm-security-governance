from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add ROOT to sys.path to resolve security modules
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security.filter import SecurityFilter

def main() -> None:
    parser = argparse.ArgumentParser(description="CLI tool to check if tool calls or prompts violate security policy")
    parser.add_argument("--policy", type=str, help="Path to the security policy JSON file")
    parser.add_argument("--tool", type=str, help="Tool name to check")
    parser.add_argument("--args", type=str, help="JSON string representing the tool arguments")
    parser.add_argument("--prompt", type=str, help="Prompt string to check")
    
    args = parser.parse_args()
    
    policy_path = Path(args.policy) if args.policy else ROOT / "security" / "mock_policy.json"
    
    if not policy_path.is_file():
        print(f"Error: Policy file not found: {policy_path}", file=sys.stderr)
        sys.exit(2)
        
    try:
        sec_filter = SecurityFilter.load_from_file(policy_path)
    except Exception as e:
        print(f"Error: Failed to load policy: {e}", file=sys.stderr)
        sys.exit(2)
        
    blocked = False
    
    if args.prompt:
        if not sec_filter.is_prompt_safe(args.prompt):
            print("BLOCKED: Prompt contains blocked injection pattern.")
            blocked = True
        else:
            print("SAFE: Prompt contains no injection patterns.")
        
    if args.tool:
        tool_args = None
        if args.args:
            try:
                tool_args = json.loads(args.args)
            except Exception as e:
                print(f"Error: Failed to parse arguments JSON: {e}", file=sys.stderr)
                sys.exit(2)
        
        if not sec_filter.check_tool_call(args.tool, tool_args):
            print(f"BLOCKED: Tool call '{args.tool}' is unsafe or contains blocked parameters.")
            blocked = True
        else:
            print(f"SAFE: Tool call '{args.tool}' is allowed.")
        
    if not args.prompt and not args.tool:
        print("Error: Specify at least --prompt or --tool to check.", file=sys.stderr)
        parser.print_help()
        sys.exit(2)
        
    if blocked:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
