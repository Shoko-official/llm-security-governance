from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

class SecurityFilter:
    def __init__(self, policy_data: Dict[str, Any]) -> None:
        self.version: str = policy_data.get("version", "1.0.0")
        self.denied_tool_prefixes: List[str] = policy_data.get("denied_tool_prefixes", [])
        self.denied_commands: List[str] = policy_data.get("denied_commands", [])
        self.prompt_injection_patterns: List[re.Pattern] = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in policy_data.get("prompt_injection_patterns", [])
        ]

    @classmethod
    def load_from_file(cls, policy_path: Path) -> SecurityFilter:
        with open(policy_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if the tool name starts with any denied prefix."""
        for prefix in self.denied_tool_prefixes:
            if tool_name.startswith(prefix):
                return False
        return True

    def is_command_allowed(self, command: str) -> bool:
        """Check if the command contains or starts with any blocked commands."""
        cmd_stripped = command.strip()
        for denied in self.denied_commands:
            if cmd_stripped.startswith(denied) or f" {denied}" in cmd_stripped or f";{denied}" in cmd_stripped:
                return False
        return True

    def is_prompt_safe(self, prompt: str) -> bool:
        """Check if prompt contains any prompt injection pattern."""
        for pattern in self.prompt_injection_patterns:
            if pattern.search(prompt):
                return False
        return True

    def check_tool_call(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if a tool call is safe.
        Returns True if safe, False if unsafe.
        """
        if not self.is_tool_allowed(tool_name):
            return False

        if arguments:
            for key, val in arguments.items():
                if isinstance(val, str):
                    if key.lower() in {"command", "cmd", "command_line", "args"}:
                        if not self.is_command_allowed(val):
                            return False
                    if not self.is_prompt_safe(val):
                        return False
        return True
