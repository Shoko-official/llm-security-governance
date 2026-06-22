from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
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
        self.last_spans: List[Dict[str, Any]] = []
        self.current_trace_id: Optional[str] = None
        self._parent_span_id: str = "N/A"

    def reset_trace(self) -> None:
        self.current_trace_id = None
        self.last_spans = []
        self._parent_span_id = "N/A"

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
        """Check if prompt contains any prompt injection pattern (including base64 encoding)."""
        start_time = datetime.now(timezone.utc)
        if self.current_trace_id is None:
            self.current_trace_id = uuid.uuid4().hex
            
        result = True
        
        # 1. Normal scan
        for pattern in self.prompt_injection_patterns:
            if pattern.search(prompt):
                result = False
                break
                
        if result:
            import base64
            b64_pattern = re.compile(r'[A-Za-z0-9+/=]{8,}')
            for match in b64_pattern.finditer(prompt):
                try:
                    decoded = base64.b64decode(match.group(0)).decode("utf-8", errors="ignore")
                    for pattern in self.prompt_injection_patterns:
                        if pattern.search(decoded):
                            result = False
                            break
                except Exception:
                    pass
                if not result:
                    break
                    
        if result:
            # 3. Adversarial framing patterns
            framing_patterns = [
                r"\[system\b", r"\bsystem\s*:\s*", r"\buser\s*:\s*", r"\bassistant\s*:\s*",
                r"roleplay\b", r"pretend you are", r"assume the role of"
            ]
            for fp in framing_patterns:
                if re.search(fp, prompt, re.IGNORECASE):
                    result = False
                    break

        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000.0
        
        span = {
            "span_id": uuid.uuid4().hex[:16],
            "trace_id": self.current_trace_id,
            "parent_span_id": self._parent_span_id,
            "name": "is_prompt_safe",
            "start_time": start_time.isoformat().replace("+00:00", "Z"),
            "end_time": end_time.isoformat().replace("+00:00", "Z"),
            "duration_ms": round(duration_ms, 4),
            "service_name": "security",
            "status": "ok",
            "attributes": {
                "safe": result
            }
        }
        self.last_spans.append(span)
        return result

    def check_tool_call(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if a tool call is safe.
        Returns True if safe, False if unsafe.
        """
        start_time = datetime.now(timezone.utc)
        if self.current_trace_id is None:
            self.current_trace_id = uuid.uuid4().hex
            
        span_id = uuid.uuid4().hex[:16]
        old_parent = self._parent_span_id
        self._parent_span_id = span_id
        
        result = True
        
        if not self.is_tool_allowed(tool_name):
            result = False
        else:
            if arguments:
                for key, val in arguments.items():
                    if isinstance(val, str):
                        key_lower = key.lower()
                        if any(k in key_lower for k in {"command", "cmd", "args", "arg", "line"}):
                            if not self.is_command_allowed(val):
                                result = False
                                break
                        if not self.is_prompt_safe(val):
                            result = False
                            break
                            
        self._parent_span_id = old_parent
        
        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000.0
        
        span = {
            "span_id": span_id,
            "trace_id": self.current_trace_id,
            "parent_span_id": old_parent,
            "name": "check_tool_call",
            "start_time": start_time.isoformat().replace("+00:00", "Z"),
            "end_time": end_time.isoformat().replace("+00:00", "Z"),
            "duration_ms": round(duration_ms, 4),
            "service_name": "security",
            "status": "ok",
            "attributes": {
                "tool_name": tool_name,
                "safe": result
            }
        }
        self.last_spans.append(span)
        return result
