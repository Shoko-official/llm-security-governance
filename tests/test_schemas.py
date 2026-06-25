import sys
from pathlib import Path
import json
import unittest
import jsonschema

# Insert ROOT in sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

class TestSecuritySchemas(unittest.TestCase):
    def setUp(self):
        self.policy_schema_path = ROOT / "security" / "schemas" / "policy.json"
        self.taxonomy_schema_path = ROOT / "security" / "schemas" / "risk_taxonomy.json"
        
        with open(self.policy_schema_path, "r", encoding="utf-8") as f:
            self.policy_schema = json.load(f)
            
        with open(self.taxonomy_schema_path, "r", encoding="utf-8") as f:
            self.taxonomy_schema = json.load(f)

    def test_mock_policy_valid(self):
        mock_policy_path = ROOT / "security" / "mock_policy.json"
        with open(mock_policy_path, "r", encoding="utf-8") as f:
            mock_policy = json.load(f)
        jsonschema.validate(instance=mock_policy, schema=self.policy_schema)

    def test_mock_taxonomy_valid(self):
        mock_taxonomy_path = ROOT / "security" / "mock_risk_taxonomy.json"
        with open(mock_taxonomy_path, "r", encoding="utf-8") as f:
            mock_taxonomy = json.load(f)
        jsonschema.validate(instance=mock_taxonomy, schema=self.taxonomy_schema)

    def test_invalid_policy(self):
        # Missing required field 'version'
        invalid_policy = {
            "denied_tool_prefixes": ["sys"],
            "denied_commands": ["rm"],
            "prompt_injection_patterns": ["ignore"]
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_policy, schema=self.policy_schema)

        # Extra property (additionalProperties is false)
        invalid_policy_extra = {
            "version": "1.0.0",
            "denied_tool_prefixes": ["sys"],
            "denied_commands": ["rm"],
            "prompt_injection_patterns": ["ignore"],
            "extra_field": 123
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_policy_extra, schema=self.policy_schema)

    def test_invalid_taxonomy(self):
        # Invalid risk pattern for ID (should be RISK-001, etc)
        invalid_taxonomy = {
            "risks": [
                {
                    "id": "INVALID-ID",
                    "name": "Prompt Injection",
                    "severity": "high",
                    "description": "description"
                }
            ]
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_taxonomy, schema=self.taxonomy_schema)

        # Invalid severity level
        invalid_taxonomy_severity = {
            "risks": [
                {
                    "id": "RISK-001",
                    "name": "Prompt Injection",
                    "severity": "ultra-critical",
                    "description": "description"
                }
            ]
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_taxonomy_severity, schema=self.taxonomy_schema)

    def test_mock_traces_valid(self):
        from scripts.validate_security import validate_traces_file
        traces_path = ROOT / "security" / "traces.json"
        span_schema_path = ROOT.parent / "llm-systems-core" / "schemas" / "span.json"
        # Should not raise any exception
        validate_traces_file(traces_path, span_schema_path)

    def test_invalid_traces_detection(self):
        from scripts.validate_security import validate_traces_file, SecurityValidationError
        import tempfile
        
        span_schema_path = ROOT.parent / "llm-systems-core" / "schemas" / "span.json"
        
        # 1. Invalid JSON structure (not list)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"span_id": "123"}')
            temp_name = Path(f.name)
        try:
            with self.assertRaises(SecurityValidationError):
                validate_traces_file(temp_name, span_schema_path)
        finally:
            try:
                temp_name.unlink()
            except Exception:
                pass
            
        # 2. Missing safe attribute in is_prompt_safe
        invalid_trace_1 = [
            {
                "span_id": "43aaa323839141f7",
                "trace_id": "7f0cd39a843b4d6286ab92b74fbcb421",
                "parent_span_id": "N/A",
                "name": "is_prompt_safe",
                "start_time": "2026-06-25T22:12:34.349700Z",
                "end_time": "2026-06-25T22:12:34.349700Z",
                "duration_ms": 0.0,
                "service_name": "security",
                "status": "ok",
                "attributes": {
                    "scan_type": "input_prompt"
                }
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_trace_1, f)
            temp_name = Path(f.name)
        try:
            with self.assertRaises(SecurityValidationError) as ctx:
                validate_traces_file(temp_name, span_schema_path)
            self.assertIn("missing 'safe' attribute", str(ctx.exception))
        finally:
            try:
                temp_name.unlink()
            except Exception:
                pass

        # 3. Invalid safe type (not boolean)
        invalid_trace_2 = [
            {
                "span_id": "43aaa323839141f7",
                "trace_id": "7f0cd39a843b4d6286ab92b74fbcb421",
                "parent_span_id": "N/A",
                "name": "is_prompt_safe",
                "start_time": "2026-06-25T22:12:34.349700Z",
                "end_time": "2026-06-25T22:12:34.349700Z",
                "duration_ms": 0.0,
                "service_name": "security",
                "status": "ok",
                "attributes": {
                    "safe": "yes"
                }
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_trace_2, f)
            temp_name = Path(f.name)
        try:
            with self.assertRaises(SecurityValidationError) as ctx:
                validate_traces_file(temp_name, span_schema_path)
            self.assertIn("'safe' attribute must be boolean", str(ctx.exception))
        finally:
            try:
                temp_name.unlink()
            except Exception:
                pass
            
        # 4. Unknown security name span
        invalid_trace_3 = [
            {
                "span_id": "43aaa323839141f7",
                "trace_id": "7f0cd39a843b4d6286ab92b74fbcb421",
                "parent_span_id": "N/A",
                "name": "unknown_operation",
                "start_time": "2026-06-25T22:12:34.349700Z",
                "end_time": "2026-06-25T22:12:34.349700Z",
                "duration_ms": 0.0,
                "service_name": "security",
                "status": "ok",
                "attributes": {}
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_trace_3, f)
            temp_name = Path(f.name)
        try:
            with self.assertRaises(SecurityValidationError) as ctx:
                validate_traces_file(temp_name, span_schema_path)
            self.assertIn("unknown name for security service", str(ctx.exception))
        finally:
            try:
                temp_name.unlink()
            except Exception:
                pass

if __name__ == "__main__":
    unittest.main()
