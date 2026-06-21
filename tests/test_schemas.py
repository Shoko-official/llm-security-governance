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

if __name__ == "__main__":
    unittest.main()
