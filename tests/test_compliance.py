import sys
from pathlib import Path
import json
import unittest
import jsonschema
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

class TestCompliance(unittest.TestCase):
    def setUp(self):
        self.schema_path = ROOT / "security" / "schemas" / "compliance_rules.json"
        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

    def test_mock_rules_valid(self):
        mock_rules_path = ROOT / "security" / "mock_compliance_rules.json"
        with open(mock_rules_path, "r", encoding="utf-8") as f:
            mock_rules = json.load(f)
        jsonschema.validate(instance=mock_rules, schema=self.schema)

    def test_invalid_rules(self):
        # Missing rule_id
        invalid = {
            "description": "Test",
            "enforcement_level": "low",
            "checks": {
                "require_filter_active": True,
                "allowed_false_positive_rate": 0.05,
                "minimum_injection_block_rate": 0.95,
                "require_command_blocking": True,
                "require_tool_prefix_blocking": True
            }
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid, schema=self.schema)

        # Invalid enforcement level
        invalid_level = {
            "rule_id": "test-rule",
            "description": "Test",
            "enforcement_level": "ultra-critical",
            "checks": {
                "require_filter_active": True,
                "allowed_false_positive_rate": 0.05,
                "minimum_injection_block_rate": 0.95,
                "require_command_blocking": True,
                "require_tool_prefix_blocking": True
            }
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_level, schema=self.schema)

    def test_compliance_script_runs(self):
        script_path = ROOT / "scripts" / "validate_compliance.py"
        res = subprocess.run([sys.executable, str(script_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
        self.assertIn("Compliance verification successful", res.stdout)

if __name__ == "__main__":
    unittest.main()
