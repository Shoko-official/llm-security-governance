import sys
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security.filter import SecurityFilter

class TestPromptInjectionSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_path: Path = ROOT / "security" / "mock_policy.json"
        self.vectors_path: Path = ROOT / "security" / "mock_injection_vectors.json"
        
        self.filter: SecurityFilter = SecurityFilter.load_from_file(self.policy_path)
        
        with open(self.vectors_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.vectors = data.get("vectors", [])

    def test_injection_vectors(self) -> None:
        total_unsafe = 0
        blocked_unsafe = 0
        total_safe = 0
        false_positives = 0
        
        for vec in self.vectors:
            prompt = vec["prompt"]
            expected_safe = vec["expected_safe"]
            
            is_safe = self.filter.is_prompt_safe(prompt)
            
            if not expected_safe:
                total_unsafe += 1
                if not is_safe:
                    blocked_unsafe += 1
                else:
                    print(f"FAILED TO BLOCK UNSAFE PROMPT: {prompt}")
            else:
                total_safe += 1
                if not is_safe:
                    false_positives += 1
                    print(f"FALSE POSITIVE ON SAFE PROMPT: {prompt}")
                    
        block_rate = (blocked_unsafe / total_unsafe) if total_unsafe > 0 else 1.0
        false_positive_rate = (false_positives / total_safe) if total_safe > 0 else 0.0
        
        print(f"\n[Prompt Safety Stats] Total Unsafe: {total_unsafe}, Blocked: {blocked_unsafe} (Block Rate: {block_rate*100:.1f}%)")
        print(f"[Prompt Safety Stats] Total Safe: {total_safe}, False Positives: {false_positives} (False Positive Rate: {false_positive_rate*100:.1f}%)")
        
        self.assertEqual(block_rate, 1.0, f"Block rate is {block_rate*100:.1f}% instead of 100.0%")
        self.assertEqual(false_positive_rate, 0.0, f"False positive rate is {false_positive_rate*100:.1f}% instead of 0.0%")

if __name__ == "__main__":
    unittest.main()
