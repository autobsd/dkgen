import os
import subprocess
import sys
import unittest

# Automatically detect binary path: Check for environment variable first,
# then fall back to the project default build location.
BINARY_PATH = os.environ.get("DKGEN_BIN", "bin/dkgen")

class TestKeyGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Verify the binary exists before spinning up tests."""
        if not os.path.exists(BINARY_PATH):
            print(f"\nERROR: Target binary '{BINARY_PATH}' not found.", file=sys.stderr)
            print("Please compile your program using 'make' first.\n", file=sys.stderr)
            sys.exit(1)

    def run_binary(self, input_data: str):
        """Helper to pipe raw lines into the C binary and capture execution state."""
        result = subprocess.run(
            [BINARY_PATH],
            input=input_data,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr

    def test_happy_path(self):
        # 32 bytes of valid non-zero hex for seed and salt
        valid_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(valid_input)
        
        self.assertEqual(code, 0, "Valid program sequence should exit with 0")
        self.assertIn("PRIVATE_KEY:", stdout)
        self.assertIn("PUBLIC_KEY:", stdout)
        self.assertTrue(stdout.endswith("STATUS:SUCCESS\n"))
        self.assertEqual(stderr, "")

    def test_all_zero_seed_rejection(self):
        bad_input = (
            "ALGO:ED25519\n"
            "SEED:0000000000000000000000000000000000000000000000000000000000000000\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "", "Stdout should remain empty on validation failure")
        self.assertIn("ERROR:SEED is all zeros", stderr)

    def test_all_zero_salt_rejection(self):
        bad_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:0000000000000000000000000000000000000000000000000000000000000000\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "", "Stdout should remain empty on validation failure")
        self.assertIn("ERROR:SALT is all zeros", stderr)

    def test_line_overflow(self):
        # Generate an excessively long line exceeding MAX_LINE_LEN (512)
        bad_input = "ALGO:" + ("A" * 600) + "\n"
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Line too long", stderr)

    def test_missing_fields(self):
        # Missing SEED line entirely
        bad_input = "ALGO:ED25519\nSALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Missing required fields", stderr)

    def test_duplicate_fields(self):
        bad_input = (
            "ALGO:ED25519\n"
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Duplicate ALGO field", stderr)

    def test_unknown_token_rejection(self):
        bad_input = "UNKNOWN_FIELD:some_value\n"
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Unknown line in input", stderr)

if __name__ == "__main__":
    unittest.main()
