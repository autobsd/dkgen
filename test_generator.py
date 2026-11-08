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

    def test_happy_path_ed25519(self):
        # 32 bytes of valid non-zero hex for seed and salt
        valid_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(valid_input)
        
        self.assertEqual(code, 0, "Valid program sequence should exit with 0")
        self.assertIn("PRIVATE_KEY:\n", stdout)
        self.assertIn("PUBLIC_KEY:\n", stdout)
        self.assertTrue(stdout.endswith("STATUS:SUCCESS\n"))
        self.assertEqual(stderr, "")

    def test_happy_path_p256(self):
        # Validate that the brand new provider-centric P-256 architecture compiles and derives
        valid_input = (
            "ALGO:P-256\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(valid_input)
        
        self.assertEqual(code, 0, "Valid P-256 configuration must succeed")
        self.assertIn("PRIVATE_KEY:\n", stdout)
        self.assertIn("PUBLIC_KEY:\n", stdout)
        # P-256 public keys in uncompressed SEC1 format are 65 bytes long (130 hex characters)
        self.assertTrue(stdout.endswith("STATUS:SUCCESS\n"))

    def test_buffer_exact_fill_boundary(self):
        """Tests that a line matching exactly MAX_LINE_LEN - 1 (511 chars) 

        plus a newline character does not trigger a false-positive truncation error.
        """
        # Prefixed with 'SALT:' (5 chars), then 506 valid hex characters = 511 chars total.
        # This fits perfectly in line[512] leaving room only for the trailing '\0'.
        exact_salt = "SALT:" + ("a" * 506) + "\n"
        valid_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n" +
            exact_salt
        )
        code, stdout, stderr = self.run_binary(valid_input)
        
        # If your fixed truncation-checking logic works, this safely passes validation 
        # (though it fails later on the internal 32-byte salt constraint, not "Line too long")
        self.assertEqual(code, 1)
        self.assertNotIn("ERROR:Line too long", stderr)
        self.assertIn("ERROR:Invalid SALT", stderr)

    def test_line_overflow_recovery(self):
        """Verifies that an over-length line is caught, stripped out via stream 

        draining, but the utility continues executing instead of aborting.
        """
        recovering_input = (
            "ALGO:ED25519\n"
            "SEED:" + ("B" * 600) + "\n"  # 600 characters triggers structural overflow
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n" # Clean recovery seed
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(recovering_input)
        
        # If the code used `continue;` for truncation, the program skips the bad seed line,
        # logs the error message to stderr, processes the remaining lines, and successfully outputs keys!
        self.assertEqual(code, 0)
        self.assertIn("ERROR:Line too long\n", stderr)
        self.assertIn("STATUS:SUCCESS\n", stdout)

    def test_all_zero_seed_rejection(self):
        bad_input = (
            "ALGO:ED25519\n"
            "SEED:0000000000000000000000000000000000000000000000000000000000000000\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("ERROR:SEED is all zeros", stderr)

    def test_all_zero_salt_rejection(self):
        bad_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:0000000000000000000000000000000000000000000000000000000000000000\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("ERROR:SALT is all zeros", stderr)

    def test_missing_fields(self):
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

    def test_malformed_hex_odd_length(self):
        """Rejects seeds with non-matching hex pairs."""
        bad_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2\n" # 63 characters instead of 64
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Invalid SEED", stderr)

    def test_malformed_hex_invalid_characters(self):
        """Rejects non-hex elements (e.g., letters past F)."""
        bad_input = (
            "ALGO:ED25519\n"
            "SEED:G102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n" # Contains 'G'
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(bad_input)
        
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Invalid SEED", stderr)

    def test_ed25519_exact_cryptographic_output(self):
        """Validates the exact expected private key, public key, and status for a ED25519 derivation."""
        valid_input = (
            "ALGO:ED25519\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        
        # Expected precise output blocks based on the CLI trial
        expected_private = "PRIVATE_KEY:\n5b9bdcfb6a9457569fda58715c711c3c9fb38ed89769af6538cc879dbbf46032\n"
        expected_public = "PUBLIC_KEY:\n6cd079dd1b66b06ea9a45defa267ef9d72eba9e86bc3a3187da16d21853db513\n"
        expected_status = "STATUS:SUCCESS\n"
        
        code, stdout, stderr = self.run_binary(valid_input)
        
        # Comprehensive output validation assertions
        self.assertEqual(code, 0, "ED25519 run should complete with exit code 0")
        self.assertIn(expected_private, stdout, "Derived private key mismatch")
        self.assertIn(expected_public, stdout, "Derived public key mismatch")
        self.assertTrue(stdout.endswith(expected_status), "Output sequence must finish with SUCCESS status")
        self.assertEqual(stderr, "", "Stderr should remain clear for successful operations")

    def test_p256_exact_cryptographic_output(self):
        """Validates the exact expected private key, public key, and status for a P-256 derivation."""
        valid_input = (
            "ALGO:P-256\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        
        # Expected precise output blocks based on the CLI trial
        expected_private = "PRIVATE_KEY:\n5b9bdcfb6a9457569fda58715c711c3c9fb38ed89769af6538cc879dbbf46032\n"
        expected_public = "PUBLIC_KEY:\n04e561ed8f716b2c099a4c8ae14f969c22582c1edda5128cb1f24031d8b0500b8030b50a546adc702c43bda7cf7373c9b0af41b010c31a9181bd056b8f32e80837\n"
        expected_status = "STATUS:SUCCESS\n"
        
        code, stdout, stderr = self.run_binary(valid_input)
        
        # Comprehensive output validation assertions
        self.assertEqual(code, 0, "P-256 run should complete with exit code 0")
        self.assertIn(expected_private, stdout, "Derived private key mismatch")
        self.assertIn(expected_public, stdout, "Derived public key mismatch")
        self.assertTrue(stdout.endswith(expected_status), "Output sequence must finish with SUCCESS status")
        self.assertEqual(stderr, "", "Stderr should remain clear for successful operations")

    def test_happy_path_argon2id_20(self):
        """Validates that the ARGON2ID_20 profile successfully derives a 20-byte key."""
        valid_input = (
            "ALGO:ARGON2ID_20\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(valid_input)
        
        self.assertEqual(code, 0, "ARGON2ID_20 profile should exit with 0")
        self.assertIn("KEY:\n", stdout)
        self.assertNotIn("PRIVATE_KEY:", stdout)
        self.assertNotIn("PUBLIC_KEY:", stdout)
        
        # Extract the key line to verify its length (20 bytes = 40 hex characters)
        lines = stdout.strip().split('\n')
        self.assertIn("KEY:", lines)
        key_index = lines.index("KEY:") + 1
        derived_key = lines[key_index]
        self.assertEqual(len(derived_key), 40, "ARGON2ID_20 output must be exactly 40 hex characters")
        self.assertTrue(stdout.endswith("STATUS:SUCCESS\n"))
        self.assertEqual(stderr, "")

    def test_happy_path_argon2id_32(self):
        """Validates that the ARGON2ID_32 profile successfully derives a 32-byte key."""
        valid_input = (
            "ALGO:ARGON2ID_32\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        code, stdout, stderr = self.run_binary(valid_input)
        
        self.assertEqual(code, 0, "ARGON2ID_32 profile should exit with 0")
        self.assertIn("KEY:\n", stdout)
        
        # Extract the key line to verify its length (32 bytes = 64 hex characters)
        lines = stdout.strip().split('\n')
        self.assertIn("KEY:", lines)
        key_index = lines.index("KEY:") + 1
        derived_key = lines[key_index]
        self.assertEqual(len(derived_key), 64, "ARGON2ID_32 output must be exactly 64 hex characters")
        self.assertTrue(stdout.endswith("STATUS:SUCCESS\n"))
        self.assertEqual(stderr, "")

    def test_argon2id_20_exact_cryptographic_output(self):
        """Validates the exact expected raw cryptographic output for ARGON2ID_20."""
        valid_input = (
            "ALGO:ARGON2ID_20\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        
        # Expected exact output sequence based on Argon2id with 4 lanes, 64MiB, 3 iterations
        expected_output = (
            "KEY:\n"
            "1f690bc4a65517be2eef6ec7510a4b858fd749ef\n"
            "STATUS:SUCCESS\n"
        )
        
        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, expected_output, "Cryptographic output for ARGON2ID_20 mismatched")
        self.assertEqual(stderr, "")

    def test_argon2id_32_exact_cryptographic_output(self):
        """Validates the exact expected raw cryptographic output for ARGON2ID_32."""
        valid_input = (
            "ALGO:ARGON2ID_32\n"
            "SEED:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
            "SALT:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        )
        
        # Note: The first 32 bytes of the Argon2id output match the raw private keys 
        # generated in your existing ED25519 and P-256 test cases.
        expected_output = (
            "KEY:\n"
            "5b9bdcfb6a9457569fda58715c711c3c9fb38ed89769af6538cc879dbbf46032\n"
            "STATUS:SUCCESS\n"
        )
        
        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, expected_output, "Cryptographic output for ARGON2ID_32 mismatched")
        self.assertEqual(stderr, "")

if __name__ == "__main__":
    unittest.main()
