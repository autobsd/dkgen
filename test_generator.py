import os
import subprocess
import sys
import unittest

try:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Automatically detect binary path: Check for environment variable first,
# then fall back to the project default build location.
BINARY_PATH = os.environ.get("DKGEN_BIN", "bin/dkgen")

PASSPHRASE_TEXT = "correct-horse-battery-staple"
SALT_TEXT = "random-salt-value-1234"
PEPPER_TEXT = "optional-pepper-secret"

# OpenSSL Argon2id (t=3, m=65536 KiB, p=4) + Ed25519 / P-256 reference vectors
# for PASSPHRASE="correct-horse-battery-staple", SALT="random-salt-value-1234"
VECTORS = {
    "ARGON2ID_20": {
        "priv": "07bc83c680f5c288dbbe224a2c67aa453d94ee17",
    },
    "ARGON2ID_32": {
        "priv": "a40ac895a221b37b64ea94cc31e8ce944a1cee27e3cf32eb7f503463a1a24ee6",
    },
    "ED25519": {
        "priv": "a40ac895a221b37b64ea94cc31e8ce944a1cee27e3cf32eb7f503463a1a24ee6",
        "pub": "43bb478ff002130c55c7e68d031546deaa147927a575c55af513b68b911d9c88",
    },
    "P-256": {
        "priv": "a40ac895a221b37b64ea94cc31e8ce944a1cee27e3cf32eb7f503463a1a24ee6",
        "pub": (
            "04"
            "ce35cabf20fcaa0f3abfde56bdde9362ef3a9b499cfe47456bb88ff0129baf9e"
            "7a7af626836ac492f2b38c37a3fb68f689139cd4b29619ca8e537fe73ec6699b"
        ),
    },
    "ED25519_PEPPER": {
        "priv": "c0f6f6bee1a134351ec4ba2187cf8fbf491e00b69cae817d8732d05c2bf989bd",
        "pub": "d566fe8a7a262ae762e0638d2629886a9f8735b3e422704ea1743559e2d4c43d",
    },
}


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

    def parse_output_keys(self, stdout: str):
        """Extracts PRIVATE_KEY and optional PUBLIC_KEY hex strings from stdout."""
        lines = stdout.strip().splitlines()
        keys = {}
        if "PRIVATE_KEY:" in lines:
            idx = lines.index("PRIVATE_KEY:")
            keys["private"] = lines[idx + 1]
        if "PUBLIC_KEY:" in lines:
            idx = lines.index("PUBLIC_KEY:")
            keys["public"] = lines[idx + 1]
        return keys

    # -------------------------------------------------------------------------
    # Exact Cryptographic Output & Curve Point Verification Tests
    # -------------------------------------------------------------------------

    def test_ed25519_exact_cryptographic_output(self):
        """Validates exact private key, public key, and status for ED25519."""
        valid_input = (
            "ALGO:ED25519\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
        )
        expected_output = (
            "PRIVATE_KEY:\n"
            f"{VECTORS['ED25519']['priv']}\n"
            "PUBLIC_KEY:\n"
            f"{VECTORS['ED25519']['pub']}\n"
            "STATUS:SUCCESS\n"
        )

        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, expected_output)
        self.assertEqual(stderr, "")

        if HAS_CRYPTOGRAPHY:
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(VECTORS["ED25519"]["priv"])
            )
            derived_pub = sk.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            ).hex()
            self.assertEqual(derived_pub, VECTORS["ED25519"]["pub"])

    def test_p256_exact_cryptographic_output(self):
        """Validates exact private key, uncompressed SEC1 public key, and status for P-256."""
        valid_input = (
            "ALGO:P-256\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
        )
        expected_output = (
            "PRIVATE_KEY:\n"
            f"{VECTORS['P-256']['priv']}\n"
            "PUBLIC_KEY:\n"
            f"{VECTORS['P-256']['pub']}\n"
            "STATUS:SUCCESS\n"
        )

        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, expected_output)
        self.assertEqual(stderr, "")

        if HAS_CRYPTOGRAPHY:
            scalar = int(VECTORS["P-256"]["priv"], 16)
            sk = ec.derive_private_key(scalar, ec.SECP256R1())
            derived_pub = sk.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            ).hex()
            self.assertEqual(derived_pub, VECTORS["P-256"]["pub"])

    def test_argon2id_20_exact_cryptographic_output(self):
        """Validates exact 20-byte raw output (and absence of PUBLIC_KEY) for ARGON2ID_20."""
        valid_input = (
            "ALGO:ARGON2ID_20\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
        )
        expected_output = (
            "PRIVATE_KEY:\n"
            f"{VECTORS['ARGON2ID_20']['priv']}\n"
            "STATUS:SUCCESS\n"
        )

        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertNotIn("PUBLIC_KEY:", stdout)
        self.assertEqual(stdout, expected_output)
        self.assertEqual(stderr, "")

    def test_argon2id_32_exact_cryptographic_output(self):
        """Validates exact 32-byte raw output (and absence of PUBLIC_KEY) for ARGON2ID_32."""
        valid_input = (
            "ALGO:ARGON2ID_32\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
        )
        expected_output = (
            "PRIVATE_KEY:\n"
            f"{VECTORS['ARGON2ID_32']['priv']}\n"
            "STATUS:SUCCESS\n"
        )

        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertNotIn("PUBLIC_KEY:", stdout)
        self.assertEqual(stdout, expected_output)
        self.assertEqual(stderr, "")

    def test_ed25519_with_pepper_exact_output(self):
        """Validates exact cryptographic output when optional PEPPER is provided."""
        valid_input = (
            "ALGO:ED25519\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
            f"PEPPER:{PEPPER_TEXT}\n"
        )
        expected_output = (
            "PRIVATE_KEY:\n"
            f"{VECTORS['ED25519_PEPPER']['priv']}\n"
            "PUBLIC_KEY:\n"
            f"{VECTORS['ED25519_PEPPER']['pub']}\n"
            "STATUS:SUCCESS\n"
        )

        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, expected_output)
        self.assertEqual(stderr, "")

        if HAS_CRYPTOGRAPHY:
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(VECTORS["ED25519_PEPPER"]["priv"])
            )
            derived_pub = sk.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            ).hex()
            self.assertEqual(derived_pub, VECTORS["ED25519_PEPPER"]["pub"])

    # -------------------------------------------------------------------------
    # Input Parsing, Whitespace, and Buffer Boundary Tests
    # -------------------------------------------------------------------------

    def test_whitespace_preservation_and_field_ordering(self):
        """Fields can appear in any order; spaces in PASSPHRASE/SALT/PEPPER are preserved."""
        reordered_input = (
            f"SALT:{SALT_TEXT}\n"
            f"PEPPER:{PEPPER_TEXT}\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            "ALGO:ED25519\n"
        )
        code, stdout, stderr = self.run_binary(reordered_input)
        self.assertEqual(code, 0)
        keys = self.parse_output_keys(stdout)
        self.assertEqual(keys["private"], VECTORS["ED25519_PEPPER"]["priv"])
        self.assertEqual(stderr, "")

        # Trailing space in PASSPHRASE changes derived key
        spaced_input = (
            "ALGO:ED25519\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT} \n"
            f"SALT:{SALT_TEXT}\n"
        )
        code_sp, stdout_sp, _ = self.run_binary(spaced_input)
        self.assertEqual(code_sp, 0)
        keys_sp = self.parse_output_keys(stdout_sp)
        self.assertNotEqual(keys_sp["private"], VECTORS["ED25519"]["priv"])

    def test_empty_pepper_matches_omitted_pepper(self):
        """An empty PEPPER: line passes key_len=0, matching omitted PEPPER behavior."""
        empty_pepper_input = (
            "ALGO:ED25519\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
            "PEPPER:\n"
        )
        code, stdout, stderr = self.run_binary(empty_pepper_input)
        self.assertEqual(code, 0)
        keys = self.parse_output_keys(stdout)
        self.assertEqual(keys["private"], VECTORS["ED25519"]["priv"])
        self.assertEqual(stderr, "")

    def test_empty_passphrase_or_salt_rejected(self):
        """Empty PASSPHRASE: or SALT: yields password_len=0/salt_len=0 -> DKGEN_ERR_INVALID_ARG."""
        for field_line in ["PASSPHRASE:\n", "SALT:\n"]:
            with self.subTest(field_line=field_line.strip()):
                if field_line.startswith("PASSPHRASE:"):
                    bad_input = f"ALGO:ED25519\n{field_line}SALT:{SALT_TEXT}\n"
                else:
                    bad_input = f"ALGO:ED25519\nPASSPHRASE:{PASSPHRASE_TEXT}\n{field_line}"
                code, stdout, stderr = self.run_binary(bad_input)
                self.assertEqual(code, 1)
                self.assertIn("ERROR:Invalid argument\n", stderr)
                self.assertEqual(stdout, "")

    def test_buffer_exact_fill_boundary(self):
        """A line matching MAX_LINE_LEN - 1 (4095 chars) without a trailing newline
        in the initial fgets buffer must not trigger a false-positive overflow.
        """
        exact_salt = "SALT:" + ("a" * 4090) + "\n"
        valid_input = (
            "ALGO:ED25519\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n" +
            exact_salt
        )
        code, stdout, stderr = self.run_binary(valid_input)
        self.assertEqual(code, 0)
        self.assertNotIn("ERROR:Line too long", stderr)
        self.assertTrue(stdout.endswith("STATUS:SUCCESS\n"))

    def test_line_overflow_recovery(self):
        """An over-length line (>4095 chars) is rejected and drained; the program
        continues and succeeds once valid fields are supplied.
        """
        recovering_input = (
            "ALGO:ED25519\n"
            "PASSPHRASE:" + ("B" * 4200) + "\n"     # triggers structural overflow
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"        # clean recovery passphrase
            f"SALT:{SALT_TEXT}\n"
        )
        code, stdout, stderr = self.run_binary(recovering_input)
        self.assertEqual(code, 0)
        self.assertIn("ERROR:Line too long\n", stderr)
        self.assertIn("STATUS:SUCCESS\n", stdout)

    def test_missing_fields(self):
        """Omitting any required field (ALGO, PASSPHRASE, SALT) fails."""
        bad_input = (
            "ALGO:ED25519\n"
            f"SALT:{SALT_TEXT}\n"        # PASSPHRASE omitted
        )
        code, stdout, stderr = self.run_binary(bad_input)
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Missing required fields", stderr)
        self.assertEqual(stdout, "")

    def test_duplicate_fields(self):
        """Duplicate ALGO, PASSPHRASE, SALT, or PEPPER fields are rejected."""
        cases = [
            ("ALGO:ED25519\nALGO:ED25519\n", "ERROR:Duplicate ALGO field"),
            ("PASSPHRASE:a\nPASSPHRASE:b\n", "ERROR:Duplicate PASSPHRASE field"),
            ("SALT:a\nSALT:b\n", "ERROR:Duplicate SALT field"),
            ("PEPPER:a\nPEPPER:b\n", "ERROR:Duplicate PEPPER field"),
        ]
        for snippet, expected_err in cases:
            with self.subTest(expected_err=expected_err):
                code, stdout, stderr = self.run_binary(snippet)
                self.assertEqual(code, 1)
                self.assertIn(expected_err, stderr)
                self.assertEqual(stdout, "")

    def test_unknown_token_rejection(self):
        """Legacy SEED token or unrecognized prefixes fail immediately."""
        for bad_line in ["UNKNOWN_FIELD:some_value\n", "SEED:01020304\n"]:
            with self.subTest(bad_line=bad_line.strip()):
                code, stdout, stderr = self.run_binary(bad_line)
                self.assertEqual(code, 1)
                self.assertIn("ERROR:Unknown line in input", stderr)
                self.assertEqual(stdout, "")

    def test_unsupported_or_overlong_algo(self):
        """Rejects unsupported algorithm names and values exceeding algo_str."""
        bad_algo = (
            "ALGO:RSA-2048\n"
            f"PASSPHRASE:{PASSPHRASE_TEXT}\n"
            f"SALT:{SALT_TEXT}\n"
        )
        code, stdout, stderr = self.run_binary(bad_algo)
        self.assertEqual(code, 1)
        self.assertIn("ERROR:Unsupported algorithm profile", stderr)
        self.assertEqual(stdout, "")

        long_algo = "ALGO:" + ("X" * 32) + "\n"
        code, stdout, stderr = self.run_binary(long_algo)
        self.assertEqual(code, 1)
        self.assertIn("ERROR:ALGO value too long", stderr)
        self.assertEqual(stdout, "")


if __name__ == "__main__":
    unittest.main()
