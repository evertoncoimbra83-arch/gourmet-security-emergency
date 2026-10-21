from pathlib import Path
import hashlib
import re
import tempfile
import unittest


def normalize_secret_bytes(data: bytes) -> bytes:
    """Strip only trailing \r and \n bytes, preserving all other bytes."""
    return data.rstrip(b"\r\n")


def secret_file_value_hash(file_path: Path) -> str:
    data = file_path.read_bytes()
    normalized = normalize_secret_bytes(data)
    return hashlib.sha256(normalized).hexdigest()


def dotenv_key_hash(env_path: Path, target_key: str) -> str:
    content = env_path.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(
        r"^[ \t]*(?:export[ \t]+)?" + re.escape(target_key) + r"=(.*)$",
        re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        raise KeyError(f"Key {target_key} not found")

    raw_val = match.group(1).rstrip("\r")

    if raw_val.startswith('"') and raw_val.endswith('"'):
        raw_val = raw_val[1:-1]
    elif raw_val.startswith("'") and raw_val.endswith("'"):
        raw_val = raw_val[1:-1]

    return hashlib.sha256(raw_val.encode("utf-8")).hexdigest()


def process_env_key_hash(environ_data: bytes, target_key: str) -> str:
    prefix = (target_key + "=").encode("utf-8")
    for item in environ_data.split(b"\x00"):
        if item.startswith(prefix):
            val = item[len(prefix):]
            return hashlib.sha256(val).hexdigest()
    raise KeyError(f"Key {target_key} not found in environ")


class TestGIHashNormalization(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_secret_lf_vs_dotenv_without_lf(self):
        """Case 1: secret file with LF vs dotenv without LF => PARITY PASS"""
        token = "SAMPLE_PSEUDO_KEY_12345"
        sec_file = self.dir / "token_lf.txt"
        sec_file.write_bytes(token.encode("utf-8") + b"\n")

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN={token}\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, env_hash)

    def test_02_secret_crlf_vs_dotenv_without_crlf(self):
        """Case 2: secret file with CRLF vs dotenv without CRLF => PARITY PASS"""
        token = "SAMPLE_PSEUDO_KEY_67890"
        sec_file = self.dir / "token_crlf.txt"
        sec_file.write_bytes(token.encode("utf-8") + b"\r\n")

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN={token}\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, env_hash)

    def test_03_secret_without_newline(self):
        """Case 3: secret file without newline => PARITY PASS"""
        token = "SAMPLE_PSEUDO_KEY_ABCDE"
        sec_file = self.dir / "token_none.txt"
        sec_file.write_bytes(token.encode("utf-8"))

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN={token}\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, env_hash)

    def test_04_secret_containing_equal_sign(self):
        """Case 4: secret containing '=' => preserved"""
        token = "prefix==value=part2=="
        sec_file = self.dir / "token_eq.txt"
        sec_file.write_bytes(token.encode("utf-8") + b"\n")

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN={token}\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, env_hash)

    def test_05_secret_containing_hash_sign(self):
        """Case 5: secret containing '#' => preserved"""
        token = "token#part#comment_like"
        sec_file = self.dir / "token_hash.txt"
        sec_file.write_bytes(token.encode("utf-8") + b"\n")

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN=\"{token}\"\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, env_hash)

    def test_06_secret_containing_internal_spaces(self):
        """Case 6: secret containing internal spaces => preserved"""
        token = "token with   multiple  spaces"
        sec_file = self.dir / "token_space.txt"
        sec_file.write_bytes(token.encode("utf-8") + b"\n")

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN=\"{token}\"\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, env_hash)

    def test_07_different_secrets_fail_parity(self):
        """Case 7: different secrets => PARITY FAIL"""
        token1 = "VALUE_ONE"
        token2 = "VALUE_TWO"
        sec_file = self.dir / "token_diff.txt"
        sec_file.write_bytes(token1.encode("utf-8") + b"\n")

        env_file = self.dir / "test.env"
        env_file.write_text(f"GI_MOCK_TOKEN={token2}\n", encoding="utf-8")

        sec_hash = secret_file_value_hash(sec_file)
        env_hash = dotenv_key_hash(env_file, "GI_MOCK_TOKEN")

        self.assertNotEqual(sec_hash, env_hash)

    def test_08_dotenv_outer_quotes_handling(self):
        """Case 8: dotenv outer quotes handling (single and double quotes)"""
        token = "UNQUOTED_LOGICAL_VALUE"

        # Double quotes
        env_double = self.dir / "double.env"
        env_double.write_text(f'GI_MOCK_TOKEN="{token}"\n', encoding="utf-8")

        # Single quotes
        env_single = self.dir / "single.env"
        env_single.write_text(f"GI_MOCK_TOKEN='{token}'\n", encoding="utf-8")

        # No quotes
        env_none = self.dir / "none.env"
        env_none.write_text(f"GI_MOCK_TOKEN={token}\n", encoding="utf-8")

        hash_double = dotenv_key_hash(env_double, "GI_MOCK_TOKEN")
        hash_single = dotenv_key_hash(env_single, "GI_MOCK_TOKEN")
        hash_none = dotenv_key_hash(env_none, "GI_MOCK_TOKEN")

        self.assertEqual(hash_double, hash_none)
        self.assertEqual(hash_single, hash_none)

    def test_09_process_environ_parity(self):
        """Case 9: process environment parity against secret file"""
        token = "ENVIRON_PROCESS_TOKEN"
        sec_file = self.dir / "proc_token.txt"
        sec_file.write_bytes(token.encode("utf-8") + b"\n")

        environ_bytes = b"OTHER_VAR=123\x00GI_MOCK_TOKEN=ENVIRON_PROCESS_TOKEN\x00ANOTHER=456\x00"

        sec_hash = secret_file_value_hash(sec_file)
        proc_hash = process_env_key_hash(environ_bytes, "GI_MOCK_TOKEN")

        self.assertEqual(sec_hash, proc_hash)


if __name__ == "__main__":
    unittest.main()
