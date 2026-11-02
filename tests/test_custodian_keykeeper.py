"""No-key, no-network unit tests for the local macOS custodian utility.

All key material is FAKE and stays in test memory. The mock age backend is
NOT cryptographic. A passing Linux CI does not prove macOS integration.
"""
import base64
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from custodian import keykeeper as k

FAKE_SECRET = "AGE-SECRET-KEY-1" + "A" * 58
PUBLIC = "age1" + "b" * 58
RECOVERY = "age1" + "c" * 58


class FakeKeychain:
    def __init__(self):
        self.values = {}

    def get_password(self, service, name):
        return self.values.get((service, name))

    def set_password(self, service, name, password):
        if (service, name) in self.values:
            raise ValueError("KEY_OVERWRITE")
        self.values[service, name] = password


def mocked_age(args, input_bytes=b""):
    if args == ["age-keygen"]:
        return ("# public key: " + PUBLIC + "\n" +
                FAKE_SECRET + "\n").encode("ascii")
    if args == ["age-keygen", "-y", "-"]:
        if input_bytes.strip().decode("ascii") != FAKE_SECRET:
            raise ValueError("UNKNOWN_FAKE_KEY")
        return (PUBLIC + "\n").encode("ascii")
    if len(args) == 3 and args[:2] == ["age", "-r"]:
        if args[2] not in (PUBLIC, RECOVERY):
            raise ValueError("UNKNOWN_FAKE_RECIPIENT")
        return b"FAKE_CIPHERTEXT:" + base64.b64encode(input_bytes)
    if len(args) == 5 and args[:4] == ["age", "-d", "-i", "-"]:
        if input_bytes.strip().decode("ascii") != FAKE_SECRET:
            raise ValueError("UNKNOWN_FAKE_KEY")
        ciphertext = Path(args[4]).read_bytes()
        if not ciphertext.startswith(b"FAKE_CIPHERTEXT:"):
            raise ValueError("MALFORMED_FAKE_CIPHERTEXT")
        return base64.b64decode(ciphertext.partition(b":")[2])
    raise ValueError("UNKNOWN_FAKE_AGE_COMMAND")


class KeyCustodyUnitTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeKeychain()
        mock = patch.object(k, "_exec", side_effect=mocked_age)
        mock.start()
        self.addCleanup(mock.stop)

    def create(self, version="v1"):
        return k.initialize(self.backend, version)

    def test_init_stores_both_private_keys_only_in_keychain(self):
        status = self.create()
        self.assertEqual(status["age_recipient"], PUBLIC)
        self.assertFalse(status["quality_qualified"])
        self.assertEqual(len(self.backend.values), 1)
        contents = next(iter(self.backend.values.values()))
        self.assertIn(FAKE_SECRET, contents)
        self.assertIn("sign_private", json.loads(contents))
        self.assertNotIn(FAKE_SECRET, json.dumps(status))

    def test_does_not_overwrite_existing_key_material(self):
        self.create()
        snapshot = dict(self.backend.values)
        with self.assertRaisesRegex(ValueError, "OVERWRITTEN"):
            self.create()
        self.assertEqual(snapshot, self.backend.values)

    def test_bad_version_refused(self):
        for version in ("", "v0", "v001", "../../v1", "v1000"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                k.initialize(self.backend, version)

    def test_encrypted_output_never_contains_secret_plaintext(self):
        self.create()
        secret_data = b'{"label":"BUG","private":"test-only-label"}'
        with tempfile.TemporaryDirectory() as path:
            target = Path(path) / "private.age"
            result = k.seal(self.backend, "v1", secret_data, target)
            self.assertNotIn(secret_data, target.read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertTrue(k.verify(self.backend, "v1", target)["authenticated_decryption"])
            self.assertFalse(result["private_data_logged"])

    def test_existing_output_never_overwritten(self):
        self.create()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sealed.age"
            k.seal(self.backend, "v1", b"first", target)
            initial = target.read_bytes()
            with self.assertRaises(FileExistsError):
                k.seal(self.backend, "v1", b"second", target)
            self.assertEqual(target.read_bytes(), initial)

    def test_refuses_path_or_oversized_plaintext(self):
        self.create()
        for path in (Path("relative.age"), Path("/tmp/not-age.txt")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                k.seal(self.backend, "v1", b"private", path)
        with self.assertRaises(ValueError):
            k.seal(self.backend, "v1", b"x" * (k.MAX_BYTES + 1),
                   Path("/tmp/never-created.age"))

    def test_ed25519_signature_can_be_verified_with_public_key_only(self):
        status = self.create()
        content = b"public test-only frozen manifest"
        envelope = k.sign_receipt(self.backend, "v1", content)
        verifier = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(status["ed25519_verify_key"]))
        verifier.verify(base64.b64decode(envelope["ed25519_signature"]), content)
        with self.assertRaises(Exception):
            verifier.verify(base64.b64decode(envelope["ed25519_signature"]),
                            b"tampered manifest")
        self.assertNotIn("sign_private", json.dumps(envelope))

    def test_recovery_covers_both_keys_but_is_not_independence_proof(self):
        self.create()
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "recovery.age"
            result = k.backup_to_other_custodian(
                self.backend, "v1", RECOVERY, file)
            self.assertFalse(result["backup_restoration_independently_tested"])
            self.assertNotIn(FAKE_SECRET, file.read_text("ascii"))
            mock_content = json.loads(base64.b64decode(
                file.read_bytes().partition(b":")[2]))
            self.assertEqual(mock_content["age_identity"], FAKE_SECRET)
            self.assertIn("sign_private", mock_content)

    def test_backup_with_same_recipient_is_refused(self):
        self.create()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "SAME_KEY"):
                k.backup_to_other_custodian(
                    self.backend, "v1", PUBLIC, Path(directory) / "same.age")

    def test_version_rotation_keeps_old_key_available(self):
        self.create("v1")
        self.create("v2")
        self.assertEqual(len(self.backend.values), 2)
        self.assertEqual(k.status(self.backend, "v1")["version"], "v1")
        self.assertEqual(k.status(self.backend, "v2")["version"], "v2")

    def test_non_macos_device_cannot_manage_real_key(self):
        with patch.object(k.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(ValueError, "MACOS"):
                k.macos_keychain()

    def test_missing_or_corrupted_keychain_bundle_is_fail_closed(self):
        with self.assertRaises(ValueError):
            k.status(self.backend, "v1")
        self.create()
        key = next(iter(self.backend.values))
        self.backend.values[key] = '{"age_identity":"bad","sign_private":"x"}'
        with self.assertRaises(ValueError):
            k.status(self.backend, "v1")


if __name__ == "__main__":
    unittest.main()
