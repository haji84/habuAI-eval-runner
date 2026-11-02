"""Offline key custody for an isolated macOS evaluation-custodian account.

This is reviewable source, NOT an online key service. Never run on Actions.
Only the macOS login Keychain stores cryptographic private identities.
The public evaluation model and developer must not share this macOS user.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

SERVICE = "org.habuai.sealed-eval-custodian-v1"
VERSION = re.compile(r"^v[1-9][0-9]{0,2}$")
RECIPIENT = re.compile(r"^age1[a-z0-9]{45,2000}$")
SECRET = re.compile(r"^AGE-SECRET-KEY-[A-Z0-9-]+$")
MAX_BYTES = 1024 * 1024


def _check_version(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("INVALID_VERSION")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def macos_keychain():
    if platform.system() != "Darwin":
        raise ValueError("DEDICATED_MACOS_USER_REQUIRED")
    try:
        import keyring
    except ImportError as exc:
        raise ValueError("MACOS_KEYRING_MISSING") from exc
    backend = keyring.get_keyring()
    if not type(backend).__module__.startswith("keyring.backends.macOS"):
        raise ValueError("NON_MACOS_KEYCHAIN_BACKEND")
    return keyring


def _exec(cmd, input_bytes=b""):
    # Never put a secret in argv. The only accepted helpers are age and
    # age-keygen, always local subprocesses, never a shell or network call.
    if not cmd or cmd[0] not in ("age", "age-keygen"):
        raise ValueError("CRYPTO_HELPER_NOT_ALLOWED")
    result = subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, timeout=60)
    if result.returncode or len(result.stdout) > MAX_BYTES + 65536:
        raise ValueError("CRYPTO_HELPER_FAILED")
    return result.stdout


def _bundle(backend, version):
    _check_version(version)
    raw = backend.get_password(SERVICE, "bundle-" + version)
    if not isinstance(raw, str):
        raise ValueError("MISSING_PROTECTED_BUNDLE")
    try:
        obj = json.loads(raw)
        if (not isinstance(obj, dict)
                or set(obj) != {"age_identity", "sign_private"}
                or not isinstance(obj["age_identity"], str)
                or not SECRET.fullmatch(obj["age_identity"])
                or not isinstance(obj["sign_private"], str)):
            raise ValueError("WRONG_PROTECTED_BUNDLE")
        return obj
    except (TypeError, ValueError) as exc:
        raise ValueError("INVALID_PROTECTED_BUNDLE") from exc


def _recipient(identity):
    stdout = _exec(["age-keygen", "-y", "-"],
                   (identity + "\n").encode("ascii"))
    public = stdout.decode("ascii", errors="strict").strip()
    if not RECIPIENT.fullmatch(public):
        raise ValueError("INVALID_AGE_RECIPIENT")
    return public


def _signing_private(bundle):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        raw = base64.b64decode(bundle["sign_private"], validate=True)
        if len(raw) != 32:
            raise ValueError("SIGNING_KEY_LENGTH")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("INVALID_SIGNING_KEY") from exc


def status(backend, version):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    obj = _bundle(backend, version)
    public = _signing_private(obj).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return {
        "version": version, "age_recipient": _recipient(obj["age_identity"]),
        "ed25519_verify_key": base64.b64encode(public).decode("ascii"),
        "macos_keychain": True, "backup_independently_verified": False,
        "separate_custodian_verified": False, "quality_qualified": False,
    }


def initialize(backend, version):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _check_version(version)
    if backend.get_password(SERVICE, "bundle-" + version) is not None:
        raise ValueError("EXISTING_KEY_MUST_NOT_BE_OVERWRITTEN")
    result = _exec(["age-keygen"]).decode("ascii", errors="strict")
    identities = [line.strip() for line in result.splitlines()
                  if line.startswith("AGE-SECRET-KEY-")]
    if len(identities) != 1 or not SECRET.fullmatch(identities[0]):
        raise ValueError("AGE_KEYGEN_INVALID")
    _recipient(identities[0])
    raw_sign = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    # ONE Keychain item prevents half-created asymmetric key pairs.
    backend.set_password(SERVICE, "bundle-" + version, json.dumps({
        "age_identity": identities[0],
        "sign_private": base64.b64encode(raw_sign).decode("ascii"),
    }, sort_keys=True))
    return status(backend, version)


def _bound(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("INVALID_OR_OVERSIZED_PRIVATE_INPUT")
    return raw


def _write_once(path, blob):
    if not isinstance(path, Path) or not path.is_absolute() or path.suffix != ".age":
        raise ValueError("ABSOLUTE_AGE_PATH_REQUIRED")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("TRUSTED_EXISTING_DIRECTORY_REQUIRED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(blob)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _encrypt_to(public, payload):
    if not isinstance(public, str) or not RECIPIENT.fullmatch(public):
        raise ValueError("RECIPIENT_INVALID")
    return _exec(["age", "-r", public], _bound(payload))


def seal(backend, version, payload, path):
    obj = _bundle(backend, version)
    ciphertext = _encrypt_to(_recipient(obj["age_identity"]), payload)
    _write_once(path, ciphertext)
    return {"version": version, "ciphertext_sha256": _digest(ciphertext),
            "ciphertext_bytes": len(ciphertext), "private_data_logged": False}


def verify(backend, version, path):
    # Decrypts ONLY inside dedicated custodian memory and logs NO plaintext.
    cipher = _bound(path.read_bytes())
    identity = _bundle(backend, version)["age_identity"]
    with tempfile.TemporaryDirectory(prefix="habu-custodian-") as temp:
        tmp = Path(temp) / "ciphertext.age"
        tmp.write_bytes(cipher)
        os.chmod(tmp, 0o600)
        decrypted = _exec(["age", "-d", "-i", "-", str(tmp)],
                          (identity + "\n").encode("ascii"))
    _bound(decrypted)
    return {"version": version, "authenticated_decryption": True,
            "ciphertext_sha256": _digest(cipher),
            "private_data_logged": False}


def sign_receipt(backend, version, manifest_bytes):
    sig = _signing_private(_bundle(backend, version)).sign(_bound(manifest_bytes))
    return {"version": version, "manifest_sha256": _digest(manifest_bytes),
            "ed25519_signature": base64.b64encode(sig).decode("ascii"),
            "private_signing_key_logged": False}


def backup_to_other_custodian(backend, version, recovery_recipient, output):
    # Backup must contain BOTH encryption and signing identities.
    obj = _bundle(backend, version)
    if not RECIPIENT.fullmatch(recovery_recipient):
        raise ValueError("INVALID_RECOVERY_RECIPIENT")
    if _recipient(obj["age_identity"]) == recovery_recipient:
        raise ValueError("BACKUP_TO_SAME_KEY_FORBIDDEN")
    cipher = _encrypt_to(recovery_recipient, json.dumps(obj, sort_keys=True).encode())
    _write_once(output, cipher)
    return {"version": version, "recovery_ciphertext_sha256": _digest(cipher),
            "backup_restoration_independently_tested": False,
            "private_keys_logged": False}


def main():
    parser = argparse.ArgumentParser(description="Local isolated key custody")
    parser.add_argument("command", choices=(
        "init", "status", "seal", "verify", "sign", "backup-recovery"))
    parser.add_argument("--version", default="v1")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recovery-recipient")
    args = parser.parse_args()
    try:
        _check_version(args.version)
        backend = macos_keychain()
        if args.command == "init":
            result = initialize(backend, args.version)
        elif args.command == "status":
            result = status(backend, args.version)
        elif args.command == "seal":
            if args.output is None or args.input is not None:
                raise ValueError("STDIN_AND_OUTPUT_REQUIRED")
            result = seal(backend, args.version,
                          sys.stdin.buffer.read(MAX_BYTES + 1), args.output)
        elif args.command == "verify":
            if args.input is None:
                raise ValueError("CIPHERTEXT_REQUIRED")
            result = verify(backend, args.version, args.input)
        elif args.command == "sign":
            result = sign_receipt(backend, args.version,
                                  sys.stdin.buffer.read(MAX_BYTES + 1))
        else:
            if args.output is None or not args.recovery_recipient:
                raise ValueError("SEPARATE_BACKUP_RECIPIENT_REQUIRED")
            result = backup_to_other_custodian(
                backend, args.version, args.recovery_recipient, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError):
        print("CUSTODIAN_FAIL_CLOSED_NO_KEYS_EXPOSED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
