"""Public-only synthetic packet validation for a separated GitHub evaluation runner.

This file is a BOOTSTRAP TEMPLATE stored in existing PR #136.
Copy it into the dedicated PUBLIC runner repo after that repo exists.

Only a separately controlled custodian can verify the HMAC. This public
validator checks packet structure, exact patch/source hashes, class counts
of languages, and absence of *private answer fields*; it never receives
the key, label, witness inputs, output oracle, or production owner data.
"""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = "habu-reviewer-sealed-gate-v1"
FIELDS = frozenset({"stage", "schema", "freeze_sha256", "cohort_sha256",
                    "custodian_id", "public_cases"})
CASE_FIELDS = frozenset({"case_id", "path", "patch", "source_sha256"})
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
SAFE_ID = re.compile(r"^[a-zA-Z0-9._-]{1,80}$")
PATH = re.compile(r"^fixture/sealed_([0-9a-f]{16})\.(py|js)$")
HUNK = re.compile(r"^@@ -0,0 \+1,([1-9][0-9]*) @@\n$")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_):
    raise ValueError("NONFINITE_JSON")


def strict_json(raw: bytes | str):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="strict")
    if not isinstance(raw, str) or not 0 < len(raw) <= 700_000:
        raise ValueError("INVALID_PACKET_SIZE")
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs,
                          parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeError) as e:
        raise ValueError("INVALID_PACKET_JSON") from e


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def source_from_new_file_patch(path: str, patch: str) -> str:
    """Accept only the canonical synthetic new-file diff, not arbitrary code."""
    if not isinstance(patch, str) or not 0 < len(patch) <= 3500:
        raise ValueError("INVALID_SYNTHETIC_PATCH")
    if "\r" in patch or "\x00" in patch or not patch.endswith("\n"):
        raise ValueError("INVALID_SYNTHETIC_PATCH")
    lines = patch.splitlines(keepends=True)
    expected_prefix = [
        f"diff --git a/{path} b/{path}\n", "new file mode 100644\n",
        "--- /dev/null\n", f"+++ b/{path}\n",
    ]
    if len(lines) < 6 or lines[:4] != expected_prefix:
        raise ValueError("INVALID_SYNTHETIC_PATCH")
    hunk = HUNK.fullmatch(lines[4])
    if not hunk:
        raise ValueError("INVALID_SYNTHETIC_HUNK")
    added = lines[5:]
    if len(added) != int(hunk.group(1)) or any(
            not line.startswith("+") or not line.endswith("\n")
            for line in added):
        raise ValueError("INVALID_SYNTHETIC_PATCH")
    code = "".join(line[1:] for line in added)
    if not 0 < len(code) <= 2800:
        raise ValueError("INVALID_SYNTHETIC_SOURCE")
    return code


def validate_public_packet(raw: bytes, *, expected_sha256: str,
                           expected_freeze_sha256: str) -> list[dict]:
    """Fail closed before any model is started or expensive model downloaded.

    The packet's HMAC is only VERIFIED by a separate custodian/scorer. This
    guard cannot cryptographically verify custodianship, newness or true
    independence. A semantic/secret-leak audit is still required upstream.
    """
    if not isinstance(raw, bytes):
        raise ValueError("PACKET_BYTES_REQUIRED")
    if (not isinstance(expected_sha256, str)
            or not HEX64.fullmatch(expected_sha256)
            or sha256_bytes(raw) != expected_sha256):
        raise ValueError("PACKET_SHA_MISMATCH")
    if not isinstance(expected_freeze_sha256, str) or not HEX64.fullmatch(
            expected_freeze_sha256):
        raise ValueError("FREEZE_SHA_INVALID")
    envelope = strict_json(raw)
    if not isinstance(envelope, dict) or set(envelope) != {
            "payload", "signature"}:
        raise ValueError("PRIVATE_FIELDS_OR_PACKET_ENVELOPE")
    if (not isinstance(envelope["signature"], str)
            or not HEX64.fullmatch(envelope["signature"])):
        raise ValueError("INVALID_CUSTODIAN_COMMITMENT")
    payload = envelope["payload"]
    if (not isinstance(payload, dict) or set(payload) != FIELDS
            or payload["stage"] != "public"
            or payload["schema"] != SCHEMA
            or payload["freeze_sha256"] != expected_freeze_sha256
            or not isinstance(payload["cohort_sha256"], str)
            or not HEX64.fullmatch(payload["cohort_sha256"])
            or not isinstance(payload["custodian_id"], str)
            or not SAFE_ID.fullmatch(payload["custodian_id"])):
        raise ValueError("INVALID_OR_PRIVATE_PUBLIC_PAYLOAD")
    cases = payload["public_cases"]
    if not isinstance(cases, list) or not 40 <= len(cases) <= 128:
        raise ValueError("INVALID_PUBLIC_POPULATION")
    ids = set()
    languages = {"py": 0, "js": 0}
    for case in cases:
        if not isinstance(case, dict) or set(case) != CASE_FIELDS:
            raise ValueError("PRIVATE_LABEL_OR_EXTRA_CASE_FIELD")
        cid, path = case["case_id"], case["path"]
        if not isinstance(cid, str) or not HEX16.fullmatch(cid) or cid in ids:
            raise ValueError("INVALID_OR_DUPLICATE_CASE_ID")
        ids.add(cid)
        if not isinstance(path, str):
            raise ValueError("INVALID_SYNTHETIC_PATH")
        found = PATH.fullmatch(path)
        if not found or found.group(1) != cid:
            raise ValueError("INVALID_SYNTHETIC_PATH")
        if (not isinstance(case["source_sha256"], str)
                or not HEX64.fullmatch(case["source_sha256"])):
            raise ValueError("INVALID_SOURCE_HASH")
        source = source_from_new_file_patch(path, case["patch"])
        if sha256_bytes(source.encode("utf-8")) != case["source_sha256"]:
            raise ValueError("SYNTHETIC_SOURCE_SHA_MISMATCH")
        languages[found.group(2)] += 1
    if min(languages.values()) < 8:
        raise ValueError("UNBALANCED_LANGUAGE_POPULATION")
    return cases
