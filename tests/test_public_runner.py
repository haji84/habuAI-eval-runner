"""Offline tests for the public-only Habu sealed evaluation runner.

All examples and hashes below are TEST DOUBLES. These are not new unseen
evaluation cases and no HMAC, Ollama model, billing or GitHub action is used.
"""
import copy
import hashlib
import io
import json
from contextlib import redirect_stdout
from unittest import TestCase
from unittest.mock import patch

import public_packet_guard as g
import run_public_eval as runner

FREEZE_SHA = "a" * 64
COHORT_SHA = "b" * 64
DUMMY_SIGNATURE = "c" * 64


def synthetic_packet(count=40):
    cases = []
    for n in range(count):
        cid = f"{n+2000:016x}"
        lang = "py" if n < max(20, count // 2) else "js"
        path = f"fixture/sealed_{cid}.{lang}"
        if lang == "py":
            source = "# Synthetic contract: return the argument.\ndef check(x):\n    return x\n"
        else:
            source = "// Synthetic contract: return the argument.\nfunction check(x) { return x; }\n"
        lines = source.splitlines()
        patch = (f"diff --git a/{path} b/{path}\n"
                 f"new file mode 100644\n--- /dev/null\n+++ b/{path}\n"
                 f"@@ -0,0 +1,{len(lines)} @@\n" +
                 "".join("+" + s + "\n" for s in lines))
        cases.append({"case_id": cid, "path": path, "patch": patch,
                      "source_sha256": hashlib.sha256(
                          source.encode("utf-8")).hexdigest()})
    return {"payload": {
        "stage": "public", "schema": g.SCHEMA,
        "freeze_sha256": FREEZE_SHA,
        "cohort_sha256": COHORT_SHA,
        "custodian_id": "test-only-custodian",
        "public_cases": cases,
    }, "signature": DUMMY_SIGNATURE}


def check(packet=None, *, packet_hash=None):
    packed = json.dumps(packet if packet is not None else synthetic_packet(),
                        sort_keys=True, ensure_ascii=False).encode("utf-8")
    return g.validate_public_packet(
        packed,
        expected_sha256=packet_hash or hashlib.sha256(packed).hexdigest(),
        expected_freeze_sha256=FREEZE_SHA)


class PublicBundleFailClosedTests(TestCase):
    def test_forty_public_synthetic_paths_are_accepted_without_oracles(self):
        cases = check()
        self.assertEqual(len(cases), 40)
        self.assertEqual(sum(x["path"].endswith(".py") for x in cases), 20)
        self.assertEqual(sum(x["path"].endswith(".js") for x in cases), 20)
        for case in cases:
            self.assertEqual(set(case), g.CASE_FIELDS)

    def test_no_private_label_oracle_witness_is_allowed_in_packet(self):
        for private in ("label", "observed", "required", "critical",
                        "test_input", "runner_id", "witness_sha256",
                        "actual", "expected_good", "private_code"):
            with self.subTest(private=private):
                candidate = synthetic_packet()
                candidate["payload"]["public_cases"][0][private] = "LEAK"
                with self.assertRaisesRegex(ValueError, "PRIVATE_LABEL"):
                    check(candidate)

    def test_custodian_private_case_envelope_is_rejected(self):
        candidate = synthetic_packet()
        candidate["payload"]["cases"] = candidate["payload"].pop("public_cases")
        candidate["payload"]["stage"] = "cohort"
        with self.assertRaises(ValueError):
            check(candidate)

    def test_tampering_with_public_code_or_required_digest_fails(self):
        original = synthetic_packet()
        scenarios = [
            lambda p: p["payload"]["public_cases"][0].update(
                {"patch": p["payload"]["public_cases"][0]["patch"].replace(
                    "return x", "return x + 1")}),
            lambda p: p["payload"]["public_cases"][0].update(
                {"source_sha256": "0" * 64}),
            lambda p: p["payload"]["public_cases"][0].update(
                {"path": "fixture/sealed_ffffffffffffffff.py"}),
            lambda p: p["payload"]["public_cases"][0].update(
                {"patch": p["payload"]["public_cases"][0]["patch"] +
                          "+++ b/other.py\n"}),
        ]
        for apply in scenarios:
            candidate = copy.deepcopy(original)
            apply(candidate)
            with self.assertRaises(ValueError):
                check(candidate)

    def test_manifest_sha_mismatch_denied_before_any_model_call(self):
        with self.assertRaisesRegex(ValueError, "PACKET_SHA_MISMATCH"):
            check(packet_hash="0" * 64)

    def test_wrong_freeze_digest_or_fake_signature_denied(self):
        for attr, val in (("freeze_sha256", "0" * 64),
                          ("cohort_sha256", "short"),
                          ("custodian_id", "custodian with spaces")):
            candidate = synthetic_packet()
            candidate["payload"][attr] = val
            with self.assertRaises(ValueError):
                check(candidate)
        candidate = synthetic_packet()
        candidate["signature"] = "not signed"
        with self.assertRaises(ValueError):
            check(candidate)

    def test_duplicate_ids_and_missing_language_strata_are_denied(self):
        candidate = synthetic_packet()
        candidate["payload"]["public_cases"][1] = copy.deepcopy(
            candidate["payload"]["public_cases"][0])
        with self.assertRaises(ValueError):
            check(candidate)
        only_python = synthetic_packet()
        only_python["payload"]["public_cases"] = (
            only_python["payload"]["public_cases"][:20] * 2)
        with self.assertRaises(ValueError):
            check(only_python)

    def test_fewer_than_forty_cases_rejected(self):
        candidate = synthetic_packet()
        candidate["payload"]["public_cases"] = candidate["payload"]["public_cases"][:39]
        with self.assertRaisesRegex(ValueError, "INVALID_PUBLIC_POPULATION"):
            check(candidate)

    def test_duplicate_json_keys_and_nan_are_denied(self):
        for bad in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    g.strict_json(bad)

    def test_canonical_patch_line_count_cannot_be_falsified(self):
        row = synthetic_packet()["payload"]["public_cases"][0]
        with self.assertRaises(ValueError):
            g.source_from_new_file_patch(
                row["path"], row["patch"].replace("+1,3", "+1,30"))

    def test_runner_mock_replies_do_not_masquerade_as_evaluation(self):
        cases = check()
        output = io.StringIO()
        with patch.object(runner, "_ask_model", return_value='{"findings":[]}'):
            with redirect_stdout(output):
                exit_code = runner._response_ledger(
                    cases, packet_sha256="d" * 64,
                    freeze_sha256=FREEZE_SHA,
                    runner_head="e" * 40, total_seconds=5)
        self.assertEqual(exit_code, 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(sum(s.startswith("EVAL_PUBLIC_RESPONSE: ") for s in lines), 40)
        receipt = json.loads(lines[-1].removeprefix("EVAL_PUBLIC_RECEIPT: "))
        self.assertEqual(receipt["completed"], 40)
        self.assertFalse(receipt["quality_qualified"])
        self.assertFalse(receipt["independent_review_approved"])
        self.assertFalse(receipt["release_authorized"])

    def test_bad_local_model_digest_fails_closed(self):
        fake_tags = io.BytesIO(json.dumps({
            "models": [{"name": runner.MODEL, "digest": "f" * 64}]
        }).encode("utf-8"))
        with patch.object(runner.urllib.request, "urlopen", return_value=fake_tags):
            with self.assertRaisesRegex(ValueError, "MODEL_TAG_DIGEST_DRIFT"):
                runner._model_digest()

    def test_untrusted_no_packet_data_does_not_call_model(self):
        with patch.object(runner, "_ask_model") as ask:
            with self.assertRaises(ValueError):
                g.validate_public_packet(
                    b'{"payload":{"label":"BUG"}}',
                    expected_sha256="0" * 64,
                    expected_freeze_sha256=FREEZE_SHA)
            ask.assert_not_called()
