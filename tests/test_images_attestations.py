"""Exact signed-predicate binding; no registry, signing, credentials or cluster."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CORE = module("release_exact_test", "images-release.py")
SDK = module("sdk_exact_test", "images-instrumentation.py")
EXACT = CORE.ATTESTATIONS
DIGEST = "sha256:" + "a" * 64
BUILD_TYPE = CORE.BUILD_TYPE
AMD = {"SPDXID": "SPDXRef-DOCUMENT", "documentNamespace": "https://elven.invalid/amd64"}
ARM = {"SPDXID": "SPDXRef-DOCUMENT", "documentNamespace": "https://elven.invalid/arm64"}
BUILD = {"buildx.build.provenance": {"revision": "synthetic", "parameters": {"count": 1}}}


def policy(build_type=BUILD_TYPE):
    return {"schemaVersion": 1, "canonicalization": EXACT.CANONICALIZATION, "subjectDigest": DIGEST,
            "spdx": {"linux/amd64": EXACT.canonical_hash(AMD), "linux/arm64": EXACT.canonical_hash(ARM)},
            "build": {"predicateType": build_type, "sha256": EXACT.canonical_hash(BUILD)}}


def envelope(predicate, kind=EXACT.SPDX_TYPE, digest=DIGEST):
    statement = {"_type": "https://in-toto.io/Statement/v0.1",
                 "subject": [{"name": "elvenobservability/synthetic", "digest": {"sha256": digest.removeprefix("sha256:")}}],
                 "predicateType": kind, "predicate": predicate}
    return {"payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": base64.b64encode(b"synthetic-already-verified-signature").decode()}]}


def stdout(kind=EXACT.SPDX_TYPE, build_type=BUILD_TYPE):
    values = [envelope(AMD), envelope(ARM)] if kind == EXACT.SPDX_TYPE else [envelope(BUILD, build_type)]
    return "\n".join(json.dumps(value) for value in values)


class ExactAttestationTests(unittest.TestCase):
    def verify(self, value, kind=EXACT.SPDX_TYPE, expected=None):
        return EXACT.verify_predicates(value, expected or policy(), DIGEST, kind, BUILD_TYPE)

    def test_two_spdx_stream_array_and_idempotent_duplicates_are_accepted(self):
        values = [envelope(AMD), envelope(ARM)]
        for value in (stdout(), json.dumps(values), json.dumps([*values, values[0]])):
            with self.subTest(value=value[:30]):
                self.assertEqual(self.verify(value)["verifiedPredicateCount"], 2)

    def test_build_predicate_is_direct_json_not_a_custom_data_wrapper(self):
        self.assertEqual(self.verify(stdout(BUILD_TYPE), BUILD_TYPE)["verifiedPredicateCount"], 1)
        with self.assertRaises(ValueError):
            self.verify(json.dumps(envelope({"Data": json.dumps(BUILD)}, BUILD_TYPE)), BUILD_TYPE)

    def test_missing_platform_or_duplicate_one_platform_does_not_prove_both(self):
        for values in ([envelope(AMD)], [envelope(ARM)], [envelope(AMD), envelope(AMD)], []):
            with self.subTest(count=len(values)), self.assertRaises(ValueError):
                self.verify(json.dumps(values))

    def test_wrong_subject_predicate_type_or_content_is_rejected(self):
        for changed in (envelope(AMD, digest="sha256:" + "b" * 64), envelope(AMD, BUILD_TYPE),
                        envelope({**AMD, "extra": "not-approved"})):
            with self.subTest(changed=changed["payload"][:20]), self.assertRaises(ValueError):
                self.verify("\n".join(json.dumps(value) for value in (changed, envelope(ARM))))

    def test_mixed_subjects_and_ambiguous_digest_algorithms_are_rejected(self):
        for change in (lambda subject: subject.append(copy.deepcopy(subject[0])),
                       lambda subject: subject[0]["digest"].update(sha512="b" * 128)):
            value = envelope(AMD)
            statement = json.loads(base64.b64decode(value["payload"]))
            change(statement["subject"])
            value["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
            with self.assertRaises(ValueError):
                self.verify(json.dumps([value, envelope(ARM)]))

    def test_malformed_stream_dsse_base64_and_duplicate_json_keys_fail_closed(self):
        bad = ["", "not-json", stdout() + "trailing", "[]", "{}", "[[]]",
               '{"payload":"x","payload":"y"}']
        for field, value in (("payload", "%%%"), ("payloadType", "text/plain"),
                             ("signatures", []), ("signatures", [{}]), ("signatures", [{"sig": "%%%"}])):
            changed = envelope(AMD)
            changed[field] = value
            bad.append(json.dumps([changed, envelope(ARM)]))
        for value in bad:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                self.verify(value)

    def test_unexpected_additional_predicate_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            self.verify(stdout() + "\n" + json.dumps(envelope({"SPDXID": "unexpected"})))

    def test_semantic_json_normalizes_key_order_numbers_and_unicode_escapes(self):
        first = EXACT._load('{"b":1.0,"a":"\\u00e7","z":-0.0,"decimal":0.00100}')
        second = EXACT._load('{"decimal":1e-3,"z":0,"a":"ç","b":1}')
        self.assertEqual(EXACT.canonical_hash(first), EXACT.canonical_hash(second))
        for value in ('{"same":1,"same":2}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                EXACT._load(value)
        for value in ('{"value":1e1000000}', '{"value":"\\ud800"}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                EXACT.canonical_hash(EXACT._load(value))

    def test_policy_requires_exact_subject_both_distinct_spdx_and_build_hashes(self):
        cases = [None, {}, {**policy(), "subjectDigest": "sha256:" + "b" * 64},
                 {**policy(), "schemaVersion": 2}, {**policy(), "canonicalization": "unknown"},
                 {**policy(), "spdx": {"linux/amd64": EXACT.canonical_hash(AMD)}},
                 {**policy(), "spdx": dict.fromkeys(EXACT.PLATFORMS, EXACT.canonical_hash(AMD))},
                 {**policy(), "build": {"predicateType": "wrong", "sha256": EXACT.canonical_hash(BUILD)}}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                EXACT.validate_policy(value, DIGEST, BUILD_TYPE)

    def test_policy_from_local_evidence_binds_raw_checksums_and_no_path_escape(self):
        with tempfile.TemporaryDirectory(prefix="elven-exact-attestations-") as temporary:
            folder = Path(temporary)
            image = {"digest": DIGEST, "metadata": "build.json", "scans": {}}
            for name, value in (("build.json", BUILD), ("amd.json", AMD), ("arm.json", ARM)):
                (folder / name).write_text(json.dumps(value))
            image["metadataSha256"] = hashlib.sha256((folder / "build.json").read_bytes()).hexdigest()
            for platform, name in (("linux/amd64", "amd.json"), ("linux/arm64", "arm.json")):
                image["scans"][platform] = {"sbom": name, "sbomSha256": hashlib.sha256((folder / name).read_bytes()).hexdigest()}
            self.assertEqual(EXACT.evidence_policy(folder, image, BUILD_TYPE), policy())
            (folder / "amd.json").write_text('{"modified":true}')
            with self.assertRaisesRegex(ValueError, "checksum"):
                EXACT.evidence_policy(folder, image, BUILD_TYPE)
            image["metadata"] = "../escape.json"
            with self.assertRaisesRegex(ValueError, "companion"):
                EXACT.evidence_policy(folder, image, BUILD_TYPE)


class VerificationIntegrationTests(unittest.TestCase):
    def test_promoted_core_and_sdk_locks_require_persisted_policies(self):
        for file, owner, kind in (("versions.lock.json", CORE, BUILD_TYPE),
                                  ("instrumentation.lock.json", SDK, SDK.BUILD_TYPE)):
            lock = json.loads((ROOT / file).read_text())
            lock["distribution"]["publicationStatus"] = "verified"
            for index, image in enumerate(lock["images"].values()):
                digest = "sha256:" + format(index + 1, "x") * 64
                expected = policy(kind)
                expected["subjectDigest"] = digest
                image["distribution"].update(status="verified", digest=digest, tag="v1.0.0", attestations=expected)
            with self.subTest(file=file), tempfile.TemporaryDirectory(prefix="elven-lock-attestations-") as temporary:
                path = Path(temporary) / file
                path.write_text(json.dumps(lock))
                if owner is CORE:
                    with mock.patch.object(CORE, "LOCK", path):
                        CORE.lock_data()
                        next(iter(lock["images"].values()))["distribution"].pop("attestations")
                        path.write_text(json.dumps(lock))
                        with self.assertRaises(ValueError):
                            CORE.lock_data()
                else:
                    SDK.read_lock(path)
                    next(iter(lock["images"].values()))["distribution"].pop("attestations")
                    path.write_text(json.dumps(lock))
                    with self.assertRaises(ValueError):
                        SDK.read_lock(path)

    def test_core_verification_requires_exact_hashes_even_when_cosign_returns_success(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if args[:2] == ["cosign", "version"]:
                return json.dumps({"gitVersion": "v3.1.4"})
            if args[:2] == ["cosign", "verify-attestation"]:
                return stdout() if args[args.index("--type") + 1] == "spdxjson" else stdout(BUILD_TYPE)
            return "{}"

        with mock.patch.object(CORE, "run", side_effect=run):
            CORE.verify_image("docker.io/elvenobservability/elven-collector@" + DIGEST, "v1.0.0", policy())
        identity = calls[1][calls[1].index("--certificate-identity-regexp") + 1]
        self.assertNotIn(".*", identity)
        self.assertTrue(all("--insecure-ignore-tlog" not in args for args in calls))
        with mock.patch.object(CORE, "run", side_effect=lambda args, **kw: '{"gitVersion":"v3.1.4"}' if args[1] == "version" else "{}"):
            with self.assertRaises(ValueError):
                CORE.verify_image("docker.io/elvenobservability/elven-collector@" + DIGEST, "v1.0.0", policy())

    def test_sdk_verify_uses_persisted_lock_policy_without_local_artifacts(self):
        expected = policy(SDK.BUILD_TYPE)
        reference = "docker.io/elvenobservability/elven-auto-java@" + DIGEST
        lock = SDK.read_lock()
        lock["images"]["java"]["distribution"].update(status="verified", digest=DIGEST, tag="v1.0.0", attestations=expected)

        def run(args, **kwargs):
            if args[:2] == ["cosign", "version"]:
                return '{"gitVersion":"v3.1.4"}'
            if args[:2] == ["cosign", "verify-attestation"]:
                kind = args[args.index("--type") + 1]
                return stdout() if kind == "spdxjson" else stdout(SDK.BUILD_TYPE, SDK.BUILD_TYPE)
            return "{}"

        with mock.patch.object(SDK.OCI, "run", side_effect=run):
            SDK.verify_reference(reference, "v1.0.0", lock)
        lock["images"]["java"]["distribution"].pop("attestations")
        with mock.patch.object(SDK.OCI, "run") as command, self.assertRaises(ValueError):
            SDK.verify_reference(reference, "v1.0.0", lock)
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
