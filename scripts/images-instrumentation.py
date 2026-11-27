#!/usr/bin/env python3
"""Independent OCI lifecycle for the Elven injector and opt-in SDK payloads.

Only generic OCI/digest/registry helpers are reused from images-release.py;
its three-component lock, defaults and publication identity are never used.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_oci_utilities", ROOT / "scripts/images-release.py")
OCI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OCI)
REPOSITORY = "elven-observability/stack-observability-k8s"
WORKFLOW = ".github/workflows/instrumentation.yaml"
ENVIRONMENT = "elven-distribution-release"
BUILD_TYPE = "https://elvenobservability.com/attestations/instrumentation-build/v1"
MANIFEST = "instrumentation-release.json"
REPOSITORIES = {
    "operator": "docker.io/elvenobservability/elven-instrumentation-operator",
    "java": "docker.io/elvenobservability/elven-auto-java",
    "nodejs": "docker.io/elvenobservability/elven-auto-nodejs",
    "nodejs20": "docker.io/elvenobservability/elven-auto-nodejs20",
    "python": "docker.io/elvenobservability/elven-auto-python",
}
VERSION = re.compile(r"v?1\.[0-9]+\.[0-9]+(?:-dev|-rc\.[0-9]+)?\Z")
JAVA_BUILD_IMAGE = "gradle:9.8.2-jdk25@sha256:e46e15353757ef9c9be0197a243653e88d25ebcd4c3c841057cf839c11fcf898"


def source_ref(image):
    source = image["upstream"]
    return f"{source['repository']}:{source['tag']}@{source['digest']}"


def validate_java_source_build(image, recipe):
    """Bind the patched agent to its immutable source, builder and local patch bytes."""
    build = image.get("sourceBuild")
    repository = "https://github.com/open-telemetry/opentelemetry-java-instrumentation.git"
    if not isinstance(build, dict) or build.get("repository") != repository:
        raise ValueError("Java requires the official immutable source-build provenance")
    revision, builder = build.get("revision", ""), build.get("buildImage", "")
    if (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or builder != JAVA_BUILD_IMAGE or type(build.get("javaVersion")) is not int
            or build["javaVersion"] != 25):
        raise ValueError("Java source revision and the approved Gradle/JDK25 builder must be immutable")
    lines = [line.strip() for line in recipe.replace("\\\n", " ").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if (f"FROM --platform=$BUILDPLATFORM {builder} AS builder" not in lines
            or f"ADD --keep-git-dir=true {repository}#{revision} /src" not in lines
            or f"ARG UPSTREAM_IMAGE={source_ref(image)}" not in lines
            or "FROM ${UPSTREAM_IMAGE}" not in lines
            or image["upstream"].get("sourceVersion") != "2.33.1"
            or "unmodified" in recipe.lower()):
        raise ValueError("Java source/build/base recipe or modified-payload labeling differs from lock")
    patches = build.get("patches")
    if not isinstance(patches, list) or len(patches) != 1 or not isinstance(patches[0], dict):
        raise ValueError("Java requires exactly one reviewed local terminal-error patch")
    patch = patches[0]
    relative, checksum = patch.get("path"), patch.get("sha256", "")
    if (not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts
            or not isinstance(checksum, str)
            or not re.fullmatch(r"[0-9a-f]{64}", checksum)):
        raise ValueError("Java patch identity must include its exact path and SHA256")
    folder = ROOT / "images/autoinstrumentation/java"
    path = ROOT / relative
    if (path.parent != folder or path.suffix != ".patch" or path.is_symlink()
            or any(parent.is_symlink() for parent in path.parents if parent.is_relative_to(ROOT))
            or not path.is_file() or path.resolve().parent != folder.resolve()
            or OCI.sha256(path) != checksum):
        raise ValueError("Java patch must be a confined regular non-symlink file matching its SHA256")
    destination = "/tmp/" + path.name
    run_lines = [line for line in lines if line.startswith("RUN ")]
    commands = " ".join(run_lines)

    def invokes(command):
        return any(re.search(r"(?:\bRUN\s+|&&\s*|;\s*)" + re.escape(command)
                             + r"(?=\s*(?:&&|;|$))", line) is not None for line in run_lines)

    if (f"COPY {relative} {destination}" not in lines
            or not invokes(f"git apply --check {destination}")
            or not invokes(f"git apply {destination}")
            or "./gradlew" not in commands or ":javaagent:assemble" not in commands
            or "COPY --from=builder /src/javaagent/build/libs/opentelemetry-javaagent.jar /javaagent.jar" not in lines):
        raise ValueError("Java patch/application/build/payload transfer differs from source-build provenance")
    version, wrapper_sha = build.get("gradleVersion", ""), build.get("wrapperDistributionSha256", "")
    if (version != "9.8.2"
            or not builder.startswith(f"gradle:{version}-jdk25@")
            or not isinstance(wrapper_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", wrapper_sha)
            or not invokes(f"grep -Fx 'distributionUrl=https\\://services.gradle.org/distributions/gradle-{version}-bin.zip' gradle/wrapper/gradle-wrapper.properties")
            or not invokes(f"grep -Fx 'distributionSha256Sum={wrapper_sha}' gradle/wrapper/gradle-wrapper.properties")):
        raise ValueError("Java Gradle wrapper version/checksum differs from the pinned build provenance")
    required_flags = {"--no-parallel", "-Pkotlin.compiler.execution.strategy=in-process",
                      "-Porg.gradle.java.installations.auto-download=false",
                      "-Porg.gradle.java.installations.auto-detect=false",
                      "-Porg.gradle.java.installations.paths=$JAVA_HOME"}
    assemblies = []
    for line in run_lines:
        lexer = shlex.shlex(line.removeprefix("RUN "), posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        shell_commands, current = [], []
        for token in lexer:
            if token and set(token) <= set(";&|"):
                shell_commands.append(current)
                current = []
            else:
                current.append(token)
        shell_commands.append(current)
        for args in shell_commands:
            # A bounded network retry may execute Gradle as an `if` condition.
            # Strip only actual shell control words, never echo/printf text.
            while args and args[0] in ("do", "if", "then"):
                args = args[1:]
            if not args or args[0] != "./gradlew":
                continue
            if not required_flags <= set(args):
                raise ValueError("Every Gradle invocation must confine toolchains to pinned JAVA_HOME")
            for flag in args:
                if ((flag.startswith(("-Porg.gradle.java.installations.", "-Pkotlin.compiler.execution.strategy="))
                     and flag not in required_flags)
                        or flag.startswith("-Dorg.gradle.java.installations.") or flag == "--parallel"):
                    raise ValueError("Java compiler discovery/download or Kotlin process policy cannot be overridden")
            if ":javaagent:assemble" in args:
                assemblies.append(args)
    if not assemblies or any(not required_flags <= set(args) for args in assemblies):
        raise ValueError("Java assembly must use only pinned JAVA_HOME toolchains without download or parallel compiler heaps")


def read_lock(path=ROOT / "instrumentation.lock.json"):
    lock = json.loads(path.read_text())
    if lock.get("schemaVersion") != 1 or set(lock.get("images", {})) != set(REPOSITORIES):
        raise ValueError("Unrecognized independent instrumentation lock/components")
    if lock["distribution"].get("publicationStatus") not in ("not-published", "verified"):
        raise ValueError("Unrecognized SDK distribution publication state")
    for name, image in lock["images"].items():
        if image["distribution"]["repository"] != REPOSITORIES[name]:
            raise ValueError(f"{name}: unexpected Elven SDK repository")
        recipe = (ROOT / image["dockerfile"]).read_text()
        if name == "operator":
            go_image = image["sourceBuild"]["goImage"]
            if (not re.fullmatch(r"docker.io/library/golang:[0-9]+\.[0-9]+\.[0-9]+-bookworm@sha256:[0-9a-f]{64}", go_image)
                    or go_image not in recipe):
                raise ValueError("Operator Go toolchain differs between lock and Dockerfile")
        elif (not OCI.DIGEST.fullmatch(image["upstream"]["digest"])
              or image["upstream"]["tag"] == "latest" or source_ref(image) not in recipe):
            raise ValueError(f"{name}: immutable upstream SDK pin differs from recipe")
        if name == "java":
            validate_java_source_build(image, recipe)
        published = image["distribution"]
        if published.get("status") not in ("not-published", "verified"):
            raise ValueError(f"{name}: unrecognized SDK publication state")
        if published.get("digest") is not None and not OCI.DIGEST.fullmatch(published["digest"]):
            raise ValueError(f"{name}: malformed published digest")
        if published.get("status") == "verified" and not published.get("digest"):
            raise ValueError(f"{name}: verified requires an actual published digest")
        if published.get("status") == "verified" and not re.fullmatch(r"v1\.[0-9]+\.[0-9]+", published.get("tag", "")):
            raise ValueError(f"{name}: verified requires an exact stable release signing identity")
        if published.get("status") == "verified":
            OCI.ATTESTATIONS.validate_policy(published.get("attestations"), published["digest"],
                                             BUILD_TYPE, lock["distribution"]["platforms"])
    if lock["distribution"]["publicationStatus"] == "verified" and any(
            image["distribution"].get("status") != "verified" for image in lock["images"].values()):
        raise ValueError("Verified SDK distribution requires all five verified component identities")
    if not OCI.DIGEST.fullmatch(lock["tools"]["sbomScanner"].split("@")[-1]):
        raise ValueError("SDK SBOM generator must be pinned by digest")
    return lock


def selected(args, lock):
    return list(lock["images"]) if args.component == "all" else [args.component]


def directory(args):
    output = args.evidence_dir.resolve()
    if not output.is_relative_to(ROOT / "artifacts"):
        raise ValueError("Evidence must stay in this repository's ignored artifacts directory")
    output.mkdir(parents=True, exist_ok=True)
    return output


def input_files(name, image):
    files = [ROOT / "instrumentation.lock.json", ROOT / "images/licenses/APACHE-2.0.txt",
             *sorted((ROOT / image["dockerfile"]).parent.rglob("*"))]
    if name == "operator":
        files += sorted((ROOT / image["sourceBuild"]["module"]).rglob("*"))
    return sorted(set(path for path in files if path.is_file() and "__pycache__" not in path.parts))


def build(args, lock):
    if not VERSION.fullmatch(args.version):
        raise ValueError("Use 1.x.y-dev/1.x.y-rc.N locally or v1.x.y for an approved release")
    platforms = args.platform.split(",")
    if not platforms or not set(platforms) <= set(lock["distribution"]["platforms"]):
        raise ValueError("Supported SDK build platforms: linux/amd64,linux/arm64")
    output = directory(args)
    revision, epoch, dirty = OCI.git_state()
    path = output / MANIFEST
    state = json.loads(path.read_text()) if path.exists() else {
        "version": args.version, "revision": revision, "sourceDateEpoch": int(epoch),
        "dirtySource": dirty, "builtAt": OCI.now(), "publicationStatus": "not-published", "images": {}}
    if state["revision"] != revision or state["version"] != args.version:
        raise ValueError("Use a fresh SDK evidence directory for a different revision/version")
    created = dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).isoformat()
    env = {**os.environ, "SOURCE_DATE_EPOCH": epoch, "BUILDX_METADATA_PROVENANCE": "max"}
    for name in selected(args, lock):
        image = lock["images"][name]
        hashes = {str(path.relative_to(ROOT)): OCI.sha256(path) for path in input_files(name, image)}
        archive, metadata = output / f"{name}.oci.tar", output / f"{name}.metadata.json"
        tag = image["distribution"]["repository"] + ":" + args.version
        command = ["docker", "buildx", "build", "--file", image["dockerfile"], "--platform", args.platform,
                   "--tag", tag, "--build-arg", "VERSION=" + args.version,
                   "--build-arg", "REVISION=" + revision, "--build-arg", "CREATED=" + created,
                   "--build-arg", "SOURCE_DATE_EPOCH=" + epoch, "--provenance=mode=max",
                   "--attest", "type=sbom,generator=" + lock["tools"]["sbomScanner"],
                   "--metadata-file", str(metadata), "--output", f"type=oci,dest={archive},rewrite-timestamp=true", "."]
        OCI.run(command, cwd=ROOT, env=env)
        after_hashes = {str(path.relative_to(ROOT)): OCI.sha256(path) for path in input_files(name, image)}
        if after_hashes != hashes:
            raise ValueError(f"{name}: SDK inputs changed during build; discard and retry")
        details = json.loads(metadata.read_text())
        digest = details.get("containerimage.digest", "")
        provenance = [value for key, value in details.items() if key.startswith("buildx.build.provenance")]
        if not OCI.DIGEST.fullmatch(digest) or not provenance or not all(provenance):
            raise ValueError(f"{name}: BuildKit did not record immutable digest and provenance")
        state["images"][name] = {"tag": tag, "digest": digest, "platforms": platforms,
            "archive": archive.name, "archiveSha256": OCI.sha256(archive),
            "metadata": metadata.name, "metadataSha256": OCI.sha256(metadata),
            "inputsSha256": hashes, "scans": {}}
        OCI.write_json(path, state)
        print(f"Built {name}: {digest}; independent SDK archive/SBOM/provenance recorded; not published")


def scan(args, lock):
    output = directory(args)
    state = json.loads((output / MANIFEST).read_text())
    env = {key: value for key, value in os.environ.items() if not key.startswith("TRIVY_")}
    version = json.loads(OCI.run(["trivy", "version", "--format", "json"], capture=True, env=env))
    if version.get("Version") != lock["tools"]["trivy"]:
        raise ValueError("Use the Trivy version pinned in instrumentation.lock.json")
    failed = []
    for name in selected(args, lock):
        image = state["images"][name]
        archive = output / image["archive"]
        if OCI.sha256(archive) != image["archiveSha256"]:
            raise ValueError("SDK archive changed after build")
        with tempfile.TemporaryDirectory(prefix="elven-sdk-scan-", dir=output) as temporary:
            OCI.unpack_layout(archive, temporary, image["digest"])
            for platform in image["platforms"]:
                suffix = platform.replace("/", "-")
                report, sbom = output / f"{name}.{suffix}.vulnerabilities.json", output / f"{name}.{suffix}.spdx.json"
                common = ["trivy", "image", "--input", temporary, "--platform", platform, "--scanners", "vuln",
                          "--timeout", "30m", "--config", "/dev/null", "--ignorefile", "/dev/null", "--ignore-unfixed=false"]
                OCI.run(common + ["--format", "json", "--output", str(report)], env=env)
                OCI.run(common + ["--format", "spdx-json", "--output", str(sbom)], env=env)
                records = [v for result in json.loads(report.read_text()).get("Results", [])
                           for v in result.get("Vulnerabilities", [])]
                high = sum(v.get("Severity") in ("HIGH", "CRITICAL") for v in records)
                database = json.loads(OCI.run(["trivy", "version", "--format", "json"], capture=True, env=env)).get("VulnerabilityDB", {})
                age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(database["UpdatedAt"].replace("Z", "+00:00"))
                if age > dt.timedelta(hours=48) or OCI.sha256(archive) != image["archiveSha256"]:
                    raise ValueError("Stale DB or changed SDK OCI bytes cannot pass")
                image["scans"][platform] = {"status": "failed" if high else "passed", "highCriticalCount": high,
                    "scanner": "trivy/" + version["Version"], "scannedAt": OCI.now(), "database": database,
                    "report": report.name, "reportSha256": OCI.sha256(report), "sbom": sbom.name, "sbomSha256": OCI.sha256(sbom)}
                OCI.write_json(output / MANIFEST, state)
                print(f"{name} {platform}: HIGH/CRITICAL={high}; all severities and SPDX retained")
                if high:
                    failed.append(name + "/" + platform)
    if failed:
        raise ValueError("SDK publication blocked by HIGH/CRITICAL vulnerabilities: " + ", ".join(failed))


def verify_reference(reference, version, lock, policy=None):
    if not isinstance(reference, str) or "@" not in reference:
        raise ValueError("SDK verification requires an immutable image reference")
    digest = reference.rsplit("@", 1)[1]
    if policy is None:
        approved = next((image["distribution"] for image in lock["images"].values()
                         if image["distribution"].get("repository", "") + "@"
                         + str(image["distribution"].get("digest")) == reference), None)
        if approved is None or approved.get("status") != "verified":
            raise ValueError("SDK exact signed-predicate hashes are missing from the promoted lock")
        policy = approved.get("attestations")
        version = version or approved.get("tag")
    OCI.ATTESTATIONS.validate_policy(policy, digest, BUILD_TYPE)
    tool = json.loads(OCI.run(["cosign", "version", "--json"], capture=True))
    if tool.get("gitVersion") != "v" + lock["tools"]["cosign"]:
        raise ValueError("Use the independently pinned SDK Cosign version")
    if version is not None and not re.fullmatch(r"v1\.[0-9]+\.[0-9]+", version):
        raise ValueError("SDK signing identity must be a stable release tag")
    identity = ("^" + re.escape(f"https://github.com/{REPOSITORY}/{WORKFLOW}@refs/tags/{version}") + "$"
                if version else r"^https://github\.com/elven-observability/stack-observability-k8s/\.github/workflows/instrumentation\.yaml@refs/tags/v1\.[0-9]+\.[0-9]+$")
    flags = ["--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "--certificate-identity-regexp", identity]
    with OCI.anonymous_registry() as env:
        OCI.run(["cosign", "verify", *flags, reference], capture=True, env=env)
        for kind in ("spdxjson", BUILD_TYPE):
            output = OCI.run(["cosign", "verify-attestation", *flags, "--type", kind, reference], capture=True, env=env)
            predicate_type = OCI.ATTESTATIONS.SPDX_TYPE if kind == "spdxjson" else BUILD_TYPE
            OCI.ATTESTATIONS.verify_predicates(output, policy, digest, predicate_type, BUILD_TYPE)


def verify(args, lock):
    if lock["distribution"]["publicationStatus"] != "verified":
        raise ValueError("SDK distribution has no verified publication; production injection is blocked")
    for name in selected(args, lock):
        image = lock["images"][name]["distribution"]
        if image.get("status") != "verified" or not image.get("digest"):
            raise ValueError(f"{name}: no signed and promoted Elven SDK image")
        verify_reference(image["repository"] + "@" + image["digest"], image.get("tag"), lock, image.get("attestations"))
        print(f"Verified independent Elven instrumentation image: {name}")


def publish(args, lock):
    output = directory(args)
    state = json.loads((output / MANIFEST).read_text())
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or not re.fullmatch(r"v1\.[0-9]+\.[0-9]+", state["version"])
            or os.environ.get("GITHUB_REF") != "refs/tags/" + state["version"]):
        raise ValueError("Local SDK publication forbidden; use the protected stable release workflow")
    protection = json.loads(OCI.run(["gh", "api", f"repos/{REPOSITORY}/environments/{ENVIRONMENT}"], capture=True))
    if not any(x.get("type") == "required_reviewers" and x.get("reviewers") for x in protection.get("protection_rules", [])):
        raise ValueError("SDK publication requires a protected environment with required reviewers")
    revision, _, dirty = OCI.git_state()
    if dirty or state["dirtySource"] or state["revision"] != revision or set(state["images"]) != set(REPOSITORIES):
        raise ValueError("SDK publication requires clean unchanged sources and all five images")
    for name, image in state["images"].items():
        if image["tag"] != REPOSITORIES[name] + ":" + state["version"]:
            raise ValueError("Unexpected SDK publication target")
        if set(image["platforms"]) != set(lock["distribution"]["platforms"]):
            raise ValueError("Both SDK architectures must be built and scanned")
        for file_key in ("archive", "metadata"):
            if OCI.sha256(output / image[file_key]) != image[file_key + "Sha256"]:
                raise ValueError("SDK evidence checksum mismatch")
        for path, value in image["inputsSha256"].items():
            if OCI.sha256(ROOT / path) != value:
                raise ValueError("SDK build inputs changed before publication")
        for platform in image["platforms"]:
            entry = image["scans"].get(platform, {})
            if entry.get("status") != "passed" or entry.get("highCriticalCount") != 0 or entry.get("scanner") != "trivy/" + lock["tools"]["trivy"]:
                raise ValueError("Every SDK image/architecture needs a successful pinned scan")
            if dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(entry["scannedAt"]) > dt.timedelta(hours=24):
                raise ValueError("SDK scan evidence is stale")
            if dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(entry["database"]["UpdatedAt"].replace("Z", "+00:00")) > dt.timedelta(hours=48):
                raise ValueError("SDK scanner database is stale")
            for key in ("report", "sbom"):
                if OCI.sha256(output / entry[key]) != entry[key + "Sha256"]:
                    raise ValueError("SDK scan/SBOM evidence checksum mismatch")
    policies = {name: OCI.ATTESTATIONS.evidence_policy(output, image, BUILD_TYPE,
                                                      lock["distribution"]["platforms"])
                for name, image in state["images"].items()}
    existing = OCI.preflight_remote_tags(state["images"])
    for name, image in state["images"].items():
        if name not in existing:
            with tempfile.TemporaryDirectory(prefix="elven-sdk-publish-", dir=output) as temporary:
                OCI.unpack_layout(output / image["archive"], temporary, image["digest"])
                OCI.run(["crane", "push", "--index", temporary, image["tag"]])
        reference = REPOSITORIES[name] + "@" + image["digest"]
        with OCI.anonymous_registry() as env:
            if OCI.run(["crane", "digest", image["tag"]], capture=True, env=env) != image["digest"]:
                raise ValueError("Published SDK digest differs or is not publicly pullable")
            for platform in image["platforms"]:
                OCI.run(["crane", "validate", "--platform", platform, "--remote", reference], env=env)
        OCI.run(["cosign", "sign", "--yes", reference])
        for entry in image["scans"].values():
            OCI.run(["cosign", "attest", "--yes", "--type", "spdxjson", "--predicate", str(output / entry["sbom"]), reference])
        OCI.run(["cosign", "attest", "--yes", "--type", BUILD_TYPE, "--predicate", str(output / image["metadata"]), reference])
        verify_reference(reference, state["version"], lock, policies[name])
        image["attestations"] = policies[name]
        image["publicationStatus"] = "verified"
        OCI.write_json(output / MANIFEST, state)
    state["publicationStatus"] = "verified"
    OCI.write_json(output / MANIFEST, state)


def promote(args, lock):
    output = directory(args)
    state = json.loads((output / MANIFEST).read_text())
    if state.get("publicationStatus") != "verified" or set(state["images"]) != set(REPOSITORIES):
        raise ValueError("No complete verified SDK publication exists; never invent Elven digests")
    for name, image in state["images"].items():
        reference = REPOSITORIES[name] + "@" + image["digest"]
        policy = OCI.ATTESTATIONS.evidence_policy(output, image, BUILD_TYPE, lock["distribution"]["platforms"])
        if image.get("attestations") != policy:
            raise ValueError("Published SDK attestation policy differs from approved evidence")
        verify_reference(reference, state["version"], lock, policy)
        for platform in lock["distribution"]["platforms"]:
            with OCI.anonymous_registry() as env:
                config = json.loads(OCI.run(["crane", "config", "--platform", platform, reference], capture=True, env=env))
            labels = config.get("config", {}).get("Labels", {})
            if labels.get("org.opencontainers.image.revision") != state["revision"]:
                raise ValueError("SDK image source revision differs from the approved release")
            if name != "operator" and labels.get("org.opencontainers.image.base.digest") != lock["images"][name]["upstream"]["digest"]:
                raise ValueError("SDK image upstream base differs from its approved pin")
        lock["images"][name]["distribution"].update(digest=image["digest"], status="verified", tag=state["version"], sourceRevision=state["revision"], verifiedAt=OCI.now(), attestations=policy)
    lock["distribution"].update(publicationStatus="verified", version=state["version"].removeprefix("v"))
    OCI.write_json(output / "instrumentation.promoted.lock.json", lock)
    print("Verified independent SDK promotion candidate written; source lock/chart/customer cluster unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "build", "scan", "verify", "publish", "promote"))
    parser.add_argument("--component", choices=("all", *REPOSITORIES), default="all")
    parser.add_argument("--lock", type=Path, default=ROOT / "instrumentation.lock.json")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "artifacts/instrumentation")
    parser.add_argument("--version", default="1.0.1-dev")
    parser.add_argument("--platform", default="linux/amd64,linux/arm64")
    args = parser.parse_args()
    lock = read_lock(args.lock)
    if args.command == "check":
        print("Independent operator/SDK recipe check only; historical publication="
              + lock["distribution"]["publicationStatus"] + "; runtime/release acceptance not implied")
    elif args.command == "verify":
        verify(args, lock)
    else:
        with (directory(args) / ".instrumentation.lock").open("a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            {"build": build, "scan": scan, "publish": publish, "promote": promote}[args.command](args, lock)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as error:
        sys.exit(str(error))
