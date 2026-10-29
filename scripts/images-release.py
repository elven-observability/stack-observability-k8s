#!/usr/bin/env python3
"""Build, scan, verify and promote pinned Elven OCI wrappers; never deploy Kubernetes."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "versions.lock.json"
REPOSITORY = "elven-observability/stack-observability-k8s"
WORKFLOW = ".github/workflows/images.yaml"
ENVIRONMENT = "elven-distribution-release"
IDENTITY_RE = r"^https://github\.com/elven-observability/stack-observability-k8s/\.github/workflows/images\.yaml@refs/tags/v1\.[0-9]+\.[0-9]+$"
BUILD_TYPE = "https://elvenobservability.com/attestations/build/v1"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
VERSION = re.compile(r"v?1\.[0-9]+\.[0-9]+(?:-dev)?\Z")
APPROVED_REPOSITORIES = {
    "collector": "docker.io/elvenobservability/elven-collector",
    "beyla": "docker.io/elvenobservability/elven-ebpf",
    "alloy": "docker.io/elvenobservability/elven-profiler",
}


def run(command, capture=False, **kwargs):
    result = subprocess.run(command, text=True, capture_output=capture, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command failed (exit {result.returncode}): {command[0]} {command[1] if len(command) > 1 else ''}")
    return result.stdout.strip() if capture else None


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def source_ref(image):
    source = image["upstream"]
    return f"{source['repository']}:{source['tag']}@{source['digest']}"


def lock_data():
    lock = json.loads(LOCK.read_text())
    if lock.get("schemaVersion") != 1 or set(lock.get("images", {})) != {"collector", "beyla", "alloy"}:
        raise ValueError("Unrecognized image lock schema/components")
    for name, image in lock["images"].items():
        source = image["upstream"]
        if not DIGEST.fullmatch(source["digest"]) or source["tag"] == "latest":
            raise ValueError(f"{name}: immutable upstream image required")
        if image["distribution"]["repository"] != APPROVED_REPOSITORIES[name]:
            raise ValueError(f"{name}: repository must match its approved Elven runtime identity")
        if source_ref(image) not in (ROOT / image["dockerfile"]).read_text():
            raise ValueError(f"{name}: Dockerfile and image lock disagree")
        if image.get("sourceBuild"):
            recipe = image["sourceBuild"]
            if recipe["goImage"] not in (ROOT / image["dockerfile"]).read_text():
                raise ValueError(f"{name}: Go toolchain pin differs between Dockerfile and lock")
            if not (ROOT / recipe["manifest"]).is_file():
                raise ValueError(f"{name}: missing minimal component build manifest")
        digest = image["distribution"].get("digest")
        if digest is not None and not DIGEST.fullmatch(digest):
            raise ValueError(f"{name}: invalid distribution digest")
    if not re.fullmatch(r"docker.io/docker/buildkit-syft-scanner@sha256:[0-9a-f]{64}", lock["tools"]["sbomScanner"]):
        raise ValueError("The SBOM generator must be locked by digest")
    return lock


def components(args, lock):
    return list(lock["images"]) if args.component == "all" else [args.component]


def evidence(args):
    directory = args.evidence_dir.resolve()
    if not directory.is_relative_to(ROOT / "artifacts"):
        raise ValueError("Evidence must remain in this repository's ignored artifacts/ directory")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def git_state():
    revision = run(["git", "rev-parse", "HEAD"], capture=True, cwd=ROOT)
    epoch = run(["git", "show", "-s", "--format=%ct", "HEAD"], capture=True, cwd=ROOT)
    dirty = bool(run(["git", "status", "--porcelain"], capture=True, cwd=ROOT))
    return revision, epoch, dirty


def load_manifest(directory):
    return json.loads((directory / "release.json").read_text())


@contextlib.contextmanager
def evidence_lock(args):
    # Avoid associating one build's scan with an archive concurrently rebuilt
    # by another local process. Linux/macOS publisher tooling only.
    with (evidence(args) / ".release.lock").open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def build(args, lock):
    if not VERSION.fullmatch(args.version):
        raise ValueError("Use v1.x.y for a release, or 1.x.y-dev for local verification")
    platforms = args.platform.split(",")
    if not platforms or not set(platforms) <= set(lock["distribution"]["platforms"]):
        raise ValueError("Supported build platforms: linux/amd64,linux/arm64")
    directory = evidence(args)
    revision, epoch, dirty = git_state()
    manifest_path = directory / "release.json"
    if manifest_path.exists():
        manifest = load_manifest(directory)
        if manifest["version"] != args.version or manifest["revision"] != revision:
            raise ValueError("Use a fresh evidence directory for a different source revision/version")
    else:
        manifest = {"version": args.version, "revision": revision, "sourceDateEpoch": int(epoch),
                    "dirtySource": dirty, "builtAt": now(), "publicationStatus": "not-published", "images": {}}
    created = dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).isoformat()
    env = {**os.environ, "SOURCE_DATE_EPOCH": epoch, "BUILDX_METADATA_PROVENANCE": "max"}
    for name in components(args, lock):
        image = lock["images"][name]
        context_files = [ROOT / "images/licenses/APACHE-2.0.txt", *sorted((ROOT / image["dockerfile"]).parent.rglob("*"))]
        input_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in context_files if path.is_file()}
        recipe_digest = sha256(ROOT / image["sourceBuild"]["manifest"]) if image.get("sourceBuild") else None
        archive, metadata = directory / f"{name}.oci.tar", directory / f"{name}.metadata.json"
        tag = f"{image['distribution']['repository']}:{args.version}"
        command = ["docker", "buildx", "build", "--file", image["dockerfile"], "--platform", args.platform,
                   "--tag", tag, "--build-arg", f"VERSION={args.version}", "--build-arg", f"REVISION={revision}",
                   "--build-arg", f"CREATED={created}", "--build-arg", f"SOURCE_DATE_EPOCH={epoch}",
                   "--build-arg", f"UPSTREAM_IMAGE={source_ref(image)}", "--provenance=mode=max",
                   "--attest", f"type=sbom,generator={lock['tools']['sbomScanner']}",
                   "--metadata-file", str(metadata),
                   "--output", f"type=oci,dest={archive},rewrite-timestamp=true", "."]
        run(command, cwd=ROOT, env=env)
        if any(not (ROOT / path).is_file() or sha256(ROOT / path) != digest for path, digest in input_hashes.items()):
            raise ValueError(f"{name}: build inputs changed during execution; retry before claiming source provenance")
        build_metadata = json.loads(metadata.read_text())
        digest = build_metadata.get("containerimage.digest", "")
        provenance = {key: value for key, value in build_metadata.items() if key.startswith("buildx.build.provenance")}
        if not DIGEST.fullmatch(digest) or not provenance or not all(provenance.values()):
            raise ValueError(f"{name}: BuildKit did not produce digest and provenance")
        manifest["images"][name] = {"archive": archive.name, "archiveSha256": sha256(archive),
                                    "metadata": metadata.name, "metadataSha256": sha256(metadata),
                                    "digest": digest, "tag": tag, "platforms": platforms,
                                    "upstream": source_ref(image), "scans": {},
                                    "sourceBuild": image.get("sourceBuild"),
                                    "recipeSha256": recipe_digest, "inputsSha256": input_hashes}
        write_json(manifest_path, manifest)
        print(f"Built {name}: {digest}; OCI archive, SBOM and BuildKit provenance recorded; not published.")


def scan(args, lock):
    directory = evidence(args)
    manifest = load_manifest(directory)
    scan_env = {key: value for key, value in os.environ.items() if not key.startswith("TRIVY_")}
    scanner = json.loads(run(["trivy", "version", "--format", "json"], capture=True, env=scan_env))
    if scanner.get("Version") != lock["tools"]["trivy"]:
        raise ValueError("Use the Trivy version recorded in versions.lock.json")
    failed = []
    for name in components(args, lock):
        image = manifest["images"][name]
        archive = directory / image["archive"]
        if sha256(archive) != image["archiveSha256"]:
            raise ValueError(f"{name}: archive checksum changed after build")
        # Trivy reads an OCI layout directory, not a BuildKit OCI tar archive.
        with tempfile.TemporaryDirectory(prefix="elven-scan-", dir=directory) as folder:
            unpack_layout(archive, folder, image["digest"])
            for platform in image["platforms"]:
                suffix = platform.replace("/", "-")
                report, sbom = directory / f"{name}.{suffix}.vulnerabilities.json", directory / f"{name}.{suffix}.spdx.json"
                common = ["trivy", "image", "--input", folder, "--platform", platform, "--scanners", "vuln",
                          "--config", "/dev/null", "--ignorefile", "/dev/null", "--ignore-unfixed=false"]
                run(common + ["--format", "json", "--output", str(report)], env=scan_env)
                report_data = json.loads(report.read_text())
                vulnerabilities = [v for result in report_data.get("Results", []) for v in result.get("Vulnerabilities", [])
                                   if v.get("Severity") in ("HIGH", "CRITICAL")]
                run(common + ["--format", "spdx-json", "--output", str(sbom)], env=scan_env)
                if sha256(archive) != image["archiveSha256"]:
                    raise ValueError(f"{name}: OCI bytes changed during scan; discard stale results")
                database = json.loads(run(["trivy", "version", "--format", "json"], capture=True, env=scan_env)).get("VulnerabilityDB", {})
                updated = database.get("UpdatedAt")
                if not updated or dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(updated.replace("Z", "+00:00")) > dt.timedelta(hours=48):
                    raise ValueError("Missing or stale vulnerability DB metadata; scan cannot pass")
                image["scans"][platform] = {"status": "failed" if vulnerabilities else "passed",
                    "scanner": f"trivy/{scanner['Version']}", "scannedAt": now(),
                    "database": database,
                    "report": report.name, "reportSha256": sha256(report), "sbom": sbom.name,
                    "sbomSha256": sha256(sbom), "highCriticalCount": len(vulnerabilities)}
                write_json(directory / "release.json", manifest)
                print(f"{name} {platform}: HIGH/CRITICAL={len(vulnerabilities)}; full report and SPDX saved.")
                if vulnerabilities:
                    failed.append(f"{name}/{platform}")
    if failed:
        raise ValueError("Release blocked by HIGH/CRITICAL vulnerabilities: " + ", ".join(failed))


def govulncheck(args, lock):
    directory = evidence(args)
    manifest = load_manifest(directory)
    image = manifest["images"]["collector"]
    if sha256(directory / image["archive"]) != image["archiveSha256"]:
        raise ValueError("Collector OCI changed after build")
    version = lock["tools"]["govulncheck"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("govulncheck must be an explicit stable version")
    image_ref = image["tag"] + "@" + image["digest"]
    with tempfile.TemporaryDirectory(prefix="elven-go-audit-", dir=directory) as folder:
        inputs, output = Path(folder) / "inputs", Path(folder) / "output"
        inputs.mkdir(mode=0o755)
        output.mkdir(mode=0o777)
        output.chmod(0o777)  # disposable reports only, no production credentials
        names = []
        binary_hashes = {}
        license_bundles = {}
        for platform in image["platforms"]:
            name = platform.replace("/", "-")
            names.append(name)
            container = run(["docker", "create", "--platform", platform, "--entrypoint", "/elven-collector", image_ref, "--version"], capture=True)
            if not re.fullmatch(r"[0-9a-f]{64}", container):
                raise ValueError("Unexpected disposable container identity")
            try:
                run(["docker", "cp", container + ":/elven-collector", str(inputs / name)])
                notices = inputs / (name + "-licenses")
                run(["docker", "cp", container + ":/usr/share/licenses/elven-collector/dependencies", str(notices)])
                inventory_path = notices / "MANIFEST.json"
                inventory = json.loads(inventory_path.read_text())
                modules = set()
                for entry in inventory:
                    module_name = (entry["Module"] + "@" + entry["Version"]).replace("/", "__").replace("\\", "__").replace(":", "_")
                    member = (notices / module_name / entry["File"]).resolve()
                    if not member.is_relative_to(notices.resolve()) or sha256(member) != entry["SHA256"]:
                        raise ValueError("Collector dependency license text does not match its inventory")
                    modules.add(entry["Module"])
                if len(inventory) < 10 or len(modules) < 10 or "go-stdlib" not in modules:
                    raise ValueError("Collector dependency license bundle is incomplete")
                report = directory / f"collector.{name}.licenses.json"
                shutil.copyfile(inventory_path, report)
                license_bundles[platform] = {"status": "passed", "image": image_ref,
                    "verifiedNoticeCount": len(inventory), "modulesWithNotices": len(modules),
                    "report": report.name, "reportSha256": sha256(report)}
            finally:
                run(["docker", "rm", container], capture=True)
            (inputs / name).chmod(0o444)
            binary_hashes[platform] = sha256(inputs / name)
        script = (f"go install golang.org/x/vuln/cmd/govulncheck@v{version} || exit 1; result=0; "
                  + "for platform in " + " ".join(names) + "; do "
                  + '/tmp/gopath/bin/govulncheck -mode=binary -json "/target/$platform" > "/out/$platform.json"; '
                  + 'status=$?; printf "%s\\n" "$status" > "/out/$platform.status"; '
                  + 'if [ "$status" -ne 0 ]; then result=1; fi; done; exit "$result"')
        command = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,exec,size=1024m", "-e", "GOMAXPROCS=2", "-e", "GOGC=50",
            "-e", "GOPROXY=https://proxy.golang.org", "-e", "GOSUMDB=sum.golang.org", "-e", "GOTOOLCHAIN=local",
            "-e", "GOCACHE=/tmp/cache", "-e", "GOPATH=/tmp/gopath", "-e", "GOTELEMETRY=off",
            "-e", "GOVULNDB=https://vuln.go.dev", "--mount", f"type=bind,source={inputs.resolve()},target=/target,readonly",
            "--mount", f"type=bind,source={output.resolve()},target=/out", lock["images"]["collector"]["sourceBuild"]["goImage"], "sh", "-c", script]
        with (directory / "govulncheck-tool.log").open("w") as log:
            result = subprocess.run(command, text=True, stdout=log, stderr=subprocess.STDOUT)
        image["govulncheck"] = {}
        image["licenseBundles"] = license_bundles
        for platform in image["platforms"]:
            name = platform.replace("/", "-")
            report = directory / f"collector.{name}.govulncheck.json"
            source, status = output / f"{name}.json", output / f"{name}.status"
            if not source.is_file() or not status.is_file():
                continue
            shutil.copyfile(source, report)
            code = int(status.read_text().strip())
            image["govulncheck"][platform] = {"status": "passed" if code == 0 else "failed", "exitCode": code,
                "tool": "govulncheck/" + version, "mode": "binary-symbol-analysis-not-native-execution",
                "scannedAt": now(), "binarySha256": binary_hashes[platform], "report": report.name,
                "reportSha256": sha256(report), "image": image_ref}
        write_json(directory / "release.json", manifest)
        if result.returncode or len(image["govulncheck"]) != len(image["platforms"]):
            raise ValueError("Go vulnerability analysis failed or found vulnerable symbols; inspect govulncheck reports")
        print("govulncheck binary-symbol analysis passed for: " + ", ".join(image["platforms"]))


def assert_release_environment(version):
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or not re.fullmatch(r"v1\.[0-9]+\.[0-9]+", version)
            or os.environ.get("GITHUB_REF") != f"refs/tags/{version}"):
        raise ValueError("Publication requires this repository's protected v1.x.y release-tag workflow; local push is forbidden")
    rules = json.loads(run(["gh", "api", f"repos/{REPOSITORY}/environments/{ENVIRONMENT}"], capture=True))
    if not any(rule.get("type") == "required_reviewers" and rule.get("reviewers") for rule in rules.get("protection_rules", [])):
        raise ValueError(f"Configure required reviewers on environment {ENVIRONMENT}; unprotected/auto-created environments cannot publish")


@contextlib.contextmanager
def anonymous_registry():
    # A release must be pullable without borrowing the publisher's Docker PAT.
    with tempfile.TemporaryDirectory(prefix="elven-anonymous-registry-") as folder:
        Path(folder, "config.json").write_text('{"auths":{}}\n')
        yield {**os.environ, "DOCKER_CONFIG": folder}


def verify_image(reference, version=None):
    tool = json.loads(run(["cosign", "version", "--json"], capture=True))
    if tool.get("gitVersion") != "v" + lock_data()["tools"]["cosign"]:
        raise ValueError("Use the Cosign version pinned in versions.lock.json")
    identity = IDENTITY_RE if version is None else "^" + re.escape(f"https://github.com/{REPOSITORY}/{WORKFLOW}@refs/tags/{version}") + "$"
    expected = ["--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                "--certificate-identity-regexp", identity]
    with anonymous_registry() as env:
        run(["cosign", "verify", *expected, reference], capture=True, env=env)
        for attestation in ("spdxjson", BUILD_TYPE):
            run(["cosign", "verify-attestation", *expected, "--type", attestation, reference], capture=True, env=env)


def unpack_layout(archive_path, folder, expected_digest):
    with tarfile.open(archive_path) as archive:
        archive.extractall(folder, filter="data")
    # OCI archives contain an outer layout index pointing to the actual image
    # index. Push that exact inner index, not an extra index around the image.
    blob = Path(folder) / "blobs/sha256" / expected_digest.removeprefix("sha256:")
    raw = blob.read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("OCI manifest content does not match the BuildKit digest")
    if not json.loads(raw).get("manifests"):
        raise ValueError("Expected an OCI image index with native SBOM/provenance descriptors")
    (Path(folder) / "index.json").write_bytes(raw)


def publish(args, lock):
    directory = evidence(args)
    manifest = load_manifest(directory)
    assert_release_environment(manifest["version"])
    revision, _, dirty = git_state()
    if manifest["dirtySource"] or dirty or manifest["revision"] != revision:
        raise ValueError("Publication requires clean, unchanged release sources")
    if set(manifest["images"]) != set(lock["images"]):
        raise ValueError("All three distribution images must be built before publishing")
    # Validate every component before publishing any component.
    for name, image in manifest["images"].items():
        if set(image["platforms"]) != set(lock["distribution"]["platforms"]):
            raise ValueError(f"{name}: both supported platforms must be built and scanned")
        for file_key, checksum_key in (("archive", "archiveSha256"), ("metadata", "metadataSha256")):
            if sha256(directory / image[file_key]) != image[checksum_key]:
                raise ValueError(f"{name}: evidence checksum mismatch")
        for platform in image["platforms"]:
            entry = image["scans"].get(platform, {})
            if entry.get("status") != "passed" or entry.get("highCriticalCount") != 0:
                raise ValueError(f"{name}: missing/pending/failed vulnerability gate for {platform}")
            if entry.get("scanner") != f"trivy/{lock['tools']['trivy']}":
                raise ValueError(f"{name}: scan used an unapproved scanner version")
            age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(entry["scannedAt"])
            db_age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(entry["database"]["UpdatedAt"].replace("Z", "+00:00"))
            if age > dt.timedelta(hours=24) or db_age > dt.timedelta(hours=48):
                raise ValueError(f"{name}: approval outlived fresh scan evidence; rerun build/scan before publication")
            for key in ("report", "sbom"):
                if sha256(directory / entry[key]) != entry[key + "Sha256"]:
                    raise ValueError(f"{name}: scan evidence checksum mismatch")
        if name == "collector":
            for platform in image["platforms"]:
                licenses = image.get("licenseBundles", {}).get(platform, {})
                if (licenses.get("status") != "passed" or licenses.get("image") != image["tag"] + "@" + image["digest"]
                        or licenses.get("verifiedNoticeCount", 0) < 10
                        or sha256(directory / licenses["report"]) != licenses["reportSha256"]):
                    raise ValueError("Collector requires a verified dependency license payload from the exact OCI image")
                go_audit = image.get("govulncheck", {}).get(platform, {})
                if go_audit.get("status") != "passed" or go_audit.get("tool") != "govulncheck/" + lock["tools"]["govulncheck"]:
                    raise ValueError("Collector requires successful current govulncheck symbol analysis on both binaries")
                if go_audit.get("image") != image["tag"] + "@" + image["digest"]:
                    raise ValueError("Collector Go audit does not identify this exact OCI image")
                if dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(go_audit["scannedAt"]) > dt.timedelta(hours=24):
                    raise ValueError("Collector Go audit is stale; rerun before publication")
                if sha256(directory / go_audit["report"]) != go_audit["reportSha256"]:
                    raise ValueError("Collector govulncheck report checksum mismatch")
    for name, image in manifest["images"].items():
        with tempfile.TemporaryDirectory(prefix="elven-oci-", dir=directory) as folder:
            unpack_layout(directory / image["archive"], folder, image["digest"])
            run(["crane", "push", "--index", folder, image["tag"]])
        repository = lock["images"][name]["distribution"]["repository"]
        digest = run(["crane", "digest", image["tag"]], capture=True)
        if digest != image["digest"]:
            raise ValueError(f"{name}: registry digest does not match the scanned OCI artifact; do not promote")
        reference = f"{repository}@{digest}"
        with anonymous_registry() as env:
            for platform in image["platforms"]:
                run(["crane", "validate", "--platform", platform, "--remote", reference], env=env)
        run(["cosign", "sign", "--yes", reference])
        for entry in image["scans"].values():
            run(["cosign", "attest", "--yes", "--type", "spdxjson", "--predicate", str(directory / entry["sbom"]), reference])
        run(["cosign", "attest", "--yes", "--type", BUILD_TYPE, "--predicate", str(directory / image["metadata"]), reference])
        verify_image(reference, manifest["version"])
        image["publicationStatus"] = "verified"
        write_json(directory / "release.json", manifest)
        print(f"Published and signature/attestation verified: {reference}")
    manifest["publicationStatus"] = "verified"
    write_json(directory / "release.json", manifest)


def promote(args, lock):
    directory = evidence(args)
    manifest = load_manifest(directory)
    if manifest.get("publicationStatus") != "verified":
        raise ValueError("No verified publication exists; never invent Elven digests")
    if set(manifest["images"]) != set(lock["images"]):
        raise ValueError("Promotion requires the complete three-image distribution")
    for name, image in manifest["images"].items():
        source = lock["images"][name]
        reference = f"{source['distribution']['repository']}@{image['digest']}"
        with anonymous_registry() as env:
            if run(["crane", "digest", reference], capture=True, env=env) != image["digest"]:
                raise ValueError(f"{name}: public registry content missing or inconsistent")
        verify_image(reference, manifest["version"])
        for platform in lock["distribution"]["platforms"]:
            with anonymous_registry() as env:
                config = json.loads(run(["crane", "config", "--platform", platform, reference], capture=True, env=env))
            labels = config.get("config", {}).get("Labels", {})
            upstream_label = "org.elvenobservability.ca-source.digest" if source.get("sourceBuild") else "org.opencontainers.image.base.digest"
            if (labels.get(upstream_label) != source["upstream"]["digest"]
                    or labels.get("org.opencontainers.image.revision") != manifest["revision"]):
                raise ValueError(f"{name}: unexpected upstream/source revision for {platform}")
        source["distribution"].update({"digest": image["digest"], "tag": manifest["version"],
                                      "status": "verified", "verifiedAt": now(), "sourceRevision": manifest["revision"]})
    lock["distribution"].update({"publicationStatus": "verified", "version": manifest["version"].removeprefix("v")})
    output = directory / "versions.promoted.lock.json"
    write_json(output, lock)
    print(f"Verified promotion candidate: {output}. Review and commit lock/chart changes; no customer deployment performed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "build", "scan", "govulncheck", "publish", "verify", "promote"])
    parser.add_argument("--component", choices=["all", "collector", "beyla", "alloy"], default="all")
    parser.add_argument("--version", default="1.0.0-dev")
    parser.add_argument("--platform", default="linux/arm64", help="Explicit local architecture; release requires both linux/amd64,linux/arm64")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "artifacts/images")
    args = parser.parse_args()
    lock = lock_data()
    for command in ("docker",) if args.command == "build" else ():
        if not shutil.which(command):
            raise ValueError(f"Missing required tool: {command}")
    if args.command == "check":
        print("Image lock/Dockerfiles consistent; Elven publication status: " + lock["distribution"]["publicationStatus"])
    elif args.command == "verify":
        for name in components(args, lock):
            image = lock["images"][name]["distribution"]
            if not image.get("digest") or image.get("status") != "verified":
                raise ValueError(f"{name}: no promoted Elven image; production installation is blocked. Locked upstream images are for explicit --development-images laboratory use only")
            verify_image(f"{image['repository']}@{image['digest']}", image.get("tag"))
            print(f"Verified {name}: signature, SPDX and build metadata attestations")
    else:
        with evidence_lock(args):
            {"build": build, "scan": scan, "govulncheck": govulncheck, "publish": publish, "promote": promote}[args.command](args, lock)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as error:
        sys.exit(str(error))
