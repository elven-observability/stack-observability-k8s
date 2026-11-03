#!/usr/bin/env python3
"""Bound disk preparation to disposable GitHub-hosted Ubuntu image-build jobs.

Default mode is read-only. --prepare may remove only the three literal optional
preinstalled SDK directories below, and only when the 32 GiB build margin is
missing. This is an accident guard, not attestation against a machine admin.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
import sys


MINIMUM_FREE_BYTES = 32 * 1024**3
SDK_PATHS = (Path("/usr/local/lib/android"), Path("/usr/share/dotnet"), Path("/opt/ghc"))


class Failure(RuntimeError):
    pass


def require_hosted_runner():
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise Failure("Disk preparation is restricted to a disposable GitHub-hosted Linux/X64 runner.")
    user = pwd.getpwuid(os.getuid())
    if platform.system() != "Linux" or os.getuid() == 0 or user.pw_name != "runner":
        raise Failure("Unexpected runner OS/user; no SDK directory was removed.")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip("\"'")
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise Failure("Only the pinned Ubuntu 24.04 hosted runner is supported.")
    required = []
    for key in ("GITHUB_WORKSPACE", "RUNNER_TEMP"):
        value = os.environ.get(key, "")
        if not value or not Path(value).is_absolute():
            raise Failure(f"{key} must be an explicit absolute hosted-runner path.")
        required.append(Path(value).resolve())
    return required, Path(user.pw_dir).resolve()


def docker_root():
    try:
        result = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"],
                                text=True, capture_output=True, check=False, timeout=30)
    except subprocess.TimeoutExpired:
        raise Failure("Docker data-directory inspection timed out; no SDK directory was removed.") from None
    value = result.stdout.strip()
    if result.returncode or not value or "\n" in value or not Path(value).is_absolute():
        raise Failure("Cannot establish Docker's actual data directory; build will not start.")
    return Path(value).resolve()


def disk_report(paths):
    report = {}
    for path in paths:
        try:
            usage = os.statvfs(path)
        except OSError:
            raise Failure(f"Cannot measure the build filesystem at {path}; build will not start.") from None
        report[str(path)] = {"available_bytes": usage.f_bavail * usage.f_frsize,
                             "total_bytes": usage.f_blocks * usage.f_frsize}
    return report


def enough_space(report):
    return bool(report) and all(item["available_bytes"] >= MINIMUM_FREE_BYTES for item in report.values())


def overlaps(first, second):
    return first == second or first in second.parents or second in first.parents


def mount_points():
    result = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise Failure("Cannot validate runner mount boundaries.")
        value = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        result.append(Path(value))
    return result


def validate_targets(protected, mounts):
    """Validate the COMPLETE plan before the first privileged mutation."""
    available = []
    for target in SDK_PATHS:
        if not target.is_absolute() or target == Path("/") or any(overlaps(target, item) for item in protected):
            raise Failure("Optional SDK target overlaps a protected runner/build directory.")
        present = True
        for path in [*reversed(target.parents), target]:
            try:
                info = path.lstat()
            except FileNotFoundError:
                present = False
                break
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise Failure(f"Optional SDK target/ancestor is not a physical directory: {path}")
        if not present:
            continue
        if any(point == target or target in point.parents for point in mounts):
            raise Failure(f"Optional SDK target contains a mount boundary: {target}")
        available.append(target)
    return available


def prepare(*, mutate=False):
    build_paths, actual_home = require_hosted_runner()
    data_root = docker_root()
    paths = [*build_paths, data_root]
    report = disk_report(paths)
    result = {"minimum_free_bytes": MINIMUM_FREE_BYTES, "mode": "prepare" if mutate else "check-only",
              "before": report, "removed_sdk_paths": []}
    if enough_space(report):
        result["after"] = report
        return result
    if not mutate:
        raise Failure("Less than 32 GiB free for the bounded image build; check-only mode made no changes.")
    protected = [*paths, actual_home]
    if os.environ.get("HOME"):
        protected.append(Path(os.environ["HOME"]).resolve())
    plan = validate_targets(protected, mount_points())
    for target in plan:
        # Never a glob, workspace/home, Docker data root, generic root or caller
        # supplied target. GNU rm does not follow symlinks inside this SDK tree.
        command = ["/usr/bin/sudo", "--non-interactive", "--", "/usr/bin/rm", "--recursive",
                   "--one-file-system", "--preserve-root=all", "--", str(target)]
        try:
            completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=300)
        except subprocess.TimeoutExpired:
            raise Failure("Scoped hosted-runner SDK cleanup timed out; build will not start.") from None
        if completed.returncode:
            raise Failure("Scoped hosted-runner SDK cleanup failed; build will not start.")
        result["removed_sdk_paths"].append(str(target))
        report = disk_report(paths)
        if enough_space(report):
            result["after"] = report
            return result
    raise Failure("Runner still lacks 32 GiB free after scoped SDK preparation; build will not start.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="Allow scoped SDK cleanup on the validated ephemeral hosted runner only")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(mutate=args.prepare), indent=2))
    except (Failure, OSError) as error:
        print(f"Elven image-build disk guard: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
