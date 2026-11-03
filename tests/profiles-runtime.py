#!/usr/bin/env python3
"""Synthetic HTTPS/pprof -> rendered Alloy -> authenticated HTTPS sink.

No Kubernetes context, host networking, host PID, profiling probes or real
credentials are used. Both containers share an internal disposable network.
This proves a positive pprof transport path, not durable profile retention,
NetworkPolicy enforcement, private application coverage, or client ingestion.
"""
import argparse
import gzip
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

PYTHON_FIXTURE = "python:3.14.0-slim@sha256:0aecac02dc3d4c5dbb024b753af084cafe41f5416e02193f1ce345d671ec966e"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def number(field, value):
    return varint(field << 3) + varint(value)


def message(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value


def synthetic_pprof():
    """Minimal valid profile.proto with one synthetic sample and function."""
    profile = message(1, number(1, 1) + number(2, 2))
    profile += message(2, number(1, 1) + number(2, 1))
    profile += message(4, number(1, 1) + message(4, number(1, 1) + number(2, 42)))
    profile += message(5, number(1, 1) + number(2, 3) + number(3, 3) + number(4, 4))
    for text in ("", "samples", "count", "synthetic_function", "synthetic.go"):
        profile += message(6, text.encode())
    profile += number(9, time.time_ns()) + number(10, 1_000_000_000)
    return gzip.compress(profile)


def serve(folder):
    state = {"scrapes": 0, "posts": 0, "payload_bytes": 0, "authenticated_posts": 0,
             "mutual_tls_scrapes": 0}
    lock = threading.Lock()

    class Sink(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/evidence":
                with lock:
                    payload = json.dumps(state).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if not self.path.startswith("/debug/pprof/"):
                self.send_error(404)
                return
            payload = synthetic_pprof()
            with lock:
                state["scrapes"] += 1
                state["mutual_tls_scrapes"] += int(bool(self.connection.getpeercert()))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            payload = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            valid = (self.headers.get("Authorization") == "Bearer synthetic-profile-token"
                     and self.headers.get("X-Scope-OrgID") == "synthetic-profile-tenant")
            with lock:
                state["posts"] += 1
                state["payload_bytes"] += len(payload)
                state["authenticated_posts"] += int(valid)
            self.send_response(200 if valid else 401)
            self.send_header("Content-Type", "application/proto")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    servers = []
    for port, mutual_tls in ((8443, True), (9443, False)):
        server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Sink)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(folder / "server/tls.crt", folder / "server/tls.key")
        if mutual_tls:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(folder / "server/ca.crt")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


def certificates(folder):
    ca, server, target = folder / "ca", folder / "server", folder / "target"
    for path in (folder, ca, server, target):
        path.mkdir(exist_ok=True)
        path.chmod(0o755)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=Elven-Synthetic-Profiles-CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.crt"))
    for name, path, purpose in (("profile-fixture", server, "serverAuth"), ("synthetic-client", target, "clientAuth")):
        prefix = "tls" if path == server else "client"
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
            "-keyout", str(path / (prefix + ".key")), "-out", str(path / "request.csr"))
        extensions = path / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\n"
                              "authorityKeyIdentifier=keyid,issuer\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=" + purpose
                              + ("\nsubjectAltName=DNS:profile-fixture\n" if path == server else "\n"))
        run("openssl", "x509", "-req", "-in", str(path / "request.csr"), "-CA", str(ca / "ca.crt"),
            "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(extensions),
            "-out", str(path / (prefix + ".crt")))
        shutil.copyfile(ca / "ca.crt", path / "ca.crt")
        # Synthetic files are readable by the non-root container user. Only
        # these disposable test keys are world-readable, never real Secrets.
        for file in path.iterdir():
            file.chmod(0o444)


def smoke(image_override=None):
    import yaml
    root = Path(__file__).resolve().parents[1]
    identity = "elven-profile-test-" + uuid.uuid4().hex[:12]
    network, fixture_name, alloy_name = identity, identity + "-fixture", identity + "-alloy"
    resources = []
    with tempfile.TemporaryDirectory(prefix="elven-profiles-runtime-") as temporary:
        folder = Path(temporary)
        certificates(folder)
        shutil.copyfile(Path(__file__), folder / "profiles-runtime.py")
        (folder / "profiles-runtime.py").chmod(0o444)
        args = ["helm", "template", "synthetic", str(root / "charts/elven-observability"),
                "--namespace", "elven-synthetic", "--kube-version", "1.37.0",
                "--set", "networkPolicy.enabled=false",
                "--set", "cluster.name=synthetic-profiles", "--set", "modules.profiles.enabled=true",
                "--set", "modules.profiles.dataPolicyApproved=true",
                "--set", "endpoints.profiles=https://profile-fixture:9443",
                "--set", "exportTLS.existingCASecret=synthetic-export-ca",
                "--set", "modules.profiles.targets[0].name=synthetic-service",
                "--set", "modules.profiles.targets[0].address=profile-fixture:8443",
                "--set", "modules.profiles.targets[0].scheme=https",
                "--set", "modules.profiles.targets[0].path=/debug/pprof",
                "--set", "modules.profiles.targets[0].secretName=synthetic-target-tls"]
        objects = list(yaml.safe_load_all(run(*args)))
        config = next(obj for obj in objects if obj and obj.get("kind") == "ConfigMap"
                      and "profile.alloy" in obj.get("data", {}))["data"]["profile.alloy"]
        pod = next(obj for obj in objects if obj and obj.get("kind") == "Deployment"
                   and obj["metadata"]["labels"].get("app.kubernetes.io/component") == "profiles")["spec"]["template"]["spec"]
        image = pod["containers"][0]["image"]
        if image_override:
            if "@sha256:" not in image_override:
                raise ValueError("The profile runtime image override must be digest-pinned")
            image = image_override
        if "@sha256:" not in image:
            raise AssertionError("Profile runtime must be pinned by digest")
        config_file = folder / "profile.alloy"
        config_file.write_text(config)
        config_file.chmod(0o444)
        try:
            run("docker", "network", "create", "--internal", network)
            resources.append(("network", network))
            run("docker", "run", "--detach", "--name", fixture_name, "--network", network,
                "--network-alias", "profile-fixture", "--user", "10001:10001", "--cap-drop", "ALL",
                "--read-only", "--security-opt", "no-new-privileges", "--memory", "128m", "--cpus", "0.5",
                "--mount", f"type=bind,source={folder},target=/fixture,readonly", PYTHON_FIXTURE,
                "python", "-u", "/fixture/profiles-runtime.py", "--serve", "/fixture")
            resources.append(("container", fixture_name))
            run("docker", "run", "--detach", "--name", alloy_name, "--network", network,
                "--network-alias", "elven-profiles", "--user", "10001:10001", "--cap-drop", "ALL",
                "--read-only", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "0.5",
                "--tmpfs", "/var/lib/elven:uid=10001,gid=10001,mode=0700,size=64m",
                "--mount", f"type=bind,source={config_file},target=/etc/elven/profile.alloy,readonly",
                "--mount", f"type=bind,source={folder / 'target'},target=/etc/elven/targets/0,readonly",
                "--mount", f"type=bind,source={folder / 'target'},target=/etc/elven/export-ca,readonly",
                "--env", "TENANT_ID=synthetic-profile-tenant", "--env", "API_TOKEN=synthetic-profile-token",
                image, *pod["containers"][0]["args"])
            resources.append(("container", alloy_name))
            query = ("import json,ssl,urllib.request; c=ssl.create_default_context(cafile='/fixture/server/ca.crt');"
                     "print(urllib.request.urlopen('https://profile-fixture:9443/evidence',context=c,timeout=3).read().decode())")
            deadline, evidence = time.monotonic() + 100, {}
            while time.monotonic() < deadline:
                state = json.loads(run("docker", "inspect", alloy_name))[0]["State"]
                if not state["Running"]:
                    raise AssertionError("Alloy exited before positive profile delivery; inspect synthetic container logs")
                try:
                    evidence = json.loads(run("docker", "exec", fixture_name, "python", "-c", query))
                except subprocess.CalledProcessError:
                    time.sleep(0.25)
                    continue
                if evidence.get("authenticated_posts", 0) > 0:
                    break
                time.sleep(0.5)
            if (evidence.get("scrapes", 0) < 1 or evidence.get("payload_bytes", 0) < 1
                    or evidence.get("authenticated_posts", 0) < 1
                    or evidence.get("mutual_tls_scrapes", 0) != evidence.get("scrapes", 0)):
                raise AssertionError("No authenticated positive pprof delivery: " + json.dumps(evidence))
            print(json.dumps({"result": "PASS", "image": image, **evidence,
                              "network": "internal Docker bridge; no published ports or host networking",
                              "not_proven": ["durable retention/WAL", "NetworkPolicy", "client workloads", "real tenant"]}))
        except Exception:
            if ("container", alloy_name) in resources:
                # Config and credentials are synthetic. Keep diagnostics bounded.
                print(run("docker", "logs", "--tail", "30", alloy_name), file=sys.stderr)
            raise
        finally:
            for kind, name in reversed(resources):
                if kind == "container":
                    subprocess.run(["docker", "rm", "--force", name], capture_output=True, check=False)
                else:
                    subprocess.run(["docker", "network", "rm", name], capture_output=True, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", type=Path)
    parser.add_argument("--image", default=os.environ.get("ELVEN_ALLOY_IMAGE"), help="Digest-pinned profiler image override for release validation")
    arguments = parser.parse_args()
    serve(arguments.serve) if arguments.serve else smoke(arguments.image)
