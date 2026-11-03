#!/usr/bin/env python3
"""Elven opt-in instrumentation control plane; Python standard library only.

Never annotates, restarts or takes ownership of an application. TLS private
material is created through kubectl stdin, never Helm values/history or argv.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/elven-instrumentation"
LOCK = ROOT / "instrumentation.lock.json"
OWNER = "elven-instrumentation-cli"
LABEL_PREFIX = "elven.observability/"
IMAGE_REPOS = {"operator": "elven-instrumentation-operator", "java": "elven-auto-java",
               "nodejs": "elven-auto-nodejs", "python": "elven-auto-python", "nodejs20": "elven-auto-nodejs20"}


class Failure(Exception):
    pass


def run(command, data=None, timeout=120):
    try:
        result = subprocess.run([str(value) for value in command], input=data, text=True,
                                capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Timeout exceptions may contain partial stdout/stderr with Secret data.
        # Never format or chain the provider exception into a user-facing error.
        raise Failure(f"{Path(str(command[0])).name} {command[1]} exceeded its bounded timeout; no provider output was printed.") from None
    if result.returncode:
        # Provider errors may echo objects containing private keys. Do not relay
        # stderr, stdout or stdin, even when a command fails.
        raise Failure(f"{Path(str(command[0])).name} {command[1]} failed (exit {result.returncode}); inspect the target locally without sharing Secret contents.")
    return result.stdout


def identifier(value, label, limit=63):
    if not isinstance(value, str) or len(value) > limit or not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", value):
        raise Failure(f"{label} must be a lowercase DNS label of at most {limit} characters.")
    return value


def fullname(release):
    return release if len(release) <= 44 else release[:35].rstrip("-") + "-" + hashlib.sha256(release.encode()).hexdigest()[:8]


def global_name(args):
    return fullname(args.release)[:30].rstrip("-") + "-" + hashlib.sha256(f"{args.namespace}/{args.release}".encode()).hexdigest()[:10]


def kube(args, *command, data=None):
    if not args.context:
        raise Failure("--context is mandatory; the active context is never used implicitly.")
    argv = ["kubectl"]
    if args.kubeconfig:
        argv += ["--kubeconfig", args.kubeconfig]
    return run(argv + ["--context", args.context, "--request-timeout=30s", *command], data)


def helm(args, *command, online=False):
    argv = [os.environ.get("ELVEN_HELM_BINARY", "helm"), *command]
    if online:
        if not args.context:
            raise Failure("--context is mandatory.")
        argv += ["--kube-context", args.context]
        if args.kubeconfig:
            argv += ["--kubeconfig", args.kubeconfig]
    timeout = duration_seconds(args.timeout) + 90 if command and command[0] in ("upgrade", "uninstall", "rollback") else 120
    return run(argv, timeout=timeout)


def duration_seconds(value):
    match = re.fullmatch(r"([1-9][0-9]{0,4})([smh])", value)
    if not match:
        raise Failure("--timeout must be a positive duration, such as 15m, bounded to one hour.")
    duration = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    if duration > 3600:
        raise Failure("--timeout must not exceed one hour.")
    return duration


def programs(args, online):
    required = [os.environ.get("ELVEN_HELM_BINARY", "helm")]
    if online:
        required += ["kubectl"]
    for binary in required:
        if not shutil.which(binary):
            raise Failure(f"Required program is missing: {Path(binary).name}.")
    version = re.search(r"v(\d+)\.(\d+)\.(\d+)(?![\d.-])", helm(args, "version", "--short"))
    if not version:
        raise Failure("Cannot identify Helm version.")
    actual = tuple(map(int, version.groups()))
    if not (actual[0] == 4 and actual >= (4, 3, 1) or actual[0] == 3 and actual >= (3, 22, 1)):
        raise Failure("Use Helm 4.3.1+ or the supported Helm 3.22.1+ compatibility bridge.")
    return actual[0]


def render(args, folder, overrides=None):
    flags = ["--namespace", args.namespace]
    for value in args.values:
        if not Path(value).is_file():
            raise Failure("A supplied --values file does not exist.")
        flags += ["--values", value]
    if overrides:
        source = folder / "instrumentation-public-overrides.json"
        source.write_text(json.dumps(overrides))
        source.chmod(0o600)
        flags += ["--values", source]
    template = ["template", args.release, CHART, *flags, "--kube-version", args.render_kube_version]
    settings_yaml = helm(args, *template, "--show-only", "templates/settings.yaml")
    match = re.search(r'^\s+settings\.json:\s*("[^\n]+")\s*$', settings_yaml, re.MULTILINE)
    if not match:
        raise Failure("Elven instrumentation settings contract is missing.")
    settings = json.loads(json.loads(match.group(1)))
    validate_settings(settings, args.namespace)
    return helm(args, *template), settings, flags


def validate_settings(settings, operator_namespace):
    if not settings.get("enabled"):
        return
    names = settings.get("namespaces", [])
    if not names or len(names) != len(set(names)):
        raise Failure("Select explicit, distinct application namespaces.")
    for name in names:
        identifier(name, "Application namespace")
        if name in (operator_namespace, "kube-system", "kube-public", "kube-node-lease"):
            raise Failure("System and instrumentation namespaces cannot be injection targets.")
    for key in ("sourceNamespace", "sourceRelease"):
        identifier(settings["gateway"][key], f"gateway.{key}")
    endpoint = urlsplit(settings["gateway"]["endpoint"])
    if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None
            or endpoint.password is not None or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment):
        raise Failure("gateway.endpoint must be a verified HTTPS gateway base URL without credentials, path, query or fragment.")
    if endpoint.hostname in ("localhost", "0.0.0.0", "::1") or endpoint.hostname.startswith("127."):
        raise Failure("Loopback gateway destinations are forbidden.")
    try:
        endpoint.port
    except ValueError:
        raise Failure("gateway.endpoint port is invalid.") from None
    if not settings.get("networkPolicy", {}).get("enabled"):
        raise Failure("The Elven instrumentation NetworkPolicy cannot be silently disabled.")
    cidrs = settings["networkPolicy"].get("apiServerCIDRs", [])
    if not cidrs:
        raise Failure("networkPolicy.apiServerCIDRs must identify the reviewed API-server source addresses.")
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            raise Failure("API-server CIDRs must be valid canonical networks.") from None
        if network.prefixlen == 0:
            raise Failure("Unrestricted /0 API-server ingress is forbidden.")
    if settings["runtimes"].get("nodejs20") and not settings["runtimes"].get("legacyNode20Approved"):
        raise Failure("Node.js 20 is EOL and requires an explicit legacy approval; migrate to a maintained runtime.")
    required = ["operator"] + [name for name in ("java", "nodejs", "python", "nodejs20") if settings["runtimes"].get(name)]
    if len(required) == 1:
        raise Failure("Enable at least one explicit instrumentation runtime.")
    for name in required:
        image = settings["images"][name]
        if (image.get("repository") != "docker.io/elvenobservability/" + IMAGE_REPOS[name]
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("digest", ""))
                or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", image.get("tag", ""))
                or image.get("tag") == "latest"):
            raise Failure(f"images.{name} must select the exact Elven repository, explicit version and SHA-256 digest.")


def require_images(settings, development=False):
    if development:
        print("WARNING: unpromoted Elven images explicitly allowed for this disposable laboratory only.", file=sys.stderr)
        return
    if not LOCK.is_file():
        raise Failure("The instrumentation image release lock is missing.")
    lock = json.loads(LOCK.read_text())
    if lock.get("schemaVersion") != 1 or lock.get("distribution", {}).get("publicationStatus") != "verified":
        raise Failure("Production instrumentation is blocked until the Elven images are published, signed and promoted.")
    required = ["operator"] + [name for name in ("java", "nodejs", "python", "nodejs20") if settings["runtimes"].get(name)]
    for name in required:
        approved = lock.get("images", {}).get(name, {}).get("distribution", {})
        selected = settings["images"][name]
        if (approved.get("status") != "verified" or approved.get("repository") != selected.get("repository")
                or not approved.get("digest") or approved["digest"] != selected.get("digest")):
            raise Failure(f"images.{name} does not match the signed/promoted Elven release lock.")


def get_object(args, kind, name, namespace=None):
    command = ["get", kind, name, "--ignore-not-found", "-o", "json"]
    if namespace:
        command += ["--namespace", namespace]
    raw = kube(args, *command)
    return json.loads(raw) if raw.strip() else None


def helm_owned(args, obj, release=None, namespace=None, expected_app="elven-instrumentation-operator"):
    metadata = obj.get("metadata", {})
    annotations = metadata.get("annotations", {})
    return (annotations.get("meta.helm.sh/release-name") == (release or args.release)
            and annotations.get("meta.helm.sh/release-namespace") == (namespace or args.namespace)
            and metadata.get("labels", {}).get("app.kubernetes.io/managed-by") == "Helm"
            and metadata.get("labels", {}).get("app.kubernetes.io/name") == expected_app
            and metadata.get("labels", {}).get("app.kubernetes.io/part-of") == "elven-observability")


def secret_labels(args):
    return {"app.kubernetes.io/managed-by": OWNER, "app.kubernetes.io/instance": args.release,
            "app.kubernetes.io/part-of": "elven-observability", LABEL_PREFIX + "namespace": args.namespace}


def decode_secret(secret, required):
    result = {}
    for key in required:
        try:
            result[key] = base64.b64decode(secret.get("data", {}).get(key, ""), validate=True).decode("utf-8")
        except (ValueError, TypeError, UnicodeError):
            raise Failure("TLS Secret contains invalid encoded material; contents were not printed.") from None
        if not result[key].strip():
            raise Failure("TLS Secret is missing required material; contents were not printed.")
    return result


def private_files(folder, values):
    for key, value in values.items():
        path = folder / key
        path.write_text(value)
        path.chmod(0o600)


def validate_material(values, folder, role, hostname=None):
    if not shutil.which("openssl"):
        raise Failure("OpenSSL is required to verify TLS chain, purpose, SAN, key pairing and expiry.")
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_files(folder, values)
    crt = folder / ("tls.crt" if role == "server" else "client.crt")
    key = folder / ("tls.key" if role == "server" else "client.key")
    try:
        for cert in (folder / "ca.crt", crt):
            run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "86400"])
        command = ["openssl", "verify", "-x509_strict", "-CAfile", folder / "ca.crt",
                   "-purpose", "sslserver" if role == "server" else "sslclient"]
        if hostname:
            sans = run(["openssl", "x509", "-in", crt, "-noout", "-ext", "subjectAltName"])
            if hostname not in re.findall(r"DNS:([^,\s]+)", sans):
                raise Failure("Serving certificate requires the exact Service DNS name in SAN.")
            command += ["-verify_hostname", hostname]
        run(command + [crt])
        if run(["openssl", "x509", "-in", crt, "-pubkey", "-noout"]) != run(["openssl", "pkey", "-in", key, "-pubout"]):
            raise Failure("TLS key mismatch.")
    except Failure:
        raise Failure("TLS validation failed: verify chain, exact SAN, purpose, matching key and at least 24h validity. No key contents were printed.") from None


def client_material(secret, folder):
    values = decode_secret(secret, ("ca.crt", "client.crt", "client.key"))
    validate_material(values, folder, "client")
    # The Java agent expects PEM PKCS#8; do not rely on an EC key's legacy SEC1
    # encoding. This conversion keeps the same private key and does not rotate it.
    output = folder / "client-pkcs8.key"
    run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", folder / "client.key", "-out", output])
    output.chmod(0o600)
    values["client.key"] = output.read_text()
    if not values["client.key"].startswith("-----BEGIN PRIVATE KEY-----"):
        raise Failure("Cannot produce a PKCS#8 client key for the injected SDKs.")
    return values


def generate_serving(args, settings, folder):
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = fullname(args.release) + "-webhook"
    hostname = f"{name}.{args.namespace}.svc.{settings['clusterDomain']}"
    if len(hostname) > 253:
        raise Failure("Webhook DNS identity exceeds 253 characters.")
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-days", "365", "-subj", "/CN=Elven instrumentation CA",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash", "-keyout", folder / "ca.key", "-out", folder / "ca.crt"])
    run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-subj", f"/CN={name[:64]}", "-keyout", folder / "tls.key", "-out", folder / "tls.csr"])
    names = [name, f"{name}.{args.namespace}", f"{name}.{args.namespace}.svc", hostname]
    extension = folder / "server.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyAgreement\n"
                         "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                         "subjectAltName=" + ",".join("DNS:" + value for value in names) + "\n")
    run(["openssl", "x509", "-req", "-in", folder / "tls.csr", "-CA", folder / "ca.crt", "-CAkey", folder / "ca.key",
         "-CAcreateserial", "-days", "364", "-extfile", extension, "-out", folder / "tls.crt"])
    values = {key: (folder / key).read_text() for key in ("ca.crt", "tls.crt", "tls.key")}
    validate_material(values, folder, "server", hostname)
    # CA signing key remains only in the temporary directory and is destroyed on
    # exit. Neither apps nor Helm receive it (or the server key).
    return values


def require_secret_owner(args, secret, role, source_fingerprint):
    metadata = secret.get("metadata", {})
    existing = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})
    expected = {LABEL_PREFIX + "cluster-uid": args.cluster_uid,
                LABEL_PREFIX + "source-ca-sha256": source_fingerprint, LABEL_PREFIX + "tls-role": role}
    if (not all(existing.get(key) == value for key, value in secret_labels(args).items())
            or not all(annotations.get(key) == value for key, value in expected.items())):
        raise Failure("An existing TLS Secret has another owner or trust identity. Choose a new name or perform a reviewed rotation; automatic adoption/overwrite is forbidden.")


def create_secret(args, namespace, name, values, role, fingerprint):
    obj = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {
        "name": name, "namespace": namespace, "labels": secret_labels(args), "annotations": {
            LABEL_PREFIX + "cluster-uid": args.cluster_uid, LABEL_PREFIX + "source-ca-sha256": fingerprint,
            LABEL_PREFIX + "tls-role": role}},
        "data": {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}}
    # A concurrent create causes AlreadyExists and fails closed. No apply,
    # patch, replacement, adoption or broad Secret synchronization exists.
    kube(args, "create", "-f", "-", data=json.dumps(obj))


def can_i(args, verb, resource, namespace=None):
    command = ["auth", "can-i", verb, resource]
    if namespace:
        command += ["--namespace", namespace]
    try:
        allowed = kube(args, *command).strip() == "yes"
    except Failure:
        raise Failure(f"Cannot confirm installer authorization: {verb} {resource}. Check connectivity and scoped administrator permissions; no private material was printed.") from None
    if not allowed:
        raise Failure(f"Installer permission missing: {verb} {resource}; runtime has no Kubernetes API permissions.")


def cluster_identity(args, changing=False):
    system = get_object(args, "namespace", "kube-system")
    uid = (system or {}).get("metadata", {}).get("uid")
    if not uid:
        raise Failure("Cannot determine kube-system UID.")
    if (changing and not args.expect_cluster_uid) or (args.expect_cluster_uid and args.expect_cluster_uid != uid):
        raise Failure("Confirm --context and supply the exact --expect-cluster-uid before any writes.")
    args.cluster_uid = uid
    return uid


def owned_settings(args):
    installed = get_object(args, "configmap", fullname(args.release) + "-settings", args.namespace)
    if not installed or not helm_owned(args, installed):
        raise Failure("The installed settings do not belong to this Elven Helm release; refusing recovery/adoption.")
    if not release_inventory(args):
        raise Failure("The installed Elven Helm release is missing; refusing recovery/adoption.")
    return json.loads(installed["data"]["settings.json"])


def release_inventory(args):
    all_flags = ["--all"] if getattr(args, "helm_major", 4) == 3 else []
    releases = json.loads(helm(args, "list", "--namespace", args.namespace, *all_flags,
                               "--output", "json", online=True))
    selected = next((item for item in releases if item.get("name") == args.release), None)
    if selected and not selected.get("chart", "").startswith("elven-instrumentation-1."):
        raise Failure("This Helm release belongs to another chart or unsupported major; choose a new release. Automatic replacement/adoption is forbidden.")
    return selected


def check_injection_claims(args, settings):
    raw = json.loads(kube(args, "get", "mutatingwebhookconfigurations.admissionregistration.k8s.io", "--selector",
                          "app.kubernetes.io/name=elven-instrumentation-operator", "-o", "json"))
    if not isinstance(raw.get("items"), list):
        raise Failure("Cannot inspect existing Elven injection claims; no resources were changed.")
    wanted_namespaces = set(settings["namespaces"])
    for existing in raw["items"]:
        if existing.get("metadata", {}).get("name") == global_name(args):
            continue
        for webhook in existing.get("webhooks", []):
            # Unknown/missing selectors are conservatively considered global.
            namespaces = None
            for expression in webhook.get("namespaceSelector", {}).get("matchExpressions", []):
                if expression.get("key") == "kubernetes.io/metadata.name" and expression.get("operator") == "In":
                    namespaces = set(expression.get("values", []))
            # Every opt-in Pod reaches the module (unknown runtimes must be
            # rejected, not silently ignored). Therefore distinct enabled
            # runtime sets do NOT make shared namespaces safe.
            if namespaces is None or namespaces & wanted_namespaces:
                raise Failure("An existing Elven webhook has overlapping or unverified namespaces. Choose disjoint scopes; automatic double injection or webhook adoption is forbidden.")


def check_namespace_instrumentation(namespace):
    """Known namespace-wide injectors cannot race the zero-API Elven handler.

    This is a conservative compatibility guard, not universal discovery of
    arbitrary admission controllers. It never removes another owner's settings.
    """
    metadata = namespace.get("metadata", {})
    for field in ("annotations", "labels"):
        entries = metadata.get(field, {})
        if not isinstance(entries, dict):
            raise Failure("Namespace injection metadata has an unknown type; no application metadata was changed.")
        for key, value in entries.items():
            if not isinstance(key, str):
                raise Failure("Namespace injection metadata has an unknown key type.")
            known = (key.startswith("instrumentation.opentelemetry.io/inject-")
                     or key.startswith("admission.datadoghq.com/")
                     or key in ("oneagent.dynatrace.com/inject", "oneagent.dynatrace.com/injected", "dynatrace.com/inject",
                                "instrumentation.newrelic.com/inject", "newrelic.io/inject", "newrelic.com/inject",
                                "newrelic.com/instrumentation", "newrelic-k8s-agents-operator-version",
                                "newrelic-k8s-agents-operator-txid", "appdynamics.com/inject"))
            if known and value != "false":
                raise Failure("An application namespace has active or ambiguous namespace-wide instrumentation. Review the other authority through its owner before enabling Elven injection; no labels or annotations were changed.")


def preflight(args, settings, folder, changing=False):
    cluster_identity(args, changing)
    if not settings.get("enabled"):
        raise Failure("Instrumentation is disabled. Review an explicit enabled profile before installing.")
    version = json.loads(kube(args, "version", "-o", "json"))["serverVersion"]["gitVersion"]
    match = re.match(r"v1\.(\d+)\.", version)
    if not match or not 35 <= int(match.group(1)) <= 37:
        raise Failure("Supported Kubernetes minor lines are 1.35–1.37.")
    require_images(settings, args.development_images)
    namespace = get_object(args, "namespace", args.namespace)
    if namespace:
        selected = release_inventory(args)
        if selected:
            owned_settings(args)
    check_injection_claims(args, settings)
    for target in settings["namespaces"]:
        application_namespace = get_object(args, "namespace", target)
        if not application_namespace:
            raise Failure("An approved application namespace does not exist; this installer never creates application namespaces.")
        check_namespace_instrumentation(application_namespace)
    # Check names before creating even the first Secret/namespace. Only Helm's
    # resources for this exact release may be reconciled.
    stem = fullname(args.release)
    resources = [("configmap", stem + "-settings", args.namespace), ("configmap", stem + "-config", args.namespace),
                 ("deployment", stem, args.namespace), ("service", stem + "-webhook", args.namespace),
                 ("serviceaccount", stem, args.namespace), ("networkpolicy", stem, args.namespace),
                 ("mutatingwebhookconfiguration", global_name(args), None)]
    for kind, name, ns in resources:
        obj = get_object(args, kind, name, ns)
        if obj and not helm_owned(args, obj):
            raise Failure(f"Existing {kind} {name} belongs to another owner. Nothing was adopted or changed.")
    source = settings["gateway"]
    source_settings = get_object(args, "configmap", fullname(source["sourceRelease"]) + "-settings", source["sourceNamespace"])
    if not source_settings or not helm_owned(args, source_settings, source["sourceRelease"], source["sourceNamespace"], "elven-observability"):
        raise Failure("The source gateway settings must belong to the explicit Elven Helm release.")
    gateway = json.loads(source_settings["data"]["settings.json"])
    domain = gateway["cluster"].get("domain", "cluster.local")
    expected_endpoint = f"https://{fullname(source['sourceRelease'])}-gateway.{source['sourceNamespace']}.svc.{domain}:{gateway['ports']['otlpHttp']}"
    if source["endpoint"].rstrip("/") != expected_endpoint or settings["clusterDomain"] != domain:
        raise Failure("gateway.endpoint/clusterDomain do not match the owned source gateway TLS identity.")
    if gateway.get("networkPolicy", {}).get("enabled") and not set(settings["namespaces"]).issubset(gateway.get("collection", {}).get("namespaces", [])):
        raise Failure("The gateway NetworkPolicy does not authorize all selected application namespaces; review its collection.namespaces first.")
    source_secret = get_object(args, "secret", gateway["tls"]["existingSecret"], source["sourceNamespace"])
    source_labels = (source_secret or {}).get("metadata", {}).get("labels", {})
    expected_labels = {"app.kubernetes.io/managed-by": "elven-cli", "app.kubernetes.io/instance": source["sourceRelease"],
                       "app.kubernetes.io/part-of": "elven-observability", LABEL_PREFIX + "namespace": source["sourceNamespace"]}
    if not source_secret or not all(source_labels.get(key) == value for key, value in expected_labels.items()):
        raise Failure("The source client TLS Secret must be owned by the explicit Elven gateway; external material is not silently adopted.")
    client = client_material(source_secret, folder / "source-client")
    fingerprint = hashlib.sha256(client["ca.crt"].encode()).hexdigest()
    missing_clients = []
    for target in settings["namespaces"]:
        existing = get_object(args, "secret", settings["clientTLS"]["secretName"], target)
        if not existing:
            missing_clients.append(target)
            continue
        require_secret_owner(args, existing, "client", fingerprint)
        if decode_secret(existing, tuple(client)) != client:
            raise Failure("An owned application TLS Secret differs from the reviewed source identity; rotate deliberately, never overwrite it automatically.")
    serving = get_object(args, "secret", settings["webhook"]["existingSecret"], args.namespace) if namespace else None
    serving_values = None
    if serving:
        require_secret_owner(args, serving, "server", fingerprint)
        serving_values = decode_secret(serving, ("ca.crt", "tls.crt", "tls.key"))
        hostname = f"{stem}-webhook.{args.namespace}.svc.{settings['clusterDomain']}"
        validate_material(serving_values, folder / "serving-check", "server", hostname)
        supplied = settings["webhook"].get("caBundle", "")
        if supplied and supplied != base64.b64encode(serving_values["ca.crt"].encode()).decode():
            raise Failure("webhook.caBundle differs from the validated serving CA; refusing trust substitution.")
    elif settings["webhook"].get("caBundle"):
        raise Failure("A supplied webhook CA requires its already provisioned, owned serving TLS Secret; no automatic trust replacement.")
    for verb in ("get", "list", "create", "patch", "delete"):
        can_i(args, verb, "mutatingwebhookconfigurations.admissionregistration.k8s.io")
    for kind in ("deployments.apps", "services", "serviceaccounts", "configmaps", "networkpolicies.networking.k8s.io"):
        for verb in ("create", "patch"):
            can_i(args, verb, kind, args.namespace)
    # Helm release metadata is stored in Secrets; SDK/runtime service accounts
    # receive no such permissions or API token.
    for verb in ("get", "list", "create", "update", "patch", "delete"):
        can_i(args, verb, "secrets", args.namespace)
    for target in missing_clients:
        can_i(args, "create", "secrets", target)
    if not namespace:
        can_i(args, "create", "namespaces")
    print(f"Preflight passed for explicit cluster UID {args.cluster_uid}; selected applications were not changed.")
    if not serving_values or missing_clients:
        print("Missing owned TLS material will be created only by install; preflight did not generate certificates or write Secrets.")
    return {"namespace_exists": bool(namespace), "client": client, "fingerprint": fingerprint,
            "missing_clients": missing_clients, "serving": serving_values}


def install(args, settings, plan, folder, helm_major):
    # All fallible local crypto is completed before the first Kubernetes write.
    serving = plan["serving"] or generate_serving(args, settings, folder / "serving-new")
    public_override = {"webhook": {"caBundle": base64.b64encode(serving["ca.crt"].encode()).decode()}}
    _, _, flags = render(args, folder, public_override)
    if not plan["namespace_exists"]:
        kube(args, "create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": args.namespace, "labels": {"app.kubernetes.io/part-of": "elven-observability"}}}))
    if not plan["serving"]:
        create_secret(args, args.namespace, settings["webhook"]["existingSecret"], serving, "server", plan["fingerprint"])
    for target in plan["missing_clients"]:
        create_secret(args, target, settings["clientTLS"]["secretName"], plan["client"], "client", plan["fingerprint"])
    failure = "--rollback-on-failure" if helm_major == 4 else "--atomic"
    helm(args, "upgrade", "--install", args.release, CHART, *flags, "--wait", "--timeout", args.timeout,
         "--history-max", "10", "--reset-values", failure, online=True)
    print("Elven instrumentation reconciled. No application was labelled, annotated or restarted. Opt-in through reviewed GitOps Pod labels; verify actual telemetry before expanding.")


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("render", "preflight", "install", "status", "uninstall"))
    parser.add_argument("--release", default="elven-operator")
    parser.add_argument("--namespace", default="elven-observability")
    parser.add_argument("--context")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--expect-cluster-uid")
    parser.add_argument("--values", action="append", default=[])
    parser.add_argument("--render-kube-version", default="1.37.2")
    parser.add_argument("--development-images", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--timeout", default="15m")
    args = parser.parse_args(argv)
    identifier(args.release, "--release", 53)
    identifier(args.namespace, "--namespace")
    duration_seconds(args.timeout)
    online = args.command != "render"
    major = programs(args, online)
    args.helm_major = major
    if online and not args.context:
        raise Failure("--context is mandatory; refusing the active kubeconfig context.")
    with tempfile.TemporaryDirectory(prefix="elven-instrumentation-") as temporary:
        folder = Path(temporary)
        folder.chmod(0o700)
        if args.command in ("status", "uninstall"):
            cluster_identity(args, args.command == "uninstall")
            owned_settings(args)
            if args.command == "status":
                print(kube(args, "get", "pods", "--namespace", args.namespace, "-l", f"app.kubernetes.io/instance={args.release},app.kubernetes.io/part-of=elven-observability"), end="")
                print("Ready does not prove SDK injection or delivery. Check a selected synthetic application, its patch and actual backend signals.")
            else:
                helm(args, "uninstall", args.release, "--namespace", args.namespace, "--wait", "--timeout", args.timeout, online=True)
                print("Elven webhook release removed. Namespaces, TLS Secrets and existing application Pods were retained; no application was restarted.")
            return
        manifest, settings, _ = render(args, folder)
        if args.command == "render":
            if args.output:
                output = Path(args.output)
                with output.open("x") as target:
                    target.write(manifest)
                output.chmod(0o600)
                print(f"Rendered {output}; no Kubernetes access, certificate generation or application changes.")
            else:
                print(manifest, end="")
            return
        plan = preflight(args, settings, folder, args.command == "install")
        if args.command == "install":
            install(args, settings, plan, folder, major)


if __name__ == "__main__":
    try:
        main()
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        print(f"elven-instrumentation: {error}", file=sys.stderr)
        sys.exit(1)
