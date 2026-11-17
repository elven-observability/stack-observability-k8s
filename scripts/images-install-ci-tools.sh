#!/usr/bin/env bash
# CI tooling only; never run on a Kubernetes node or mutate a client context.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true || { echo 'This helper is restricted to disposable GitHub Actions runners.' >&2; exit 1; }
test "$(uname -s)" = Linux
case "$(uname -m)" in
  x86_64)
    task_arch=amd64
    task_helm_sha=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
    task_kind_sha=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
    task_kubectl_sha=6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f
    task_kubeconform_sha=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
    ;;
  aarch64|arm64)
    task_arch=arm64
    task_helm_sha=8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88
    task_kind_sha=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2
    task_kubectl_sha=922df28df248cc00a9e025f947704f1d1482de64ece54cfe57e61f19eaf1eef3
    task_kubeconform_sha=1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87
    ;;
  *) echo 'Unsupported native CI architecture.' >&2; exit 1 ;;
esac
task_tools_dir="$RUNNER_TEMP/elven-image-validation-tools"
mkdir -p "$task_tools_dir/bin"
cd "$task_tools_dir"
fetch() {
  local source_url="$1" target_file="$2" expected_sha="$3"
  curl --fail --silent --show-error --location --retry 3 "$source_url" --output "$target_file"
  printf '%s  %s\n' "$expected_sha" "$target_file" | sha256sum --check -
}
fetch "https://get.helm.sh/helm-v4.3.1-linux-$task_arch.tar.gz" helm.tar.gz "$task_helm_sha"
tar -xzf helm.tar.gz "linux-$task_arch/helm"
install -m 0755 "linux-$task_arch/helm" bin/helm
fetch "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-$task_arch" kind "$task_kind_sha"
install -m 0755 kind bin/kind
fetch "https://dl.k8s.io/release/v1.37.0/bin/linux/$task_arch/kubectl" kubectl "$task_kubectl_sha"
install -m 0755 kubectl bin/kubectl
fetch "https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-$task_arch.tar.gz" kubeconform.tar.gz "$task_kubeconform_sha"
tar -xzf kubeconform.tar.gz -C bin kubeconform
printf '%s\n' "$task_tools_dir/bin" >> "$GITHUB_PATH"
printf 'ELVEN_HELM_BINARY=%s/bin/helm\n' "$task_tools_dir" >> "$GITHUB_ENV"
