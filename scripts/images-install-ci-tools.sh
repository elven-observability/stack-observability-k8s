#!/usr/bin/env bash
# CI tooling only; never run on a Kubernetes node or mutate a client context.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true || { echo 'This helper is restricted to disposable GitHub Actions runners.' >&2; exit 1; }
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
task_tools_dir="$RUNNER_TEMP/elven-image-validation-tools"
mkdir -p "$task_tools_dir/bin"
cd "$task_tools_dir"
fetch() {
  local source_url="$1" target_file="$2" expected_sha="$3"
  curl --fail --silent --show-error --location --retry 3 "$source_url" --output "$target_file"
  printf '%s  %s\n' "$expected_sha" "$target_file" | sha256sum --check -
}
fetch https://get.helm.sh/helm-v4.3.1-linux-amd64.tar.gz helm.tar.gz 0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
tar -xzf helm.tar.gz linux-amd64/helm
install -m 0755 linux-amd64/helm bin/helm
fetch https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 kind aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
install -m 0755 kind bin/kind
fetch https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl kubectl 6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f
install -m 0755 kubectl bin/kubectl
fetch https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz kubeconform.tar.gz 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
tar -xzf kubeconform.tar.gz -C bin kubeconform
printf '%s\n' "$task_tools_dir/bin" >> "$GITHUB_PATH"
printf 'ELVEN_HELM_BINARY=%s/bin/helm\n' "$task_tools_dir" >> "$GITHUB_ENV"
