{{- define "elven.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 44 | trimSuffix "-" -}}
{{- else -}}
{{- $name := .Release.Name -}}
{{- if gt (len $name) 44 -}}
{{- printf "%s-%s" ($name | trunc 35 | trimSuffix "-") ($name | sha256sum | trunc 8) -}}
{{- else -}}{{ $name }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "elven.clustername" -}}
{{- printf "%s-%s" ((include "elven.fullname" .) | trunc 30 | trimSuffix "-") (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 10) -}}
{{- end -}}
{{- define "elven.selectorLabels" -}}
app.kubernetes.io/name: elven-observability
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
{{- define "elven.labels" -}}
{{ include "elven.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
app.kubernetes.io/part-of: elven-observability
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
elven.observability/distribution: "1"
{{- end -}}
{{- define "elven.collectorImage" -}}
{{- printf "%s:%s@%s" .Values.images.collector.repository .Values.images.collector.tag .Values.images.collector.digest -}}
{{- end -}}
{{- define "elven.beylaImage" -}}
{{- printf "%s:%s@%s" .Values.images.beyla.repository .Values.images.beyla.tag .Values.images.beyla.digest -}}
{{- end -}}
{{- define "elven.alloyImage" -}}
{{- printf "%s:%s@%s" .Values.images.alloy.repository .Values.images.alloy.tag .Values.images.alloy.digest -}}
{{- end -}}
{{- define "elven.clientTLS" -}}
ca_file: /etc/elven/tls/ca.crt
cert_file: /etc/elven/tls/client.crt
key_file: /etc/elven/tls/client.key
min_version: "1.2"
{{- end -}}
{{- define "elven.nodeEnabled" -}}
{{- if or .Values.modules.logs.enabled .Values.modules.kubeletMetrics.enabled .Values.modules.ebpf.enabled -}}true{{- else -}}false{{- end -}}
{{- end -}}
{{- define "elven.collectorSecurity" -}}
runAsUser: 10001
runAsGroup: 10001
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities: {drop: [ALL]}
seccompProfile: {type: RuntimeDefault}
{{- end -}}
{{- define "elven.gatewayEndpoint" -}}
{{- printf "https://%s-gateway.%s.svc.%s:%v" (include "elven.fullname" .) .Release.Namespace .Values.cluster.domain .Values.ports.otlpHttp -}}
{{- end -}}
