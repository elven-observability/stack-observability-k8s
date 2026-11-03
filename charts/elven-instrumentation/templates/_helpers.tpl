{{- define "elvenInjection.fullname" -}}
{{- if gt (len .Release.Name) 44 -}}
{{- printf "%s-%s" (.Release.Name | trunc 35 | trimSuffix "-") (.Release.Name | sha256sum | trunc 8) -}}
{{- else -}}{{ .Release.Name }}{{- end -}}
{{- end -}}
{{- define "elvenInjection.globalname" -}}
{{- printf "%s-%s" ((include "elvenInjection.fullname" .) | trunc 30 | trimSuffix "-") (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 10) -}}
{{- end -}}
{{- define "elvenInjection.selectorLabels" -}}
app.kubernetes.io/name: elven-instrumentation-operator
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
{{- define "elvenInjection.labels" -}}
{{ include "elvenInjection.selectorLabels" . }}
app.kubernetes.io/part-of: elven-observability
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
elven.observability/distribution: "1"
{{- end -}}
{{- define "elvenInjection.image" -}}
{{- printf "%s:%s@%s" .repository .tag .digest -}}
{{- end -}}
{{- define "elvenInjection.config" -}}
{{- $images := dict -}}
{{- range $runtime := list "java" "nodejs" "python" "nodejs20" -}}
{{- if index $.Values.runtimes $runtime -}}
{{- $_ := set $images $runtime (include "elvenInjection.image" (index $.Values.images $runtime)) -}}
{{- end -}}
{{- end -}}
{{- toJson (dict "namespaces" .Values.namespaces "operatorNamespace" .Release.Namespace "endpoint" .Values.gateway.endpoint "tlsSecretName" .Values.clientTLS.secretName "images" $images "samplingRatio" .Values.samplingRatio "sdkVolumeSizeMiB" .Values.sdkVolumeSizeMiB "legacyNode20Approved" .Values.runtimes.legacyNode20Approved) -}}
{{- end -}}
