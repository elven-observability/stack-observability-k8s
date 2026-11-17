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
{{/* Stable operational dimensions, never arbitrary application payload keys.
Runtime dimensions must survive: dropping heap/pool/type aliases distinct time
series without aggregating them and destroys the meaning of the measurements. */}}
{{- define "elven.metricKeys" -}}
{{- $keys := list "http.route" "http.request.method" "http.response.status_code" "http.method" "http.status_code" "server.address" "server.port" "network.protocol.name" "network.protocol.version" "rpc.system" "rpc.method" "rpc.service" "rpc.grpc.status_code" "db.system" "db.system.name" "db.operation" "db.operation.name" "messaging.system" "messaging.operation" "messaging.operation.type" "error.type" "exporter" "receiver" "processor" "connector" "transport" "data_type" "state" "type" "condition" "phase" "reason" "status" "outcome" "cpu" "mode" "direction" "protocol" "resource" "unit" "job" "instance" "elven_instance" "elven_release" "service.name" "service.namespace" "service.instance.id" "k8s.cluster.name" "k8s.namespace.name" "k8s.node.name" "k8s.pod.name" "k8s.pod.uid" "k8s.container.name" "k8s.deployment.name" "k8s.statefulset.name" "k8s.daemonset.name" "k8s.replicaset.name" "k8s.job.name" "k8s.cronjob.name" "k8s.volume.name" "k8s.persistentvolumeclaim.name" "container.name" "container.image.name" "namespace" "node" "pod" "container" "deployment" "le" "quantile" "method" "code" -}}
{{- if .runtime -}}
{{- $keys = concat $keys (list "jvm.memory.pool.name" "jvm.memory.type" "jvm.buffer.pool.name" "jvm.gc.name" "jvm.gc.action" "jvm.thread.daemon" "jvm.thread.state" "v8js.heap.space.name" "v8js.heap.type" "v8js.gc.type" "nodejs.eventloop.state" "cpython.gc.generation" "generation" "process.context_switch_type" "system.cpu.logical_number" "system.cpu.state" "device" "interface" "system.device" "system.network.interface" "network.interface.name") -}}
{{- end -}}
{{- toJson $keys -}}
{{- end -}}
{{- define "elven.metricResourceKeys" -}}
{{- toJson (list "service.name" "service.namespace" "service.instance.id" "k8s.cluster.name" "k8s.namespace.name" "k8s.node.name" "k8s.pod.name" "k8s.pod.uid" "k8s.container.name" "k8s.deployment.name" "k8s.statefulset.name" "k8s.daemonset.name" "k8s.replicaset.name" "k8s.job.name" "k8s.cronjob.name" "k8s.volume.name" "k8s.persistentvolumeclaim.name" "container.name") -}}
{{- end -}}
