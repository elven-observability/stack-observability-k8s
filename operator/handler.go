// Copyright Elven Observability. Licensed under the Apache License, Version 2.0.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxAdmissionBytes   = 1 << 20
	injectLabel         = "elven.observability/inject"
	containerAnnotation = "elven.observability/container-name"
	injectedAnnotation  = "elven.observability/injected"
	sdkVolume           = "elven-instrumentation"
	tlsVolume           = "elven-instrumentation-tls"
	initName            = "elven-instrumentation-init"
	sdkMount            = "/elven-auto"
	tlsMount            = "/var/run/elven/tls"
)

var (
	namespacePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uidPattern       = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
	imagePattern     = regexp.MustCompile(`^docker\.io/elvenobservability/elven-auto-(java|nodejs20|nodejs|python):[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$`)
	servicePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

// Config is maintained by the distribution, not accepted from Pod annotations.
// No API credentials or telemetry tenant/token are present in this configuration.
type Config struct {
	Namespaces           []string          `json:"namespaces"`
	OperatorNamespace    string            `json:"operatorNamespace"`
	Endpoint             string            `json:"endpoint"`
	TLSSecretName        string            `json:"tlsSecretName"`
	Images               map[string]string `json:"images"`
	SamplingRatio        string            `json:"samplingRatio"`
	SDKVolumeSizeMiB     int               `json:"sdkVolumeSizeMiB"`
	LegacyNode20Approved bool              `json:"legacyNode20Approved"`
}

func parseConfig(raw []byte) (Config, error) {
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, errors.New("invalid Elven injection configuration")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return config, errors.New("multiple configuration documents are forbidden")
	}
	if config.OperatorNamespace == "" {
		config.OperatorNamespace = "elven-observability"
	}
	if !namespacePattern.MatchString(config.OperatorNamespace) {
		return config, errors.New("invalid operator namespace")
	}
	if len(config.Namespaces) == 0 {
		return config, errors.New("explicit application namespace allow-list is required")
	}
	seen := make(map[string]bool)
	for _, namespace := range config.Namespaces {
		if !namespacePattern.MatchString(namespace) || seen[namespace] || namespace == config.OperatorNamespace || namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
			return config, errors.New("invalid, duplicate, distribution or system namespace in injection allow-list")
		}
		seen[namespace] = true
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return config, errors.New("OTLP endpoint must be an authenticated HTTPS gateway base URL without path, credentials, query or fragment")
	}
	host := strings.ToLower(endpoint.Hostname())
	ip := net.ParseIP(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) {
		return config, errors.New("loopback OTLP destinations are forbidden")
	}
	if endpoint.Port() != "" {
		if port, err := strconv.Atoi(endpoint.Port()); err != nil || port < 1 || port > 65535 {
			return config, errors.New("invalid OTLP endpoint port")
		}
	}
	if !validSecretName(config.TLSSecretName) {
		return config, errors.New("a valid namespaced client TLS Secret name is required")
	}
	if len(config.Images) == 0 {
		return config, errors.New("at least one digest-pinned Elven instrumentation image is required")
	}
	for runtime, image := range config.Images {
		match := imagePattern.FindStringSubmatch(image)
		if len(match) != 2 || match[1] != runtime || strings.Contains(strings.Split(image, "@")[0], ":latest") {
			return config, errors.New("instrumentation images must use the matching Elven runtime repository, explicit version and immutable SHA-256 digest")
		}
		if runtime == "nodejs20" && !config.LegacyNode20Approved {
			return config, errors.New("Node.js 20 is end-of-life; its separately pinned legacy image requires legacyNode20Approved")
		}
	}
	if config.SamplingRatio == "" {
		config.SamplingRatio = "1"
	}
	ratio, err := strconv.ParseFloat(config.SamplingRatio, 64)
	if err != nil || ratio < 0 || ratio > 1 || !regexp.MustCompile(`^(?:0(?:\.[0-9]+)?|1(?:\.0+)?)$`).MatchString(config.SamplingRatio) {
		return config, errors.New("samplingRatio must be a decimal between zero and one")
	}
	if config.SDKVolumeSizeMiB == 0 {
		config.SDKVolumeSizeMiB = 128
	}
	if config.SDKVolumeSizeMiB < 64 || config.SDKVolumeSizeMiB > 512 {
		return config, errors.New("sdkVolumeSizeMiB must be between 64 and 512")
	}
	return config, nil
}

type groupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}
type groupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}
type admissionRequest struct {
	UID         string               `json:"uid"`
	Kind        groupVersionKind     `json:"kind"`
	Resource    groupVersionResource `json:"resource"`
	SubResource string               `json:"subResource"`
	Namespace   string               `json:"namespace"`
	Operation   string               `json:"operation"`
	Object      json.RawMessage      `json:"object"`
}
type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}
type admissionResponse struct {
	UID       string           `json:"uid"`
	Allowed   bool             `json:"allowed"`
	Status    *admissionStatus `json:"status,omitempty"`
	PatchType string           `json:"patchType,omitempty"`
	Patch     string           `json:"patch,omitempty"`
}
type admissionStatus struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}
type patchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

type operator struct {
	config Config
	slots  chan struct{}
}

func newOperator(config Config) *operator {
	return &operator{config: config, slots: make(chan struct{}, 16)}
}

func (op *operator) serveMutate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(writer, "application/json is required", http.StatusUnsupportedMediaType)
		return
	}
	select {
	case op.slots <- struct{}{}:
		defer func() { <-op.slots }()
	default:
		http.Error(writer, "admission capacity exceeded", http.StatusServiceUnavailable)
		return
	}
	reader := http.MaxBytesReader(writer, request.Body, maxAdmissionBytes)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	var review admissionReview
	if err := decoder.Decode(&review); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(writer, "admission request exceeds limit", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(writer, "invalid admission request", http.StatusBadRequest)
		}
		return
	}
	if decoder.Decode(new(any)) != io.EOF || review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" || review.Request == nil || !uidPattern.MatchString(review.Request.UID) {
		http.Error(writer, "invalid admission envelope", http.StatusBadRequest)
		return
	}
	response := &admissionResponse{UID: review.Request.UID, Allowed: true}
	patch, err := op.admit(review.Request)
	if err != nil {
		response.Allowed = false
		response.Status = &admissionStatus{Message: err.Error(), Code: http.StatusUnprocessableEntity}
	} else if len(patch) > 0 {
		encoded, err := json.Marshal(patch)
		if err != nil {
			http.Error(writer, "cannot encode admission result", http.StatusInternalServerError)
			return
		}
		response.PatchType = "JSONPatch"
		response.Patch = base64.StdEncoding.EncodeToString(encoded)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Response: response})
}

func mapField(object map[string]any, key string) (map[string]any, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return map[string]any{}, nil
	}
	mapping, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("invalid Pod object field type")
	}
	return mapping, nil
}

func validSecretName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !namespacePattern.MatchString(label) {
			return false
		}
	}
	return true
}

func mountOverlap(mount, reserved string) bool {
	if mount == "/" {
		return true
	}
	mount = strings.TrimSuffix(mount, "/")
	return mount == reserved || strings.HasPrefix(mount, reserved+"/") || strings.HasPrefix(reserved, mount+"/")
}
func sliceField(object map[string]any, key string) ([]any, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return nil, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, errors.New("invalid Pod collection field type")
	}
	return values, nil
}
func textField(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}
func pointerEscape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func (op *operator) admit(request *admissionRequest) ([]patchOperation, error) {
	allowedNamespace := false
	for _, namespace := range op.config.Namespaces {
		if request.Namespace == namespace {
			allowedNamespace = true
			break
		}
	}
	if !allowedNamespace || request.Operation != "CREATE" || request.SubResource != "" {
		return nil, nil
	}
	if request.Kind.Group != "" || request.Kind.Version != "v1" || request.Kind.Kind != "Pod" || request.Resource.Group != "" || request.Resource.Version != "v1" || request.Resource.Resource != "pods" {
		return nil, nil
	}
	var pod map[string]any
	if json.Unmarshal(request.Object, &pod) != nil || pod == nil {
		return nil, errors.New("invalid Pod document")
	}
	metadata, err := mapField(pod, "metadata")
	if err != nil {
		return nil, err
	}
	labels, err := mapField(metadata, "labels")
	if err != nil {
		return nil, err
	}
	rawRuntime, hasRuntime := labels[injectLabel]
	if !hasRuntime {
		return nil, nil
	}
	runtime, validRuntimeType := rawRuntime.(string)
	if !validRuntimeType || runtime == "" {
		return nil, errors.New("present Elven injection label must select an enabled runtime or explicit false")
	}
	if runtime == "false" {
		return nil, nil
	}
	image, exists := op.config.Images[runtime]
	if !exists {
		return nil, errors.New("requested Elven runtime is not configured; review the explicit runtime label")
	}
	if namespace := textField(metadata, "namespace"); namespace != "" && namespace != request.Namespace {
		return nil, errors.New("Pod namespace does not match admission namespace")
	}
	annotations, err := mapField(metadata, "annotations")
	if err != nil {
		return nil, err
	}
	if textField(annotations, injectedAnnotation) != "" {
		return nil, errors.New("Pod already has an Elven injection marker; remove the injection opt-in or review the prior injection")
	}
	for key, value := range annotations {
		if strings.HasPrefix(key, "instrumentation.opentelemetry.io/") && value != "false" {
			return nil, errors.New("another instrumentation annotation is active; exactly one instrumentation authority is permitted")
		}
	}
	for _, markers := range []map[string]any{labels, annotations} {
		for _, key := range []string{"admission.datadoghq.com/enabled", "oneagent.dynatrace.com/inject", "oneagent.dynatrace.com/injected", "newrelic.io/inject", "newrelic.com/inject", "newrelic.com/instrumentation", "newrelic-k8s-agents-operator-version", "newrelic-k8s-agents-operator-txid"} {
			if value, exists := markers[key]; exists && value != "false" {
				return nil, errors.New("another admission instrumentation marker is active or ambiguous; use exactly one instrumentation authority")
			}
		}
	}
	spec, err := mapField(pod, "spec")
	if err != nil {
		return nil, err
	}
	osSettings, err := mapField(spec, "os")
	if err != nil {
		return nil, err
	}
	if value, exists := osSettings["name"]; exists && value != "linux" {
		return nil, errors.New("Elven SDK payloads require Linux; the application OS is never rewritten")
	}
	nodeSelector, err := mapField(spec, "nodeSelector")
	if err != nil {
		return nil, err
	}
	if value, exists := nodeSelector["kubernetes.io/os"]; exists && value != "linux" {
		return nil, errors.New("Elven SDK payloads cannot be injected into a non-Linux node selection")
	}
	containers, err := sliceField(spec, "containers")
	if err != nil || len(containers) == 0 {
		return nil, errors.New("Pod must contain at least one regular container")
	}
	target := textField(annotations, containerAnnotation)
	if len(containers) > 1 && target == "" {
		return nil, errors.New("multi-container Pods require elven.observability/container-name")
	}
	targetIndex := -1
	var targetContainer map[string]any
	for index, raw := range containers {
		container, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid Pod container")
		}
		name := textField(container, "name")
		if name == initName {
			return nil, errors.New("reserved Elven init container name already exists")
		}
		if (target == "" && len(containers) == 1) || name == target {
			if targetIndex >= 0 {
				return nil, errors.New("ambiguous target container")
			}
			targetIndex = index
			targetContainer = container
		}
	}
	if targetIndex < 0 {
		return nil, errors.New("the selected application container does not exist")
	}
	if textField(metadata, "generateName") == "" && textField(metadata, "name") == "" {
		return nil, errors.New("Pod name or generateName is required")
	}
	if err := instrumentationConflict(targetContainer); err != nil {
		return nil, err
	}
	volumes, err := sliceField(spec, "volumes")
	if err != nil {
		return nil, err
	}
	for _, raw := range volumes {
		volume, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid Pod volume")
		}
		name := textField(volume, "name")
		if name == sdkVolume || name == tlsVolume || strings.HasPrefix(name, "opentelemetry-auto-instrumentation") || strings.HasPrefix(name, "otel-auto-instrumentation") {
			return nil, errors.New("an instrumentation volume already exists; no adoption or overwrite is permitted")
		}
	}
	initializers, err := sliceField(spec, "initContainers")
	if err != nil {
		return nil, err
	}
	for _, raw := range initializers {
		initializer, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid init container")
		}
		name := textField(initializer, "name")
		if name == initName || strings.Contains(name, "auto-instrumentation") || strings.Contains(name, "autoinstrumentation") {
			return nil, errors.New("another instrumentation initializer already exists")
		}
		image := strings.ToLower(textField(initializer, "image"))
		if strings.HasPrefix(image, "newrelic/") || strings.HasPrefix(image, "docker.io/newrelic/") || strings.HasPrefix(image, "ghcr.io/newrelic/") {
			return nil, errors.New("an existing admission agent initializer is present")
		}
	}
	mounts, err := sliceField(targetContainer, "volumeMounts")
	if err != nil {
		return nil, err
	}
	for _, raw := range mounts {
		mount, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid container volumeMount")
		}
		path := textField(mount, "mountPath")
		if mountOverlap(path, sdkMount) || mountOverlap(path, tlsMount) {
			return nil, errors.New("reserved Elven instrumentation mount path already exists")
		}
	}
	platform := textField(annotations, "elven.observability/python-platform")
	if platform != "" && (runtime != "python" || (platform != "glibc" && platform != "musl")) {
		return nil, errors.New("python-platform must be glibc or musl and only applies to Python")
	}
	serviceName := textField(annotations, "elven.observability/service-name")
	if serviceName == "" {
		serviceName = textField(labels, "app.kubernetes.io/name")
	}
	if serviceName == "" {
		serviceName = textField(targetContainer, "name")
	}
	if !servicePattern.MatchString(serviceName) {
		return nil, errors.New("service identity must be a stable bounded identifier without whitespace, commas or control characters")
	}
	sdkEnv := runtimeEnvironment(runtime, op.config.Endpoint, request.Namespace, serviceName, op.config.SamplingRatio)
	command := []string{"cp", "-R", "/autoinstrumentation/.", sdkMount + "/"}
	if runtime == "java" {
		command = []string{"cp", "/javaagent.jar", sdkMount + "/javaagent.jar"}
	}
	if runtime == "python" && platform == "musl" {
		command = []string{"cp", "-R", "/autoinstrumentation-musl/.", sdkMount + "/"}
	}
	init := map[string]any{"name": initName, "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
		"resources":       map[string]any{"requests": map[string]string{"cpu": "50m", "memory": "32Mi"}, "limits": map[string]string{"cpu": "500m", "memory": "128Mi"}},
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": 10001, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}, "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
		"volumeMounts":    []any{map[string]any{"name": sdkVolume, "mountPath": sdkMount}}}
	initializers = append(initializers, init)
	volumes = append(volumes, map[string]any{"name": sdkVolume, "emptyDir": map[string]any{"sizeLimit": fmt.Sprintf("%dMi", op.config.SDKVolumeSizeMiB)}}, map[string]any{"name": tlsVolume, "secret": map[string]any{"secretName": op.config.TLSSecretName, "defaultMode": 292, "items": []any{map[string]string{"key": "ca.crt", "path": "ca.crt"}, map[string]string{"key": "client.crt", "path": "client.crt"}, map[string]string{"key": "client.key", "path": "client.key"}}}})
	mounts = append(mounts, map[string]any{"name": sdkVolume, "mountPath": sdkMount, "readOnly": true}, map[string]any{"name": tlsVolume, "mountPath": tlsMount, "readOnly": true})
	patch := []patchOperation{{Op: "add", Path: "/spec/volumes", Value: volumes}, {Op: "add", Path: "/spec/initContainers", Value: initializers}, {Op: "add", Path: fmt.Sprintf("/spec/containers/%d/volumeMounts", targetIndex), Value: mounts}}
	if existing, exists := targetContainer["env"]; exists && existing != nil {
		// Append only generated SDK settings. Do not echo literal credentials or
		// other application environment values in the AdmissionReview response.
		for _, entry := range sdkEnv {
			patch = append(patch, patchOperation{Op: "add", Path: fmt.Sprintf("/spec/containers/%d/env/-", targetIndex), Value: entry})
		}
	} else {
		patch = append(patch, patchOperation{Op: "add", Path: fmt.Sprintf("/spec/containers/%d/env", targetIndex), Value: sdkEnv})
	}
	if _, ok := metadata["annotations"]; !ok || metadata["annotations"] == nil {
		patch = append(patch, patchOperation{Op: "add", Path: "/metadata/annotations", Value: map[string]string{injectedAnnotation: runtime}})
	} else {
		patch = append(patch, patchOperation{Op: "add", Path: "/metadata/annotations/" + pointerEscape(injectedAnnotation), Value: runtime})
	}
	return patch, nil
}

func instrumentationConflict(container map[string]any) error {
	if sources, err := sliceField(container, "envFrom"); err != nil {
		return err
	} else if len(sources) > 0 {
		return errors.New("envFrom may hide existing instrumentation settings; use explicit environment variables before opting in")
	}
	env, err := sliceField(container, "env")
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, raw := range env {
		entry, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid application environment entry")
		}
		name := textField(entry, "name")
		if name == "" || seen[name] {
			return errors.New("application environment contains missing or duplicate names")
		}
		seen[name] = true
		if strings.HasPrefix(name, "OTEL_") || strings.HasPrefix(name, "NEW_RELIC_") || strings.HasPrefix(name, "NEWRELIC_") || name == "JAVA_TOOL_OPTIONS" || name == "JDK_JAVA_OPTIONS" || name == "_JAVA_OPTIONS" || name == "NODE_OPTIONS" || name == "PYTHONPATH" || name == "PYTHONHOME" || name == "PYTHONSTARTUP" || name == "LD_PRELOAD" || name == "LD_AUDIT" || name == "CORECLR_ENABLE_PROFILING" || strings.HasPrefix(name, "ELVEN_") {
			return errors.New("application already defines instrumentation or loader configuration; review it instead of overwriting")
		}
	}
	for _, key := range []string{"command", "args"} {
		values, err := sliceField(container, key)
		if err != nil {
			return err
		}
		for _, raw := range values {
			value, ok := raw.(string)
			if !ok {
				return errors.New("invalid application startup arguments")
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "javaagent") || strings.Contains(lower, "opentelemetry") || strings.Contains(lower, "autoinstrumentation") || strings.Contains(lower, "dd-trace") || strings.Contains(lower, "newrelic") || strings.Contains(lower, "elastic-apm") {
				return errors.New("application startup already references an instrumentation agent")
			}
		}
	}
	return nil
}

func runtimeEnvironment(runtime, endpoint, namespace, serviceName, ratio string) []any {
	values := [][2]string{{"OTEL_EXPORTER_OTLP_ENDPOINT", strings.TrimSuffix(endpoint, "/")}, {"OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"}, {"OTEL_EXPORTER_OTLP_CERTIFICATE", tlsMount + "/ca.crt"}, {"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", tlsMount + "/client.crt"}, {"OTEL_EXPORTER_OTLP_CLIENT_KEY", tlsMount + "/client.key"}, {"OTEL_EXPORTER_OTLP_TIMEOUT", "10000"}, {"OTEL_TRACES_EXPORTER", "otlp"}, {"OTEL_METRICS_EXPORTER", "otlp"}, {"OTEL_LOGS_EXPORTER", "otlp"}, {"OTEL_PROPAGATORS", "tracecontext"}, {"OTEL_TRACES_SAMPLER", "parentbased_traceidratio"}, {"OTEL_TRACES_SAMPLER_ARG", ratio}, {"OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "2048"}, {"OTEL_ATTRIBUTE_COUNT_LIMIT", "64"}, {"OTEL_SPAN_EVENT_COUNT_LIMIT", "64"}, {"OTEL_SPAN_LINK_COUNT_LIMIT", "16"}, {"OTEL_BSP_MAX_QUEUE_SIZE", "2048"}, {"OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512"}, {"OTEL_BSP_SCHEDULE_DELAY", "5000"}, {"OTEL_BLRP_MAX_QUEUE_SIZE", "2048"}, {"OTEL_BLRP_MAX_EXPORT_BATCH_SIZE", "512"}, {"OTEL_SERVICE_NAME", serviceName}, {"OTEL_RESOURCE_ATTRIBUTES", "service.namespace=" + namespace + ",k8s.namespace.name=" + namespace}, {"OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST", ""}, {"OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE", ""}, {"OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST", ""}, {"OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE", ""}}
	switch runtime {
	case "java":
		values = append(values, [2]string{"JAVA_TOOL_OPTIONS", "-javaagent:" + sdkMount + "/javaagent.jar"}, [2]string{"OTEL_INSTRUMENTATION_COMMON_DB_QUERY_SANITIZATION_ENABLED", "true"})
	case "nodejs", "nodejs20":
		// Stable service and namespace attributes are supplied explicitly. Do not
		// probe cloud metadata or collect process arguments from an application.
		values = append(values, [2]string{"NODE_OPTIONS", "--require=" + sdkMount + "/autoinstrumentation.js"}, [2]string{"OTEL_NODE_RESOURCE_DETECTORS", "env"})
	case "python":
		values = append(values, [2]string{"PYTHONPATH", sdkMount + "/opentelemetry/instrumentation/auto_instrumentation:" + sdkMount}, [2]string{"OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED", "true"})
	}
	result := make([]any, 0, len(values))
	for _, entry := range values {
		result = append(result, map[string]any{"name": entry[0], "value": entry[1]})
	}
	return result
}
