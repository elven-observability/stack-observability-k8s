// Copyright Elven Observability. Licensed under the Apache License, Version 2.0.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func configForTest(t *testing.T) Config {
	t.Helper()
	config, err := parseConfig([]byte(`{"namespaces":["elven-demo"],"operatorNamespace":"elven-observability","endpoint":"https://elven-gateway.elven-observability.svc.cluster.local:4318","tlsSecretName":"elven-application-tls","images":{"java":"docker.io/elvenobservability/elven-auto-java:2.33.1-2@sha256:` + strings.Repeat("a", 64) + `","nodejs":"docker.io/elvenobservability/elven-auto-nodejs:0.82.0-3@sha256:` + strings.Repeat("b", 64) + `","python":"docker.io/elvenobservability/elven-auto-python:0.66b1-3@sha256:` + strings.Repeat("c", 64) + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return config
}
func podForTest(runtime string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "elven-demo-pod", "labels": map[string]any{injectLabel: runtime, "app.kubernetes.io/name": "elven-demo-service"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "elven-demo-app", "image": "elven-demo-app:synthetic", "env": []any{map[string]any{"name": "APPLICATION_SETTING", "value": "preserve-me"}}, "securityContext": map[string]any{"runAsUser": 12345.0}, "volumeMounts": []any{map[string]any{"name": "application-data", "mountPath": "/application-data"}}}}, "volumes": []any{map[string]any{"name": "application-data", "emptyDir": map[string]any{}}}}}
}
func requestForTest(t *testing.T, pod map[string]any) *admissionRequest {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return &admissionRequest{UID: "synthetic-request-uid", Namespace: "elven-demo", Operation: "CREATE", Kind: groupVersionKind{Version: "v1", Kind: "Pod"}, Resource: groupVersionResource{Version: "v1", Resource: "pods"}, Object: raw}
}
func environment(t *testing.T, patch []patchOperation) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, operation := range patch {
		var entries []any
		if strings.HasSuffix(operation.Path, "/env") {
			entries = operation.Value.([]any)
		} else if strings.HasSuffix(operation.Path, "/env/-") {
			entries = []any{operation.Value}
		}
		for _, raw := range entries {
			entry := raw.(map[string]any)
			name := entry["name"].(string)
			if _, exists := result[name]; exists {
				t.Fatalf("duplicate env %s", name)
			}
			result[name], _ = entry["value"].(string)
		}
	}
	if len(result) == 0 {
		t.Fatal("environment patch missing")
	}
	return result
}

func TestConfigRequiresScopedImmutableElvenInputs(t *testing.T) {
	valid := configForTest(t)
	for name, mutate := range map[string]func(*Config){
		"no namespaces":               func(c *Config) { c.Namespaces = nil },
		"system namespace":            func(c *Config) { c.Namespaces = []string{"kube-system"} },
		"distribution namespace":      func(c *Config) { c.Namespaces = []string{c.OperatorNamespace} },
		"duplicate namespace":         func(c *Config) { c.Namespaces = []string{"elven-demo", "elven-demo"} },
		"wildcard namespace":          func(c *Config) { c.Namespaces = []string{"*"} },
		"insecure URL":                func(c *Config) { c.Endpoint = "http://elven-gateway:4318" },
		"endpoint query":              func(c *Config) { c.Endpoint += "?token=never-reflect" },
		"endpoint path":               func(c *Config) { c.Endpoint += "/v1/traces" },
		"endpoint credentials":        func(c *Config) { c.Endpoint = "https://synthetic:private@elven-gateway:4318" },
		"endpoint loopback":           func(c *Config) { c.Endpoint = "https://127.0.0.1:4318" },
		"endpoint loopback uppercase": func(c *Config) { c.Endpoint = "https://LOCALHOST:4318" },
		"endpoint IPv6 loopback":      func(c *Config) { c.Endpoint = "https://[0:0:0:0:0:0:0:1]:4318" },
		"endpoint unspecified IPv6":   func(c *Config) { c.Endpoint = "https://[::]:4318" },
		"endpoint empty query":        func(c *Config) { c.Endpoint += "?" },
		"endpoint encoded slash":      func(c *Config) { c.Endpoint += "/%2F" },
		"endpoint port":               func(c *Config) { c.Endpoint = "https://elven-gateway:65536" },
		"no TLS secret":               func(c *Config) { c.TLSSecretName = "" },
		"invalid DNS secret":          func(c *Config) { c.TLSSecretName = "elven..tls" },
		"invalid secret segment":      func(c *Config) { c.TLSSecretName = strings.Repeat("a", 64) + ".tls" },
		"external repository": func(c *Config) {
			c.Images = map[string]string{"java": "other/runtime:1@sha256:" + strings.Repeat("a", 64)}
		},
		"wrong runtime repository": func(c *Config) { c.Images = map[string]string{"java": valid.Images["nodejs"]} },
		"mutable image": func(c *Config) {
			c.Images = map[string]string{"java": "docker.io/elvenobservability/elven-auto-java:2.33.1-2"}
		},
		"latest image": func(c *Config) {
			c.Images = map[string]string{"java": "docker.io/elvenobservability/elven-auto-java:latest@sha256:" + strings.Repeat("a", 64)}
		},
		"invalid ratio":            func(c *Config) { c.SamplingRatio = "NaN" },
		"excessive ratio":          func(c *Config) { c.SamplingRatio = "1.1" },
		"unbounded payload volume": func(c *Config) { c.SDKVolumeSizeMiB = 513 },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			raw, _ := json.Marshal(c)
			if _, err := parseConfig(raw); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for _, raw := range []string{`{}`, `{"unknown":true}`, `{} {}`} {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Fatal("invalid document accepted")
		}
	}
}

func TestRuntimeInjectionPreservesApplicationAndUsesMTLS(t *testing.T) {
	config := configForTest(t)
	for _, runtime := range []string{"java", "nodejs", "python"} {
		t.Run(runtime, func(t *testing.T) {
			pod := podForTest(runtime)
			original, _ := json.Marshal(pod)
			patch, err := newOperator(config).admit(requestForTest(t, pod))
			if err != nil {
				t.Fatal(err)
			}
			if len(patch) != 4+len(runtimeEnvironment(runtime, config.Endpoint, "elven-demo", "elven-demo-service", "1")) {
				t.Fatalf("unexpected patch size %d", len(patch))
			}
			after, _ := json.Marshal(pod)
			if !bytes.Equal(original, after) {
				t.Fatal("handler mutated input Pod")
			}
			for _, operation := range patch {
				if strings.Contains(operation.Path, "securityContext") || strings.Contains(operation.Path, "/image") || strings.Contains(operation.Path, "/serviceAccount") {
					t.Fatalf("application field rewritten: %s", operation.Path)
				}
			}
			env := environment(t, patch)
			if _, exists := env["APPLICATION_SETTING"]; exists {
				t.Fatal("original app setting unnecessarily re-echoed")
			}
			if env["OTEL_EXPORTER_OTLP_ENDPOINT"] != config.Endpoint || env["OTEL_EXPORTER_OTLP_PROTOCOL"] != "http/protobuf" {
				t.Fatal("OTLP endpoint changed")
			}
			for key, file := range map[string]string{"OTEL_EXPORTER_OTLP_CERTIFICATE": "ca.crt", "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE": "client.crt", "OTEL_EXPORTER_OTLP_CLIENT_KEY": "client.key"} {
				if env[key] != tlsMount+"/"+file {
					t.Fatalf("missing TLS %s", key)
				}
			}
			if env["OTEL_PROPAGATORS"] != "tracecontext" || env["OTEL_TRACES_SAMPLER"] != "parentbased_traceidratio" || env["OTEL_TRACES_SAMPLER_ARG"] != "1" {
				t.Fatal("unsafe propagation or sampling defaults")
			}
			if _, exists := env["OTEL_EXPORTER_OTLP_INSECURE"]; exists {
				t.Fatal("insecure TLS override injected")
			}
			if _, exists := env["OTEL_EXPORTER_OTLP_HEADERS"]; exists {
				t.Fatal("backend credentials must never enter application environment")
			}
			for _, signal := range []string{"TRACES", "METRICS", "LOGS"} {
				if env["OTEL_"+signal+"_EXPORTER"] != "otlp" {
					t.Fatalf("missing %s exporter", signal)
				}
			}
			initializers := patch[1].Value.([]any)
			initializer := initializers[len(initializers)-1].(map[string]any)
			if initializer["image"] != config.Images[runtime] {
				t.Fatal("unpinned or wrong SDK image")
			}
			security := initializer["securityContext"].(map[string]any)
			if security["allowPrivilegeEscalation"] != false || security["runAsNonRoot"] != true || security["readOnlyRootFilesystem"] != true {
				t.Fatal("unsafe init context")
			}
			mounts := patch[2].Value.([]any)
			if len(mounts) != 3 || mounts[0].(map[string]any)["name"] != "application-data" || mounts[1].(map[string]any)["readOnly"] != true || mounts[2].(map[string]any)["readOnly"] != true {
				t.Fatal("app mounts not preserved/read-only")
			}
			switch runtime {
			case "java":
				if env["JAVA_TOOL_OPTIONS"] != "-javaagent:/elven-auto/javaagent.jar" || env["OTEL_INSTRUMENTATION_COMMON_DB_QUERY_SANITIZATION_ENABLED"] != "true" {
					t.Fatal("Java loader or statement privacy incorrect")
				}
			case "nodejs":
				if env["NODE_OPTIONS"] != "--require=/elven-auto/autoinstrumentation.js" {
					t.Fatal("Node loader missing")
				}
			case "python":
				if !strings.Contains(env["PYTHONPATH"], "/elven-auto/opentelemetry/instrumentation/auto_instrumentation") {
					t.Fatal("Python loader missing")
				}
			}
		})
	}
}

func TestNamespaceOperationAndPodOptInBoundaries(t *testing.T) {
	op := newOperator(configForTest(t))
	for name, change := range map[string]func(*admissionRequest){
		"different namespace": func(r *admissionRequest) { r.Namespace = "unselected" },
		"system namespace":    func(r *admissionRequest) { r.Namespace = "kube-system" },
		"update":              func(r *admissionRequest) { r.Operation = "UPDATE" },
		"delete":              func(r *admissionRequest) { r.Operation = "DELETE" },
		"subresource":         func(r *admissionRequest) { r.SubResource = "ephemeralcontainers" },
		"deployment":          func(r *admissionRequest) { r.Kind.Kind = "Deployment"; r.Resource.Resource = "deployments" },
		"custom Pod resource": func(r *admissionRequest) { r.Kind.Group = "example.invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			request := requestForTest(t, podForTest("java"))
			change(request)
			patch, err := op.admit(request)
			if err != nil || len(patch) != 0 {
				t.Fatal("unselected request was changed or denied")
			}
		})
	}
	for _, labelPresent := range []bool{false, true} {
		pod := podForTest("false")
		if !labelPresent {
			delete(pod["metadata"].(map[string]any)["labels"].(map[string]any), injectLabel)
		}
		patch, err := op.admit(requestForTest(t, pod))
		if err != nil || len(patch) != 0 {
			t.Fatal("Pod without opt-in changed")
		}
	}
	if _, err := op.admit(requestForTest(t, podForTest("unsupported"))); err == nil {
		t.Fatal("unknown selected runtime silently accepted")
	}
}

func TestPresentEmptyUnknownAndDisabledRuntimeLabelsAreDenied(t *testing.T) {
	config := configForTest(t)
	delete(config.Images, "python")
	op := newOperator(config)
	for _, runtime := range []string{"", "unknown-runtime", "python"} {
		t.Run(runtime, func(t *testing.T) {
			request := requestForTest(t, podForTest(runtime))
			if _, err := op.admit(request); err == nil {
				t.Fatal("selected invalid or disabled runtime accepted")
			}
			review := admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Request: request}
			raw, _ := json.Marshal(review)
			httpRequest := httptest.NewRequest(http.MethodPost, "https://elven.invalid/mutate", bytes.NewReader(raw))
			httpRequest.Header.Set("Content-Type", "application/json")
			writer := httptest.NewRecorder()
			op.serveMutate(writer, httpRequest)
			var response admissionReview
			if writer.Code != http.StatusOK || json.Unmarshal(writer.Body.Bytes(), &response) != nil || response.Response == nil || response.Response.Allowed || response.Response.Patch != "" || response.Response.UID != request.UID {
				t.Fatal("full AdmissionReview did not reject selected invalid or disabled runtime")
			}
		})
	}
}

func TestLinuxOnlySDKsNeverRewriteWindowsOrConflictingSelectors(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"Windows Pod OS":             func(spec map[string]any) { spec["os"] = map[string]any{"name": "windows"} },
		"Windows node selection":     func(spec map[string]any) { spec["nodeSelector"] = map[string]any{"kubernetes.io/os": "windows"} },
		"invalid Pod OS type":        func(spec map[string]any) { spec["os"] = "windows" },
		"invalid node selector type": func(spec map[string]any) { spec["nodeSelector"] = "windows" },
	} {
		t.Run(name, func(t *testing.T) {
			pod := podForTest("java")
			change(pod["spec"].(map[string]any))
			before, _ := json.Marshal(pod)
			if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err == nil {
				t.Fatal("non-Linux selected Pod accepted")
			}
			after, _ := json.Marshal(pod)
			if !bytes.Equal(before, after) {
				t.Fatal("application scheduling rewritten")
			}
		})
	}
	pod := podForTest("java")
	pod["spec"].(map[string]any)["os"] = map[string]any{"name": "linux"}
	pod["spec"].(map[string]any)["nodeSelector"] = map[string]any{"kubernetes.io/os": "linux", "application-pool": "preserve"}
	if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err != nil {
		t.Fatal(err)
	}
}

func TestActiveForeignAdmissionMarkersRejectBeforeAnyMutation(t *testing.T) {
	keys := []string{"admission.datadoghq.com/enabled", "oneagent.dynatrace.com/inject", "oneagent.dynatrace.com/injected", "newrelic.io/inject", "newrelic.com/inject", "newrelic.com/instrumentation", "newrelic-k8s-agents-operator-version", "newrelic-k8s-agents-operator-txid"}
	for _, location := range []string{"labels", "annotations"} {
		for _, key := range keys {
			for _, value := range []string{"true", "", "selected-agent"} {
				t.Run(location+"/"+key+"/"+value, func(t *testing.T) {
					pod := podForTest("java")
					metadata := pod["metadata"].(map[string]any)
					if _, ok := metadata[location]; !ok {
						metadata[location] = map[string]any{}
					}
					metadata[location].(map[string]any)[key] = value
					if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err == nil {
						t.Fatal("another admission authority can stack an agent")
					}
				})
			}
		}
	}
	pod := podForTest("java")
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{"oneagent.dynatrace.com/inject": "false"}
	if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err != nil {
		t.Fatal("explicitly disabled foreign injector rejected")
	}
}

func TestExistingInstrumentationAndLoaderSettingsAreNeverOverwritten(t *testing.T) {
	for _, name := range []string{"OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "LD_PRELOAD", "LD_AUDIT", "CORECLR_ENABLE_PROFILING", "ELVEN_CONFIGURATION", "NEW_RELIC_APP_NAME", "NEWRELIC_ENABLED"} {
		t.Run(name, func(t *testing.T) {
			pod := podForTest("java")
			container := pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			container["env"] = []any{map[string]any{"name": name, "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "private", "key": "key"}}}}
			if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err == nil {
				t.Fatal("existing configuration overwritten")
			}
		})
	}
	for name, change := range map[string]func(map[string]any){
		"upstream annotation": func(p map[string]any) {
			p["metadata"].(map[string]any)["annotations"] = map[string]any{"instrumentation.opentelemetry.io/inject-java": "true"}
		},
		"existing Elven marker": func(p map[string]any) {
			p["metadata"].(map[string]any)["annotations"] = map[string]any{injectedAnnotation: "java"}
		},
		"SDK volume": func(p map[string]any) {
			p["spec"].(map[string]any)["volumes"] = []any{map[string]any{"name": sdkVolume}}
		},
		"TLS volume": func(p map[string]any) {
			p["spec"].(map[string]any)["volumes"] = []any{map[string]any{"name": tlsVolume}}
		},
		"upstream volume": func(p map[string]any) {
			p["spec"].(map[string]any)["volumes"] = []any{map[string]any{"name": "opentelemetry-auto-instrumentation-java"}}
		},
		"existing init": func(p map[string]any) {
			p["spec"].(map[string]any)["initContainers"] = []any{map[string]any{"name": initName}}
		},
		"old instrumentation init": func(p map[string]any) {
			p["spec"].(map[string]any)["initContainers"] = []any{map[string]any{"name": "opentelemetry-auto-instrumentation"}}
		},
		"existing admission agent image": func(p map[string]any) {
			p["spec"].(map[string]any)["initContainers"] = []any{map[string]any{"name": "unknown-initializer", "image": "docker.io/newrelic/newrelic-node-init:synthetic"}}
		},
		"TLS mount": func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "private", "mountPath": tlsMount}}
		},
		"parent TLS mount": func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "private", "mountPath": "/var/run"}}
		},
		"nested SDK mount": func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "private", "mountPath": "/elven-auto/existing"}}
		},
		"hidden envFrom": func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["envFrom"] = []any{map[string]any{"secretRef": map[string]string{"name": "private"}}}
		},
		"duplicate env": func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"] = []any{map[string]any{"name": "DUPLICATE", "value": "a"}, map[string]any{"name": "DUPLICATE", "value": "b"}}
		},
		"startup agent": func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["args"] = []any{"-javaagent:/existing/agent.jar"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod := podForTest("java")
			change(pod)
			if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err == nil {
				t.Fatal("existing agent/settings adopted or duplicated")
			}
		})
	}
}

func TestMultiContainerSelectionIsExplicitAndDoesNotRewriteSidecar(t *testing.T) {
	pod := podForTest("nodejs")
	spec := pod["spec"].(map[string]any)
	spec["containers"] = append(spec["containers"].([]any), map[string]any{"name": "elven-demo-sidecar", "image": "synthetic-sidecar:1", "env": []any{map[string]any{"name": "OTEL_SERVICE_NAME", "value": "existing-sidecar-authority"}}})
	op := newOperator(configForTest(t))
	if _, err := op.admit(requestForTest(t, pod)); err == nil {
		t.Fatal("ambiguous multi-container Pod accepted")
	}
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{containerAnnotation: "elven-demo-app", "preserve.example/key": "preserve-value"}
	patch, err := op.admit(requestForTest(t, pod))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range patch {
		if strings.HasPrefix(operation.Path, "/spec/containers/1") {
			t.Fatal("sidecar was modified")
		}
	}
	if patch[len(patch)-1].Path != "/metadata/annotations/elven.observability~1injected" {
		t.Fatal("annotation path not escaped/preserved")
	}
	pod["metadata"].(map[string]any)["annotations"].(map[string]any)[containerAnnotation] = "missing"
	if _, err := op.admit(requestForTest(t, pod)); err == nil {
		t.Fatal("missing container accepted")
	}
}

func TestPythonMuslSelectionAndDeterministicMutation(t *testing.T) {
	pod := podForTest("python")
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{"elven.observability/python-platform": "musl"}
	op := newOperator(configForTest(t))
	request := requestForTest(t, pod)
	first, err := op.admit(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := op.admit(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("mutation is not deterministic")
	}
	command := first[1].Value.([]any)[0].(map[string]any)["command"].([]string)
	if !reflect.DeepEqual(command, []string{"cp", "-R", "/autoinstrumentation-musl/.", "/elven-auto/"}) {
		t.Fatal("wrong musl payload")
	}
	pod["metadata"].(map[string]any)["annotations"].(map[string]any)["elven.observability/python-platform"] = "unknown"
	if _, err := op.admit(requestForTest(t, pod)); err == nil {
		t.Fatal("unreviewed Python runtime accepted")
	}
}

func TestAdmissionHTTPEnvelopeAndPatchAreRealJSON(t *testing.T) {
	op := newOperator(configForTest(t))
	server := httptest.NewTLSServer(http.HandlerFunc(op.serveMutate))
	defer server.Close()
	payload, _ := json.Marshal(admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Request: requestForTest(t, podForTest("java"))})
	response, err := server.Client().Post(server.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("admission failed")
	}
	var review admissionReview
	if err := json.NewDecoder(response.Body).Decode(&review); err != nil {
		t.Fatal(err)
	}
	if review.Response == nil || !review.Response.Allowed || review.Response.UID != "synthetic-request-uid" || review.Response.PatchType != "JSONPatch" {
		t.Fatal("invalid AdmissionReview response")
	}
	encoded, err := base64.StdEncoding.DecodeString(review.Response.Patch)
	if err != nil {
		t.Fatal(err)
	}
	var patch []patchOperation
	if err := json.Unmarshal(encoded, &patch); err != nil || len(patch) != 4+len(runtimeEnvironment("java", configForTest(t).Endpoint, "elven-demo", "elven-demo-service", "1")) {
		t.Fatal("invalid JSONPatch")
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("admission data may be cached")
	}
}

func TestAdmissionRejectsMalformedAndOversizedRequestsWithoutReflectingData(t *testing.T) {
	op := newOperator(configForTest(t))
	for name, test := range map[string]struct {
		method, media, payload string
		status                 int
	}{
		"wrong method":       {http.MethodGet, "application/json", `{}`, http.StatusMethodNotAllowed},
		"wrong content type": {http.MethodPost, "text/plain", `{}`, http.StatusUnsupportedMediaType},
		"invalid JSON":       {http.MethodPost, "application/json", `{"private":"SYNTHETIC-PRIVATE-SENTINEL"`, http.StatusBadRequest},
		"missing envelope":   {http.MethodPost, "application/json", `{}`, http.StatusBadRequest},
		"oversize":           {http.MethodPost, "application/json", `{"private":"` + strings.Repeat("x", maxAdmissionBytes) + `"}`, http.StatusRequestEntityTooLarge},
		"multiple documents": {http.MethodPost, "application/json", `{} {}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://elven.invalid/mutate", strings.NewReader(test.payload))
			request.Header.Set("Content-Type", test.media)
			writer := httptest.NewRecorder()
			op.serveMutate(writer, request)
			if writer.Code != test.status {
				t.Fatalf("got%d expected%d", writer.Code, test.status)
			}
			if strings.Contains(writer.Body.String(), "SYNTHETIC-PRIVATE-SENTINEL") {
				t.Fatal("request data reflected")
			}
		})
	}
	for _, uid := range []string{"", "bad/uid", strings.Repeat("x", 129)} {
		review := admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Request: requestForTest(t, podForTest("java"))}
		review.Request.UID = uid
		raw, _ := json.Marshal(review)
		request := httptest.NewRequest(http.MethodPost, "https://elven.invalid/mutate", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		writer := httptest.NewRecorder()
		op.serveMutate(writer, request)
		if writer.Code != http.StatusBadRequest {
			t.Fatal("invalid UID accepted")
		}
	}
}

func TestAdmissionRejectionDoesNotExposePrivateEnvironment(t *testing.T) {
	pod := podForTest("java")
	pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"] = []any{map[string]any{"name": "OTEL_EXPORTER_OTLP_HEADERS", "value": "Authorization=Bearer SYNTHETIC-PRIVATE-SENTINEL"}}
	review := admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Request: requestForTest(t, pod)}
	raw, _ := json.Marshal(review)
	request := httptest.NewRequest(http.MethodPost, "https://elven.invalid/mutate", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	writer := httptest.NewRecorder()
	newOperator(configForTest(t)).serveMutate(writer, request)
	if writer.Code != http.StatusOK {
		t.Fatal("admission denial must use an AdmissionReview")
	}
	var result admissionReview
	if json.Unmarshal(writer.Body.Bytes(), &result) != nil || result.Response == nil || result.Response.Allowed {
		t.Fatal("conflict not rejected")
	}
	if strings.Contains(writer.Body.String(), "SYNTHETIC-PRIVATE-SENTINEL") {
		t.Fatal("private environment leaked")
	}
}

func TestSuccessfulPatchNeverReechoesExistingApplicationCredentials(t *testing.T) {
	for _, mode := range []string{"existing", "absent", "null", "empty"} {
		t.Run(mode, func(t *testing.T) {
			pod := podForTest("java")
			container := pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			switch mode {
			case "existing":
				container["env"] = append(container["env"].([]any), map[string]any{"name": "APPLICATION_PRIVATE_KEY", "value": "SYNTHETIC-PRIVATE-APP-SENTINEL"})
			case "absent":
				delete(container, "env")
			case "null":
				container["env"] = nil
			case "empty":
				container["env"] = []any{}
			}
			patch, err := newOperator(configForTest(t)).admit(requestForTest(t, pod))
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(patch)
			if strings.Contains(string(encoded), "SYNTHETIC-PRIVATE-APP-SENTINEL") || strings.Contains(string(encoded), "APPLICATION_PRIVATE_KEY") {
				t.Fatal("original application credentials reflected in successful patch")
			}
			// Apply actual env JSONPatch operations to a JSON-cloned Pod. Independent
			// volume/init/annotation operations cannot replace this environment array.
			cloneBytes, _ := json.Marshal(pod)
			var clone map[string]any
			_ = json.Unmarshal(cloneBytes, &clone)
			clonedContainer := clone["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			for _, operation := range patch {
				switch operation.Path {
				case "/spec/containers/0/env":
					clonedContainer["env"] = operation.Value
				case "/spec/containers/0/env/-":
					clonedContainer["env"] = append(clonedContainer["env"].([]any), operation.Value)
				}
			}
			foundPrivate, foundEndpoint := false, false
			for _, raw := range clonedContainer["env"].([]any) {
				entry := raw.(map[string]any)
				if entry["name"] == "APPLICATION_PRIVATE_KEY" {
					foundPrivate = entry["value"] == "SYNTHETIC-PRIVATE-APP-SENTINEL"
				}
				if entry["name"] == "OTEL_EXPORTER_OTLP_ENDPOINT" {
					foundEndpoint = true
				}
			}
			if foundPrivate != (mode == "existing") || !foundEndpoint {
				t.Fatal("append-only env patch failed to preserve original credentials and add SDK config")
			}
		})
	}
}

func TestMalformedSelectedPodFieldsFailClosed(t *testing.T) {
	for _, field := range []string{"containers", "volumes", "initContainers"} {
		t.Run(field, func(t *testing.T) {
			pod := podForTest("java")
			pod["spec"].(map[string]any)[field] = "invalid"
			if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err == nil {
				t.Fatal("malformed selected Pod accepted")
			}
		})
	}
	pod := podForTest("java")
	pod["metadata"].(map[string]any)["namespace"] = "other"
	if _, err := newOperator(configForTest(t)).admit(requestForTest(t, pod)); err == nil {
		t.Fatal("mismatched namespace accepted")
	}
	op := newOperator(configForTest(t))
	for i := 0; i < cap(op.slots); i++ {
		op.slots <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodPost, "https://elven.invalid/mutate", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	writer := httptest.NewRecorder()
	op.serveMutate(writer, request)
	if writer.Code != http.StatusServiceUnavailable {
		t.Fatal("capacity is unbounded")
	}
}

func TestServiceIdentityIsStableAndCannotInjectResourceAttributes(t *testing.T) {
	op := newOperator(configForTest(t))
	pod := podForTest("java")
	pod["metadata"].(map[string]any)["name"] = "elven-demo-generated-pod-unique"
	pod["metadata"].(map[string]any)["annotations"] = map[string]any{"elven.observability/service-name": "elven-orders-api"}
	patch, err := op.admit(requestForTest(t, pod))
	if err != nil {
		t.Fatal(err)
	}
	if environment(t, patch)["OTEL_SERVICE_NAME"] != "elven-orders-api" {
		t.Fatal("stable explicit service name ignored")
	}
	for _, invalid := range []string{"service,secret=value", "service\nprivate", "service with spaces", strings.Repeat("x", 129)} {
		pod["metadata"].(map[string]any)["annotations"].(map[string]any)["elven.observability/service-name"] = invalid
		if _, err := op.admit(requestForTest(t, pod)); err == nil {
			t.Fatal("unsafe service identity accepted")
		}
	}
}

func TestNodeSDKUsesOnlyExplicitEnvironmentResourceDiscovery(t *testing.T) {
	for _, runtime := range []string{"nodejs", "nodejs20"} {
		env := environment(t, []patchOperation{{Op: "add", Path: "/env", Value: runtimeEnvironment(runtime, "https://elven-gateway:4318", "elven-demo", "elven-service", "1")}})
		if env["OTEL_NODE_RESOURCE_DETECTORS"] != "env" {
			t.Fatal("Node SDK probes cloud metadata or process arguments")
		}
		if env["OTEL_SERVICE_NAME"] != "elven-service" || !strings.Contains(env["OTEL_RESOURCE_ATTRIBUTES"], "k8s.namespace.name=elven-demo") {
			t.Fatal("explicit resource identity lost")
		}
	}
}

func TestLegacyNode20RequiresSeparateImageAndExplicitApproval(t *testing.T) {
	config := configForTest(t)
	config.Images["nodejs20"] = "docker.io/elvenobservability/elven-auto-nodejs20:0.81.2-1@sha256:" + strings.Repeat("d", 64)
	raw, _ := json.Marshal(config)
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("EOL runtime accepted without approval")
	}
	config.LegacyNode20Approved = true
	raw, _ = json.Marshal(config)
	approved, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := newOperator(approved).admit(requestForTest(t, podForTest("nodejs20")))
	if err != nil {
		t.Fatal(err)
	}
	if environment(t, patch)["NODE_OPTIONS"] != "--require=/elven-auto/autoinstrumentation.js" {
		t.Fatal("legacy Node loader is missing")
	}
	config.Images["nodejs20"] = config.Images["nodejs"]
	raw, _ = json.Marshal(config)
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("Node 22+ agent reused for Node 20")
	}
}

func Example_runtimeEnvironment() {
	entries := runtimeEnvironment("java", "https://elven-gateway:4318", "elven-demo", "elven-demo-service", "0.1")
	for _, raw := range entries {
		entry := raw.(map[string]any)
		if entry["name"] == "OTEL_PROPAGATORS" {
			fmt.Println(entry["value"])
		}
	}
	// Output: tracecontext
}

func TestNoTLSClientCanReachHTTPSAdmission(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(newOperator(configForTest(t)).serveMutate))
	defer server.Close()
	response, err := http.Get(server.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("untrusted serving certificate accepted")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate verification failure, got %v", err)
	}
	response, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("trusted request did not reach admission method guard")
	}
}
