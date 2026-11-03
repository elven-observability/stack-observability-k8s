// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func testProcessor() *privacyProcessor { return &privacyProcessor{config: *defaultConfig()} }
func noPrivate(t *testing.T, output string, private ...string) {
	t.Helper()
	for _, v := range private {
		if strings.Contains(output, v) {
			t.Fatalf("private fixture %q remained in %s", v, output)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	if err := defaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.LogBodyMode = "off" }, func(c *Config) { c.MaxDepth = 0 }, func(c *Config) { c.MaxDepth = 65 },
		func(c *Config) { c.MaxStringBytes = 255 }, func(c *Config) { c.MaxStringBytes = 1048577 },
		func(c *Config) { c.MaxCollectionItems = 0 }, func(c *Config) { c.MaxCollectionItems = 16385 },
	} {
		c := defaultConfig()
		change(c)
		if c.Validate() == nil {
			t.Fatalf("unsafe config accepted: %+v", c)
		}
	}
	f := NewFactory()
	if f.Type().String() != "elven_privacy" {
		t.Fatal("wrong component identity")
	}
	if err := f.CreateDefaultConfig().(*Config).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMaxDepthRetainsOTLPInteroperability(t *testing.T) {
	if defaultConfig().MaxDepth != 24 {
		t.Fatal("the default must leave protobuf envelope recursion headroom")
	}
	for name, depth := range map[string]int{"minimum": 1, "maximum": 24} {
		t.Run(name, func(t *testing.T) {
			c := defaultConfig()
			c.MaxDepth = depth
			if err := c.Validate(); err != nil {
				t.Fatalf("supported depth %d rejected: %v", depth, err)
			}
		})
	}
	for name, depth := range map[string]int{"zero": 0, "above_maximum": 25, "old_default": 32, "old_ceiling": 64} {
		t.Run(name, func(t *testing.T) {
			c := defaultConfig()
			c.MaxDepth = depth
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "24") {
				t.Fatalf("unsafe depth %d not rejected with an actionable bound: %v", depth, err)
			}
		})
	}
}

func TestLogsFullEnvelopeAndUtility(t *testing.T) {
	data := plog.NewLogs()
	r := data.ResourceLogs().AppendEmpty()
	r.Resource().Attributes().PutStr("service.name", "checkout")
	r.Resource().Attributes().PutEmptyMap("nested").PutInt("accessToken", 123456)
	r.SetSchemaUrl("https://schemas.elven.invalid/1?token=RESOURCE_PRIVATE")
	scope := r.ScopeLogs().AppendEmpty()
	scope.Scope().SetName("alice@example.com")
	scope.Scope().SetVersion("password=SCOPE_PRIVATE")
	scope.Scope().Attributes().PutStr("Authorization", "SCOPE_AUTH_PRIVATE")
	record := scope.LogRecords().AppendEmpty()
	record.Body().SetStr("order completed latency=42ms email=alice@example.com password=LOG_PRIVATE")
	record.Attributes().PutInt("http.response.status_code", 200)
	record.Attributes().PutEmptyMap("service.name").PutStr("password", "MAP_PRIVATE")
	record.Attributes().PutEmptyMap("alice@example.com").PutStr("display", "PERSON_NAME_PRIVATE")
	record.Attributes().PutStr("db.statement", "SELECT id FROM orders WHERE email='alice@example.com' AND id=314159")
	record.Attributes().PutEmptySlice("db.query.parameters").AppendEmpty().SetStr("PARAM_PRIVATE")
	record.SetSeverityText("INFO token=SEVERITY_PRIVATE")
	record.SetEventName("order password=EVENT_PRIVATE")
	tid := pcommon.TraceID{1, 2, 3}
	sid := pcommon.SpanID{4, 5, 6}
	record.SetTraceID(tid)
	record.SetSpanID(sid)
	testProcessor().processLogs(context.Background(), data)
	output, _ := (&plog.JSONMarshaler{}).MarshalLogs(data)
	noPrivate(t, string(output), "alice@example.com", "RESOURCE_PRIVATE", "SCOPE_PRIVATE", "SCOPE_AUTH_PRIVATE", "LOG_PRIVATE", "MAP_PRIVATE", "PERSON_NAME_PRIVATE", "PARAM_PRIVATE", "SEVERITY_PRIVATE", "EVENT_PRIVATE", "314159", "123456")
	if !strings.Contains(record.Body().Str(), "order completed latency=42ms") {
		t.Fatal("operational text lost")
	}
	if record.TraceID() != tid || record.SpanID() != sid {
		t.Fatal("correlation changed")
	}
	if v, _ := record.Attributes().Get("http.response.status_code"); v.Int() != 200 {
		t.Fatal("numeric metadata changed")
	}
	if v, _ := record.Attributes().Get("db.statement"); !strings.Contains(v.Str(), "SELECT id FROM orders") {
		t.Fatal("query shape lost")
	}
}

func TestStructuredBodiesNonStringSecrets(t *testing.T) {
	for _, structured := range []bool{false, true} {
		data := plog.NewLogs()
		record := data.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		if structured {
			body := record.Body().SetEmptyMap()
			body.PutStr("message", "payment completed in 42ms")
			body.PutEmptyMap("request").PutInt("password", 345678)
			body.PutEmptySlice("items").AppendEmpty().SetEmptyMap().PutStr("email", "alice@example.com")
			body.PutEmptyMap("Authorization").PutStr("credential", "STRUCT_PRIVATE")
		} else {
			record.Body().SetStr(`{"message":"payment completed in 42ms","request":{"password":345678},"items":[{"email":"alice@example.com"}],"Authorization":{"credential":"STRUCT_PRIVATE"}}`)
		}
		testProcessor().processLogs(context.Background(), data)
		output, _ := (&plog.JSONMarshaler{}).MarshalLogs(data)
		noPrivate(t, string(output), "345678", "alice@example.com", "STRUCT_PRIVATE")
		if !strings.Contains(string(output), "payment completed in 42ms") {
			t.Fatal("nested message lost")
		}
		if !structured {
			var body any
			if json.Unmarshal([]byte(record.Body().Str()), &body) != nil {
				t.Fatal("JSON destroyed")
			}
		}
	}
}

func TestStrictModePreservesUsefulMetadata(t *testing.T) {
	data := plog.NewLogs()
	record := data.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	record.Body().SetStr("arbitrary private body")
	record.Attributes().PutInt("http.response.status_code", 500)
	p := testProcessor()
	p.config.LogBodyMode = "strict"
	p.processLogs(context.Background(), data)
	if record.Body().Str() != mask {
		t.Fatal("strict body leaked")
	}
	if v, _ := record.Attributes().Get("http.response.status_code"); v.Int() != 500 {
		t.Fatal("useful metadata lost")
	}
}

func TestTracesEventsLinksAndCorrelation(t *testing.T) {
	data := ptrace.NewTraces()
	r := data.ResourceSpans().AppendEmpty()
	r.Resource().Attributes().PutEmptyMap("service.name").PutStr("password", "RESOURCE_PRIVATE")
	r.SetSchemaUrl("https://schemas.elven.invalid/?token=SCHEMA_PRIVATE")
	scope := r.ScopeSpans().AppendEmpty()
	scope.Scope().SetName("alice@example.com")
	span := scope.Spans().AppendEmpty()
	span.SetName("SELECT id FROM orders WHERE id=271828 AND email='alice@example.com'")
	span.Status().SetMessage("failed token=STATUS_PRIVATE")
	span.Attributes().PutInt("db.query.parameters", 456789)
	span.TraceState().FromRaw("vendor=OPAQUE_PRIVATE")
	event := span.Events().AppendEmpty()
	event.SetName("failure alice@example.com")
	event.Attributes().PutEmptyMap("exception.type").PutStr("apiKey", "EVENT_PRIVATE")
	link := span.Links().AppendEmpty()
	link.Attributes().PutStr("password", "LINK_PRIVATE")
	link.TraceState().FromRaw("vendor=LINK_STATE_PRIVATE")
	tid := pcommon.TraceID{1, 2, 3}
	sid := pcommon.SpanID{9, 8, 7}
	span.SetTraceID(tid)
	span.SetSpanID(sid)
	link.SetTraceID(tid)
	link.SetSpanID(sid)
	testProcessor().processTraces(context.Background(), data)
	output, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(data)
	noPrivate(t, string(output), "RESOURCE_PRIVATE", "SCHEMA_PRIVATE", "alice@example.com", "271828", "STATUS_PRIVATE", "456789", "OPAQUE_PRIVATE", "EVENT_PRIVATE", "LINK_PRIVATE", "LINK_STATE_PRIVATE")
	if span.TraceID() != tid || span.SpanID() != sid || link.TraceID() != tid || link.SpanID() != sid {
		t.Fatal("correlation changed")
	}
	if span.Links().Len() != 1 || !strings.HasPrefix(span.Name(), "SELECT id FROM orders") {
		t.Fatal("useful query/link lost")
	}
	p := testProcessor()
	p.config.PreserveSpanLinks = false
	p.processTraces(context.Background(), data)
	if span.Links().Len() != 0 {
		t.Fatal("explicit link removal ignored")
	}
}

func TestMetricsMetadataExemplarsAndNumericObservations(t *testing.T) {
	data := pmetric.NewMetrics()
	r := data.ResourceMetrics().AppendEmpty()
	r.Resource().Attributes().PutStr("service.name", "alice@example.com")
	scope := r.ScopeMetrics().AppendEmpty()
	scope.Scope().Attributes().PutStr("token", "SCOPE_PRIVATE")
	m := scope.Metrics().AppendEmpty()
	m.SetName("latency.alice@example.com")
	m.SetDescription("latency token=DESCRIPTION_PRIVATE")
	m.SetUnit("password=UNIT_PRIVATE")
	m.Metadata().PutEmptyMap("credentials").PutStr("other", "METADATA_PRIVATE")
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(42424242424)
	dp.Attributes().PutInt("http.response.status_code", 200)
	dp.Attributes().PutStr("customer.email", "alice@example.com")
	exemplar := dp.Exemplars().AppendEmpty()
	exemplar.FilteredAttributes().PutInt("accessToken", 987654)
	tid := pcommon.TraceID{6, 7, 8}
	exemplar.SetTraceID(tid)
	testProcessor().processMetrics(context.Background(), data)
	output, _ := (&pmetric.JSONMarshaler{}).MarshalMetrics(data)
	noPrivate(t, string(output), "alice@example.com", "SCOPE_PRIVATE", "DESCRIPTION_PRIVATE", "UNIT_PRIVATE", "METADATA_PRIVATE", "987654")
	if dp.IntValue() != 42424242424 || exemplar.TraceID() != tid {
		t.Fatal("metric observation/correlation changed")
	}
	if m.Name() != "elven.redacted.metric" || m.Unit() != "1" {
		t.Fatal("metric identifiers not normalized")
	}
}

func TestBudgetsMalformedBytesAndIdempotency(t *testing.T) {
	p := testProcessor()
	p.config.MaxDepth = 3
	p.config.MaxStringBytes = 256
	p.config.MaxCollectionItems = 8
	fixtures := []string{`{"message":"ok","password":`, `{"nested":{"nested":{"nested":{"email":"alice@example.com"}}}}`,
		strings.Repeat("x", 257), "\xffpassword=PRIVATE", "[REDACTED] password=PRIVATE",
		"[INFO] request completed in 42ms", "[2026-11-03T00:00:00Z] completed in 42ms",
		`{"message":"ok","nested":{"accessToken":"PRIVATE"}}`, `"{\"password\":\"PRIVATE\"}"`,
		"DELETE /orders", "update cache complete status=200"}
	for _, input := range fixtures {
		first := p.cleanText(input)
		second := p.cleanText(first)
		noPrivate(t, first, "alice@example.com", "PRIVATE")
		if first != second {
			t.Fatalf("not idempotent: %q -> %q -> %q", input, first, second)
		}
		if strings.Contains(input, "completed in 42ms") && !strings.Contains(first, "completed in 42ms") {
			t.Fatalf("ordinary log prefix lost: %q", first)
		}
		if (input == "DELETE /orders" || input == "update cache complete status=200") && first != input {
			t.Fatalf("operational phrase lost: %q", first)
		}
	}
	v := pcommon.NewValueBytes()
	v.Bytes().FromRaw([]byte("PRIVATE"))
	p.sanitizer().valueInPlace(v, 0, "")
	if v.Str() != "[REDACTED:bytes]" {
		t.Fatal("bytes leaked")
	}
	v = pcommon.NewValueMap()
	for i := 0; i < 9; i++ {
		v.Map().PutInt(string(rune('a'+i)), int64(i))
	}
	p.sanitizer().valueInPlace(v, 0, "")
	if v.Str() != "[REDACTED:limit]" {
		t.Fatal("collection budget ignored")
	}
}

func TestScientificNumericAttributesDoNotBypassPIIPatterns(t *testing.T) {
	p := testProcessor()
	value := pcommon.NewValueDouble(52998224725)
	p.sanitizer().valueInPlace(value, 0, "measurement")
	if value.Type() != pcommon.ValueTypeStr || value.Str() != mask {
		t.Fatal("Double CPF survived scientific-notation formatting")
	}
	result := p.cleanText(`{"measurement":5.2998224725e10,"latency":4.2e1}`)
	noPrivate(t, result, "5.2998224725", "52998224725")
	var decoded map[string]any
	if err := json.Unmarshal([]byte(result), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["latency"] != float64(42) {
		t.Fatalf("operational numeric changed: %s", result)
	}
}
