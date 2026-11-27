// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestRedisOperationNeverReturnsOperandsOrScripts(t *testing.T) {
	for input, expected := range map[string]string{
		"GET account:ARBITRARY_PRIVATE_KEY":           "GET",
		"set SESSION_PRIVATE VALUE_PRIVATE EX 42":     "SET",
		"HGETALL secret:ARBITRARY_PRIVATE_KEY":        "HGETALL",
		"EVAL return('SCRIPT_PRIVATE') 1 KEY_PRIVATE": "EVAL",
		"AUTH USER_PRIVATE PASSWORD_PRIVATE":          "AUTH",
		"CLIENT SETNAME HOST_PRIVATE":                 "CLIENT",
		"CLUSTER NODES KEY_PRIVATE":                   "CLUSTER",
		"MGET %4bEY_PRIVATE VALUE_PRIVATE":            "MGET",
		"RAW_PRIVATE data":                            "[REDACTED:redis]",
		"*2\r\n$3\r\nGET\r\n$12\r\nRAW_PRIVATE":       "[REDACTED:redis]",
		"":                                            "[REDACTED:redis]",
		"[REDACTED]":                                  "[REDACTED]",
	} {
		t.Run(input, func(t *testing.T) {
			if got := redisOperation(input); got != expected {
				t.Fatalf("expected bounded operation %q, got %q", expected, got)
			}
		})
	}
}

func TestRedisFiniteErrorMarkersNeverReturnOperands(t *testing.T) {
	for _, code := range []string{"WRONGTYPE", "NOAUTH", "WRONGPASS", "NOPERM", "OOM", "READONLY", "MISCONF", "BUSY", "NOSCRIPT", "LOADING", "CLUSTERDOWN", "CROSSSLOT", "TRYAGAIN", "MOVED", "ASK", "EXECABORT", "ERR"} {
		for _, input := range []string{code, code + " OPERAND_PRIVATE password=VALUE_PRIVATE", code + "\tOPERAND_PRIVATE"} {
			got := redisDiagnosticValue("exception.message", input)
			if want := "[REDACTED:redis:" + code + "]"; got != want {
				t.Fatalf("finite category %s lost: %q", code, got)
			}
			if redisDiagnosticValue("exception.message", got) != got || !isMarker(got) {
				t.Fatal("exact finite marker must survive the second privacy boundary")
			}
			if redisDiagnosticValue("exception.stacktrace", input) != mask || redisDiagnosticValue("exception.stacktrace", got) != mask {
				t.Fatal("Redis stacks must remain fully masked, even with a known code")
			}
			noPrivate(t, got, "OPERAND_PRIVATE", "VALUE_PRIVATE")
		}
	}
}

func TestRedisDiagnosticsUnknownEncodedSpoofedOversizedAndInvalidFailClosed(t *testing.T) {
	for _, input := range []string{"", "unknown OPERAND_PRIVATE", "wrongtype OPERAND_PRIVATE", " WRONGTYPE OPERAND_PRIVATE",
		"WRONGTYPE_PRIVATE", "WRONGTYPE:OPERAND_PRIVATE", "%57RONGTYPE OPERAND_PRIVATE", `\u0057RONGTYPE OPERAND_PRIVATE`,
		"WRONGTYPE\u00a0OPERAND_PRIVATE", "WRONGTYPE\x00OPERAND_PRIVATE", "WRONGTYPE " + string([]byte{0xff}),
		"WRONGTYPE " + strings.Repeat("x", 262144), "[REDACTED:redis:UNKNOWN]", "[REDACTED:redis:WRONGTYPE]PRIVATE",
		"[REDACTED:redis:WRONGTYPE] PRIVATE", "[REDACTED:redis:WRONGTYPE] PRIVATE]", "[REDACTED:redis:]"} {
		if got := redisDiagnosticValue("status.description", input); got != mask {
			t.Fatalf("unsafe diagnostic was not fully masked: %q", got)
		}
	}
	if isMarker("[REDACTED:redis:WRONGTYPE]PRIVATE") || isMarker("[REDACTED:redis:UNKNOWN]") {
		t.Fatal("only exact finite generated markers may bypass text parsing")
	}
}

func TestRedisFiniteErrorsThroughRealPdataHandlersKeepNoOperandsAndAreIdempotent(t *testing.T) {
	const private = "REDIS_ERROR_OPERAND_PRIVATE"
	const marker = "[REDACTED:redis:WRONGTYPE]"
	traces := ptrace.NewTraces()
	spans := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	span := spans.AppendEmpty()
	span.SetName("HGET " + private)
	span.SetTraceID(pcommon.TraceID{1, 2, 3})
	span.SetSpanID(pcommon.SpanID{4, 5, 6})
	span.SetParentSpanID(pcommon.SpanID{7, 8, 9})
	span.SetKind(ptrace.SpanKindClient)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("WRONGTYPE " + private)
	span.Attributes().PutStr("db.system.name", "redis")
	span.Attributes().PutStr("status.description", "WRONGTYPE "+private)
	span.Attributes().PutStr("exception.message", "WRONGTYPE "+private)
	span.Attributes().PutStr("exception.stacktrace", "WRONGTYPE "+private+"\n at PRIVATEFRAME")
	event := span.Events().AppendEmpty()
	event.SetName("exception")
	event.Attributes().PutStr("exception.type", "redis.clients.jedis.exceptions.JedisDataException")
	event.Attributes().PutStr("exception.message", "WRONGTYPE "+private)
	event.Attributes().PutStr("exception.stacktrace", "WRONGTYPE "+private+"\n at PRIVATEFRAME")
	// A non-Redis API error must keep its real operational message and frames.
	http := spans.AppendEmpty()
	http.SetName("GET /exercise")
	httpEvent := http.Events().AppendEmpty()
	httpEvent.SetName("exception")
	httpEvent.Attributes().PutStr("exception.message", "checkout failed for sdk.synthetic.customer@example.invalid retry=false")
	httpEvent.Attributes().PutStr("exception.stacktrace", "Error: sdk.synthetic.customer@example.invalid\n at exercise (/app/main.js:42:9)")
	logs := plog.NewLogs()
	record := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	record.Attributes().PutStr("db.system", "redis")
	record.Attributes().PutStr("exception.message", "WRONGTYPE "+private)
	record.Attributes().PutStr("status.description", "WRONGTYPE "+private)
	record.Attributes().PutEmptyMap("exception.stacktrace").PutStr("key", private)
	record.Body().SetStr(`{"db.system":"redis","exception.message":"WRONGTYPE REDIS_ERROR_OPERAND_PRIVATE","status.description":"WRONGTYPE REDIS_ERROR_OPERAND_PRIVATE","exception.stacktrace":"WRONGTYPE REDIS_ERROR_OPERAND_PRIVATE"}`)
	p := testProcessor()
	if _, err := p.processTraces(context.Background(), traces); err != nil {
		t.Fatal(err)
	}
	if _, err := p.processLogs(context.Background(), logs); err != nil {
		t.Fatal(err)
	}
	firstTraces, _ := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
	firstLogs, _ := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	noPrivate(t, string(firstTraces)+string(firstLogs), private, "PRIVATEFRAME", "sdk.synthetic.customer@example.invalid")
	if span.Name() != "HGET" || span.Status().Code() != ptrace.StatusCodeError || span.Status().Message() != marker || span.Kind() != ptrace.SpanKindClient || span.TraceID() != (pcommon.TraceID{1, 2, 3}) || span.SpanID() != (pcommon.SpanID{4, 5, 6}) || span.ParentSpanID() != (pcommon.SpanID{7, 8, 9}) {
		t.Fatal("finite Redis category, operation or correlation changed")
	}
	for _, attrs := range []pcommon.Map{span.Attributes(), event.Attributes(), record.Attributes()} {
		if value, _ := attrs.Get("exception.message"); value.Str() != marker {
			t.Fatal("finite Redis error category lost")
		}
		if value, _ := attrs.Get("exception.stacktrace"); value.Str() != mask {
			t.Fatal("Redis stack or non-string diagnostic was not completely masked")
		}
	}
	if value, _ := event.Attributes().Get("exception.type"); value.Str() != "redis.clients.jedis.exceptions.JedisDataException" {
		t.Fatal("Redis exception type lost")
	}
	if !strings.Contains(record.Body().Str(), marker) {
		t.Fatal("structured Redis log lost its finite error category")
	}
	if value, _ := httpEvent.Attributes().Get("exception.message"); value.Str() != "checkout failed for [REDACTED] retry=false" {
		t.Fatal("generic non-Redis API exception lost selective privacy")
	}
	if value, _ := httpEvent.Attributes().Get("exception.stacktrace"); !strings.Contains(value.Str(), "at exercise (/app/main.js:42:9)") {
		t.Fatal("non-Redis frames must remain useful")
	}
	p.processTraces(context.Background(), traces)
	p.processLogs(context.Background(), logs)
	secondTraces, _ := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
	secondLogs, _ := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	if string(firstTraces) != string(secondTraces) || string(firstLogs) != string(secondLogs) {
		t.Fatal("finite Redis category must be idempotent over node and gateway boundaries")
	}
}

func TestRedisDiagnosticCategoryHonorsSizeDepthPrimitiveBudgetAndType(t *testing.T) {
	p := testProcessor()
	p.config.MaxStringBytes = 256
	attrs := pcommon.NewMap()
	attrs.PutStr("db.system", "redis")
	attrs.PutStr("exception.message", "WRONGTYPE "+strings.Repeat("x", 256))
	attrs.PutInt("status.description", 42)
	p.cleanMap(attrs)
	for _, key := range []string{"exception.message", "status.description"} {
		if value, _ := attrs.Get(key); value.Str() != mask {
			t.Fatal("oversized/non-string Redis diagnostic must fail closed")
		}
	}
	input := pcommon.NewMap()
	input.PutStr("db.system", "redis")
	input.PutStr("exception.message", "WRONGTYPE PRIVATE")
	output := pcommon.NewMap()
	s := p.sanitizer()
	s.remaining = 0
	s.mapInto(input, output, 0)
	if value, _ := output.Get("exception.message"); value.Str() != "[REDACTED:limit]" {
		t.Fatal("Redis category bypassed primitive budget")
	}
	s = p.sanitizer()
	output = pcommon.NewMap()
	s.mapInto(input, output, s.config.MaxDepth)
	if value, _ := output.Get("exception.message"); value.Str() != "[REDACTED:limit]" {
		t.Fatal("Redis category bypassed map depth")
	}
	s = p.sanitizer()
	raw := s.native(map[string]any{"db.system": "redis", "exception.message": "WRONGTYPE PRIVATE"}, s.config.MaxDepth, "").(map[string]any)
	if raw["exception.message"] != "[REDACTED:limit]" {
		t.Fatal("Redis category bypassed native depth")
	}
}

func TestRedisOTLPSpansRetainOperationsExceptionsAndCorrelation(t *testing.T) {
	data := ptrace.NewTraces()
	spans := data.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	span := spans.AppendEmpty()
	span.SetTraceID(pcommon.TraceID{1, 2, 3})
	span.SetSpanID(pcommon.SpanID{4, 5, 6})
	span.SetName("GET ACCOUNT_PRIVATE")
	span.SetKind(ptrace.SpanKindClient)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("missing ACCOUNT_PRIVATE")
	span.Attributes().PutStr("db.system.name", "redis")
	span.Attributes().PutStr("db.operation.name", "GET ACCOUNT_PRIVATE")
	span.Attributes().PutStr("db.query.text", "GET ACCOUNT_PRIVATE")
	span.Attributes().PutStr("db.query.summary", "GET ACCOUNT_PRIVATE")
	span.Attributes().PutStr("db.redis.key", "ACCOUNT_PRIVATE")
	span.Attributes().PutEmptySlice("redis.arguments").AppendEmpty().SetStr("ARGUMENT_PRIVATE")
	span.Attributes().PutInt("db.redis.database_index", 1)
	e := span.Events().AppendEmpty()
	e.SetName("exception")
	e.Attributes().PutStr("exception.type", "RedisError")
	e.Attributes().PutStr("exception.message", "GET ACCOUNT_PRIVATE failed")
	e.Attributes().PutStr("exception.stacktrace", "RedisError: ACCOUNT_PRIVATE\n at client.go:42")
	testProcessor().processTraces(context.Background(), data)
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(data)
	if err != nil {
		t.Fatal(err)
	}
	noPrivate(t, string(raw), "ACCOUNT_PRIVATE", "ARGUMENT_PRIVATE")
	if span.Name() != "GET" || span.TraceID() != (pcommon.TraceID{1, 2, 3}) || span.SpanID() != (pcommon.SpanID{4, 5, 6}) || span.Status().Code() != ptrace.StatusCodeError {
		t.Fatal("operation, correlation or error status lost")
	}
	for _, key := range []string{"db.operation.name", "db.query.text", "db.query.summary"} {
		if value, ok := span.Attributes().Get(key); !ok || value.Str() != "GET" {
			t.Fatal("command was not preserved")
		}
	}
	if v, _ := e.Attributes().Get("exception.type"); v.Str() != "RedisError" {
		t.Fatal("exception type lost")
	}
	if v, _ := span.Attributes().Get("db.redis.database_index"); v.Int() != 1 {
		t.Fatal("numeric database metadata lost")
	}
	// Redaction is stable when both the source collector and gateway run it.
	testProcessor().processTraces(context.Background(), data)
	second, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(data)
	if string(raw) != string(second) {
		t.Fatal("Redis privacy is not idempotent")
	}
}

func TestRedisLogAndMetricAttributesRedactKeysAndStructuredCommands(t *testing.T) {
	logs := plog.NewLogs()
	record := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	record.Body().SetStr(`{"db.system":"redis","db.statement":"SET ACCOUNT_PRIVATE VALUE_PRIVATE","redis.key":"ACCOUNT_PRIVATE","message":"cache operation failed latency=42ms"}`)
	record.Attributes().PutStr("db.system", "redis")
	record.Attributes().PutStr("db.statement", "SET ACCOUNT_PRIVATE VALUE_PRIVATE")
	testProcessor().processLogs(context.Background(), logs)
	raw, _ := (&plog.JSONMarshaler{}).MarshalLogs(logs)
	noPrivate(t, string(raw), "ACCOUNT_PRIVATE", "VALUE_PRIVATE")
	if !strings.Contains(record.Body().Str(), "cache operation failed latency=42ms") {
		t.Fatal("operational log text lost")
	}
	if v, _ := record.Attributes().Get("db.statement"); v.Str() != "SET" {
		t.Fatal("Redis command lost")
	}
	metrics := pmetric.NewMetrics()
	metric := metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("cache.client.duration")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(42)
	dp.Attributes().PutStr("redis.key", "METRIC_KEY_PRIVATE")
	dp.Attributes().PutStr("db.system.name", "redis")
	dp.Attributes().PutStr("db.query.text", "GET METRIC_KEY_PRIVATE")
	testProcessor().processMetrics(context.Background(), metrics)
	raw, _ = (&pmetric.JSONMarshaler{}).MarshalMetrics(metrics)
	noPrivate(t, string(raw), "METRIC_KEY_PRIVATE")
	if dp.DoubleValue() != 42 || metric.Name() != "cache.client.duration" {
		t.Fatal("metric observation changed")
	}
}

func TestRedisSensitiveFieldsDoNotRequireDatabaseContext(t *testing.T) {
	for _, key := range []string{"redis.key", "db.redis.key", "redis.keys", "redis.args", "db.redis.command.args", "redis.raw_command", "%72edis.key", "redis.arguments", "redis.values", "redis.script", "db.redis.script", "%72edis.script", "redis.script.sha"} {
		t.Run(key, func(t *testing.T) {
			attrs := pcommon.NewMap()
			attrs.PutStr(key, "ARBITRARY_PRIVATE_OPERAND")
			testProcessor().cleanMap(attrs)
			if value, ok := attrs.Get(key); ok && value.Str() != mask {
				t.Fatal("Redis operands retained without context")
			}
		})
	}
}

func TestExplicitRedisCommandIsContextWithoutDatabaseSystem(t *testing.T) {
	data := ptrace.NewTraces()
	span := data.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("HGET ACCOUNT_PRIVATE FIELD_PRIVATE")
	span.Attributes().PutStr("redis.command", "HGET ACCOUNT_PRIVATE FIELD_PRIVATE")
	testProcessor().processTraces(context.Background(), data)
	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(data)
	noPrivate(t, string(raw), "ACCOUNT_PRIVATE", "FIELD_PRIVATE")
	if span.Name() != "HGET" {
		t.Fatal("explicit Redis command lost")
	}
	value, _ := span.Attributes().Get("redis.command")
	if value.Str() != "HGET" {
		t.Fatal("Redis operands leaked without db.system")
	}
	input := `{"db.redis.command":"SET KEY_PRIVATE VALUE_PRIVATE","redis.script":"return SCRIPT_PRIVATE","message":"cache update completed"}`
	output := testProcessor().cleanText(input)
	noPrivate(t, output, "KEY_PRIVATE", "VALUE_PRIVATE", "SCRIPT_PRIVATE")
	if !strings.Contains(output, "cache update completed") {
		t.Fatal("useful log message lost")
	}
}

func TestRedisFieldsHonorSizeDepthAndItemBounds(t *testing.T) {
	attrs := pcommon.NewMap()
	attrs.PutStr("db.system", "redis")
	attrs.PutStr("db.statement", "GET "+strings.Repeat("x", defaultConfig().MaxStringBytes))
	testProcessor().cleanMap(attrs)
	if value, _ := attrs.Get("db.statement"); value.Str() != "[REDACTED:redis]" {
		t.Fatal("oversized Redis statement did not fail closed")
	}
	p := testProcessor()
	p.config.MaxDepth = 1
	attrs = pcommon.NewMap()
	nested := attrs.PutEmptyMap("nested")
	nested.PutStr("db.system", "redis")
	nested.PutStr("db.statement", "GET ARBITRARY_PRIVATE_OPERAND")
	p.cleanMap(attrs)
	raw, _ := attrs.AsRaw()["nested"].(map[string]any)
	if raw["db.statement"] != "[REDACTED:limit]" {
		t.Fatal("Redis branch bypassed depth bound")
	}
}

func TestHTTPAndSQLUsefulFieldsSurviveSelectiveErrorSanitization(t *testing.T) {
	data := ptrace.NewTraces()
	spans := data.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	http := spans.AppendEmpty()
	http.SetName("GET /checkout")
	http.Attributes().PutStr("http.request.method", "GET")
	http.Attributes().PutInt("http.response.status_code", 500)
	e := http.Events().AppendEmpty()
	e.SetName("exception")
	e.Attributes().PutStr("exception.type", "java.io.IOException")
	e.Attributes().PutStr("exception.message", "downstream failed password=ERROR_PRIVATE")
	sql := spans.AppendEmpty()
	sql.SetName("SELECT orders")
	sql.Attributes().PutStr("db.system.name", "postgresql")
	sql.Attributes().PutStr("db.query.text", "SELECT id FROM orders WHERE email='alice@example.com' AND id=314159")
	sql.Attributes().PutEmptyMap("db.query.parameters").PutStr("id", "SQL_BIND_PRIVATE")
	testProcessor().processTraces(context.Background(), data)
	raw, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(data)
	noPrivate(t, string(raw), "ERROR_PRIVATE", "alice@example.com", "314159", "SQL_BIND_PRIVATE")
	if http.Name() != "GET /checkout" {
		t.Fatal("HTTP route lost")
	}
	if v, _ := http.Attributes().Get("http.response.status_code"); v.Int() != 500 {
		t.Fatal("HTTP status lost")
	}
	if v, _ := e.Attributes().Get("exception.message"); !strings.HasPrefix(v.Str(), "downstream failed") {
		t.Fatal("operational exception message lost")
	}
	if v, _ := sql.Attributes().Get("db.query.text"); !strings.Contains(v.Str(), "SELECT id FROM orders") {
		t.Fatal("SQL shape lost")
	}
}
