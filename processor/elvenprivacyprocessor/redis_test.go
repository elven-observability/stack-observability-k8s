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
	for _, key := range []string{"redis.key", "db.redis.key", "redis.keys", "redis.args", "db.redis.command.args", "redis.raw_command", "%72edis.key", "redis.arguments", "redis.values"} {
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
	input := `{"db.redis.command":"SET KEY_PRIVATE VALUE_PRIVATE","message":"cache update completed"}`
	output := testProcessor().cleanText(input)
	noPrivate(t, output, "KEY_PRIVATE", "VALUE_PRIVATE")
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
