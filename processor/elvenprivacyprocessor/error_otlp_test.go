// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// These are actual pdata processor-handler and OTLP protobuf round trips. They
// qualify the processor boundary, not application auto-injection, a compiled
// Collector receiver/WAL/exporter, or a remote tenant backend.
func TestSelectiveExceptionsKeepOperationalMessagesAndFramesThroughOTLP(t *testing.T) {
	const email = "native.synthetic.customer@example.invalid"
	const credential = "SYNTHETIC_STATUS_SECRET"
	type runtimeCase struct{ exceptionType, message, stacktrace, frame string }
	cases := map[string]runtimeCase{
		"java": {
			"java.io.IOException", "pricing upstream failed for " + email,
			"java.io.IOException: pricing upstream failed for " + email + "\n\tat works.elven.checkout.Pricing.fetch(Pricing.java:42)\n\tat works.elven.checkout.Handler.handle(Handler.java:18)",
			"works.elven.checkout.Pricing.fetch(Pricing.java:42)",
		},
		"nodejs": {
			"Error", "pricing upstream failed for " + email,
			"Error: pricing upstream failed for " + email + "\n    at fetchPrice (/app/checkout.js:42:9)\n    at handleCheckout (/app/checkout.js:18:5)",
			"at fetchPrice (/app/checkout.js:42:9)",
		},
		"python": {
			"RuntimeError", "pricing upstream failed for " + email,
			"Traceback (most recent call last):\n  File \"/app/checkout.py\", line 42, in fetch_price\n    raise RuntimeError(\"pricing upstream failed for " + email + "\")\nRuntimeError: pricing upstream failed for " + email,
			"File \"/app/checkout.py\", line 42, in fetch_price",
		},
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			traceID, spanID := pcommon.TraceID{1, 2, 3}, pcommon.SpanID{4, 5, 6}
			traces := ptrace.NewTraces()
			resource := traces.ResourceSpans().AppendEmpty()
			resource.Resource().Attributes().PutStr("service.name", "elven-synthetic-checkout")
			span := resource.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
			span.SetTraceID(traceID)
			span.SetSpanID(spanID)
			span.SetName("GET /checkout")
			span.SetKind(ptrace.SpanKindServer)
			span.Attributes().PutStr("http.request.method", "GET")
			span.Attributes().PutInt("http.response.status_code", 502)
			span.Attributes().PutStr("status.description", fixture.message)
			span.Status().SetCode(ptrace.StatusCodeError)
			span.Status().SetMessage(fixture.message)
			event := span.Events().AppendEmpty()
			event.SetName("exception")
			event.Attributes().PutStr("exception.type", fixture.exceptionType)
			event.Attributes().PutStr("exception.message", fixture.message)
			event.Attributes().PutStr("exception.stacktrace", fixture.stacktrace)

			logs := plog.NewLogs()
			record := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
			record.SetTraceID(traceID)
			record.SetSpanID(spanID)
			record.SetSeverityNumber(plog.SeverityNumberError)
			record.SetSeverityText("ERROR")
			record.SetEventName("checkout.failed")
			record.Body().SetStr("checkout failed: pricing upstream unavailable for " + email + " retry=false")
			record.Attributes().PutInt("http.response.status_code", 502)
			record.Attributes().PutStr("exception.type", fixture.exceptionType)
			record.Attributes().PutStr("exception.message", fixture.message)
			record.Attributes().PutStr("exception.stacktrace", fixture.stacktrace)
			record.Attributes().PutStr("status.description", "pricing failed password="+credential)
			original, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
			if err != nil || !strings.Contains(string(original), email) {
				t.Fatal("fixture did not contain the actual private exception value before sanitization")
			}
			p := testProcessor()
			if _, err := p.processTraces(context.Background(), traces); err != nil {
				t.Fatal(err)
			}
			if _, err := p.processLogs(context.Background(), logs); err != nil {
				t.Fatal(err)
			}
			traceWire, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
			if err != nil {
				t.Fatal(err)
			}
			logWire, err := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
			if err != nil {
				t.Fatal(err)
			}
			noPrivate(t, string(traceWire), email, credential)
			noPrivate(t, string(logWire), email, credential)
			decodedTraces, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(traceWire)
			if err != nil {
				t.Fatal(err)
			}
			decodedLogs, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(logWire)
			if err != nil {
				t.Fatal(err)
			}
			actual := decodedTraces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
			actualLog := decodedLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			if actual.Name() != "GET /checkout" || actual.Status().Code() != ptrace.StatusCodeError || actual.Kind() != ptrace.SpanKindServer {
				t.Fatal("HTTP operation or error classification was changed")
			}
			if actual.TraceID() != traceID || actual.SpanID() != spanID || actualLog.TraceID() != traceID || actualLog.SpanID() != spanID {
				t.Fatal("error log and trace correlation was lost")
			}
			if actual.Status().Message() != "pricing upstream failed for "+mask {
				t.Fatal("span status lost its operational message or did not mask the sensitive substring")
			}
			for _, attrs := range []pcommon.Map{actual.Events().At(0).Attributes(), actualLog.Attributes()} {
				if value, _ := attrs.Get("exception.type"); value.Str() != fixture.exceptionType {
					t.Fatal("exception type was lost")
				}
				if value, _ := attrs.Get("exception.message"); value.Str() != "pricing upstream failed for "+mask {
					t.Fatal("exception message was replaced wholesale or retained the private substring")
				}
				if value, _ := attrs.Get("exception.stacktrace"); !strings.Contains(value.Str(), fixture.frame) || !strings.Contains(value.Str(), mask) {
					t.Fatal("useful frames were not preserved while masking the exception header")
				}
			}
			if value, _ := actual.Attributes().Get("status.description"); value.Str() != "pricing upstream failed for "+mask {
				t.Fatal("attribute form of status description was not selectively sanitized")
			}
			if value, _ := actualLog.Attributes().Get("http.response.status_code"); value.Int() != 502 {
				t.Fatal("HTTP status lost in correlated error log")
			}
			if actualLog.Body().Str() != "checkout failed: pricing upstream unavailable for "+mask+" retry=false" || actualLog.SeverityNumber() != plog.SeverityNumberError {
				t.Fatal("useful error log text or level was lost")
			}
		})
	}
}

func TestRedisErrorMessageAndStackCannotEchoUnknownKeysThroughOTLP(t *testing.T) {
	// Arbitrary Redis keys can be valid-looking code paths or frame names.
	// Retain the typed error and correlation, but do not infer safety from a
	// stack-frame regex and accidentally promote the operand as a useful frame.
	const key = "account:at/client.go:42"
	traces := ptrace.NewTraces()
	span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("GET " + key)
	span.SetTraceID(pcommon.TraceID{1, 2, 3})
	span.Attributes().PutStr("db.system.name", "redis")
	span.Attributes().PutStr("status.description", "missing "+key)
	span.Attributes().PutStr("exception.message", "missing "+key)
	span.Attributes().PutStr("exception.stacktrace", "RedisError: "+key)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("missing " + key)
	event := span.Events().AppendEmpty()
	event.SetName("exception")
	event.Attributes().PutStr("exception.type", "RedisError")
	event.Attributes().PutStr("exception.message", "missing "+key)
	event.Attributes().PutStr("exception.stacktrace", "RedisError: "+key+"\n at "+key)
	logs := plog.NewLogs()
	record := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	record.Attributes().PutStr("db.system", "redis")
	record.Attributes().PutStr("exception.type", "RedisError")
	record.Attributes().PutStr("exception.message", "missing "+key)
	record.Attributes().PutStr("exception.stacktrace", "at "+key)
	record.Attributes().PutStr("status.description", "missing "+key)
	record.Body().SetStr(`{"db.system":"redis","exception.type":"RedisError","exception.message":"missing ` + key + `","exception.stacktrace":"at ` + key + `","status.description":"missing ` + key + `"}`)
	p := testProcessor()
	if _, err := p.processTraces(context.Background(), traces); err != nil {
		t.Fatal(err)
	}
	if _, err := p.processLogs(context.Background(), logs); err != nil {
		t.Fatal(err)
	}
	logWire, err := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	if err != nil {
		t.Fatal(err)
	}
	noPrivate(t, string(logWire), key)
	if value, _ := record.Attributes().Get("exception.type"); value.Str() != "RedisError" {
		t.Fatal("Redis log exception type lost")
	}
	wire, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
	if err != nil {
		t.Fatal(err)
	}
	noPrivate(t, string(wire), key)
	decoded, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(wire)
	if err != nil {
		t.Fatal(err)
	}
	actual := decoded.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if actual.Name() != "GET" || actual.Status().Code() != ptrace.StatusCodeError || actual.TraceID() != span.TraceID() {
		t.Fatal("safe Redis operation/error/correlation lost")
	}
	if actual.Status().Message() != mask {
		t.Fatal("unsafe Redis status retained")
	}
	for _, key := range []string{"exception.message", "exception.stacktrace", "status.description"} {
		if value, _ := actual.Attributes().Get(key); value.Str() != mask {
			t.Fatal("Redis operand may remain in diagnostic span attributes")
		}
	}
	for _, key := range []string{"exception.message", "exception.stacktrace"} {
		if value, _ := actual.Events().At(0).Attributes().Get(key); value.Str() != mask {
			t.Fatal("Redis operand may remain in exception")
		}
	}
	if value, _ := actual.Events().At(0).Attributes().Get("exception.type"); value.Str() != "RedisError" {
		t.Fatal("Redis exception type lost")
	}
}
