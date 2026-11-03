// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"strings"
	"testing"
)

func TestSensitiveLogfmtValuesCannotLeakSuffixes(t *testing.T) {
	for _, input := range []string{
		`operation ok password=abc,PRIVATE_SUFFIX duration=42ms`,
		`operation ok password=abc;PRIVATE_SUFFIX duration=42ms`,
		`operation ok password=abc&PRIVATE_SUFFIX duration=42ms`,
		`operation ok password="abc,PRIVATE_SUFFIX" duration=42ms`,
		`operation ok password='abc;PRIVATE_SUFFIX' duration=42ms`,
		`operation ok password="one"PRIVATE_SUFFIX duration=42ms`,
		`operation ok password="one",PRIVATE_SUFFIX duration=42ms`,
		`operation ok payload={"safe":"one","other":"PRIVATE_SUFFIX"} duration=42ms`,
		`operation ok payload=[{"safe":"one"},{"other":"PRIVATE_SUFFIX"}] duration=42ms`,
		`operation ok payload={"safe":["one",{"other":"PRIVATE_SUFFIX","quoted":"]}"}]} duration=42ms`,
		`operation ok payload="{\"safe\":\"one\",\"other\":\"PRIVATE_SUFFIX\"}" duration=42ms`,
		`operation ok payload={"nested":{"password":"abc\\\"PRIVATE_SUFFIX"}} duration=42ms`,
		`operation ok Authorization="Bearer PRIVATE_SUFFIX" duration=42ms`,
		`operation ok container={"Cookie":"sid=one; other=PRIVATE_SUFFIX","status":200} duration=42ms`,
	} {
		result := redactText(input)
		if strings.Contains(result, "PRIVATE_SUFFIX") {
			t.Fatalf("sensitive suffix survived: %q -> %q", input, result)
		}
		if !strings.HasPrefix(result, "operation ok ") || !strings.HasSuffix(result, " duration=42ms") {
			t.Fatalf("clear log context lost: %q -> %q", input, result)
		}
		if twice := redactText(result); twice != result {
			t.Fatalf("not idempotent: %q -> %q", result, twice)
		}
	}
}

func TestMalformedSensitiveCompoundFailsClosed(t *testing.T) {
	for _, input := range []string{
		`operation ok payload={"safe":"one","other":"PRIVATE_SUFFIX" duration=42ms`,
		`operation ok payload=[{"other":"PRIVATE_SUFFIX"} duration=42ms`,
		`operation ok payload={"safe":[{"other":"PRIVATE_SUFFIX"}]}]ORPHAN_PRIVATE_SUFFIX duration=42ms`,
		`operation ok password="unclosed PRIVATE_SUFFIX duration=42ms`,
		"operation ok payload=" + strings.Repeat("[", 25) + `"PRIVATE_SUFFIX"` + strings.Repeat("]", 25) + " duration=42ms",
	} {
		result := redactText(input)
		if strings.Contains(result, "PRIVATE_SUFFIX") {
			t.Fatalf("malformed sensitive field leaked: %q -> %q", input, result)
		}
		if !strings.HasPrefix(result, "operation ok ") || !strings.Contains(result, "[REDACTED") {
			t.Fatalf("missing safe operational prefix: %q", result)
		}
	}
}

func TestRawSensitiveHeadersRemainOpaque(t *testing.T) {
	for _, input := range []string{
		`operation ok Cookie: sid=one; other=PRIVATE_SUFFIX duration=42ms`,
		`operation ok cookie=sid=one; other=PRIVATE_SUFFIX duration=42ms`,
		`operation ok Authorization: Digest username=one, realm=PRIVATE_SUFFIX duration=42ms`,
		`operation ok authorization=Digest username=one, realm=PRIVATE_SUFFIX duration=42ms`,
	} {
		result := redactText(input)
		if strings.Contains(result, "PRIVATE_SUFFIX") {
			t.Fatalf("opaque header leaked: %q -> %q", input, result)
		}
		if !strings.HasPrefix(result, "operation ok ") {
			t.Fatalf("prefix lost: %q", result)
		}
		if twice := redactText(result); twice != result {
			t.Fatalf("header masking not idempotent: %q -> %q", result, twice)
		}
	}
}

func TestLargeAmbiguousSecretHasNoRawFallback(t *testing.T) {
	input := "operation ok password=" + strings.Repeat("PRIVATE_SUFFIX ", 4096)
	result := redactText(input)
	if strings.Contains(result, "PRIVATE_SUFFIX") || !strings.HasPrefix(result, "operation ok password=") {
		t.Fatalf("ambiguous large field leaked/lost prefix: %q", result)
	}
	if twice := redactText(result); twice != result {
		t.Fatalf("large-field masking not idempotent: %q -> %q", result, twice)
	}
}
