// SPDX-License-Identifier: Apache-2.0
package elvenprivacyprocessor

import (
	"strings"
	"testing"
)

func TestTextPreservesOperationalContext(t *testing.T) {
	for _, input := range []string{
		"INFO completed request with status=200 duration_ms=42 retries=2",
		"HTTP POST /orders completed in 42ms trace_id=1234567890123456",
		"queue_size=20971520 capacity=4096 receiver=otlp",
		"record id=abc12345678901def processed",
		"retained [REDACTED] status=ok",
		"Bearer [REDACTED]",
		"password=[REDACTED] status=ok",
		"HTTP DELETE /orders completed status=200",
		"update cache complete status=200",
		"progress=100% complete",
	} {
		if result := redactText(input); result != input {
			t.Errorf("operational text changed: %q -> %q", input, result)
		}
	}
}

func TestTextKnownPIIAndSecretsAreSelective(t *testing.T) {
	cases := []struct{ input, private, context string }{
		{`operation=checkout email=alice@example.com status=failed`, "alice@example.com", "status=failed"},
		{`user alice@example.com completed operation in 42ms`, "alice@example.com", "42ms"},
		{`INFO password="correct horse battery staple" status=ok`, "correct horse battery staple", "status=ok"},
		{`INFO accessToken='private token with spaces' status=ok`, "private token with spaces", "status=ok"},
		{`api-key=opaque-private-value status=ok`, "opaque-private-value", "status=ok"},
		// Raw header parameters are ambiguous: keep context before the header.
		{`status=ok Authorization: Bearer opaque-private-value`, "opaque-private-value", "status=ok"},
		{`request Bearer opaque-private-value status=ok`, "opaque-private-value", "status=ok"},
		{`request Basic dXNlcjpwYXNzd29yZA== status=ok`, "dXNlcjpwYXNzd29yZA==", "status=ok"},
		{`request eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.signature completed`, "eyJhbGciOiJIUzI1NiJ9", "completed"},
		{`cpf 529.982.247-25 processed`, "529.982.247-25", "processed"},
		{`cpf 52998224725 processed`, "52998224725", "processed"},
		{`cnpj 11.222.333/0001-81 processed`, "11.222.333/0001-81", "processed"},
		{`card 4111 1111 1111 1111 processed`, "4111 1111 1111 1111", "processed"},
		{`phone=+55 (11) 99999-9999 status=ok`, "+55 (11) 99999-9999", "status=ok"},
		{`cpf ５２９９８２２４７２５ processed`, "52998224725", "processed"},
		{`cpf ٥٢٩٩٨٢٢٤٧٢٥ processed`, "52998224725", "processed"},
		{`INFO %70assword=secret-sentinel CPU=95%`, "secret-sentinel", "CPU=95%"},
		{`INFO pass\u0077ord=secret-sentinel status=ok`, "secret-sentinel", "status=ok"},
		{`[REDACTED] password=secret-sentinel status=ok`, "secret-sentinel", "status=ok"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			result := redactText(tc.input)
			if strings.Contains(result, tc.private) {
				t.Fatalf("private segment survived: %q", result)
			}
			if !strings.Contains(result, "[REDACTED") {
				t.Fatalf("no redaction marker: %q", result)
			}
			if !strings.Contains(result, tc.context) {
				t.Fatalf("lost operational context %q: %q", tc.context, result)
			}
		})
	}
}

func TestURLCredentialsQueriesAndFragments(t *testing.T) {
	for _, input := range []string{
		`request https://alice:password-secret@service.example/orders?customer=Alice&token=token-secret#fragment-secret completed`,
		`request postgres://alice:hello%20private@db.example/app?sslmode=require completed`,
		`request /orders?customer=Alice&email=alice%40example.com completed`,
	} {
		result := redactText(input)
		for _, private := range []string{"alice", "Alice", "password-secret", "token-secret", "fragment-secret", "hello", "private", "require"} {
			if strings.Contains(result, private) {
				t.Errorf("URL leaked %q: %q", private, result)
			}
		}
		if !strings.Contains(result, "request ") || !strings.Contains(result, "completed") {
			t.Errorf("lost context: %q", result)
		}
	}
}

func TestSensitiveKeyNormalization(t *testing.T) {
	for _, key := range []string{
		"accessToken", "api-key", "Authorization", "db.query.parameters", "bind_params", "email", "user.email", "user.name", "client.address", "sessionId", "password", "%70assword", `pass\u0077ord`, "pass\u200bword", "http.request.headers.X-Custom", "http.response.body", "cpf", "card_number", "request.payload", "enduser.id",
	} {
		if !isSensitiveKey(key) {
			t.Errorf("sensitive key not detected: %q (%q)", key, normalizedKey(key))
		}
	}
	for _, key := range []string{"service.name", "k8s.pod.name", "http.request.method", "http.response.status_code", "db.query.text", "db.statement", "duration_ms", "trace_id", "span_id", "phase"} {
		if isSensitiveKey(key) {
			t.Errorf("operational key treated as secret: %q", key)
		}
	}
	for _, key := range []string{"db.statement", "db.query.text", "sql", "statement", "query", "%64b.statement"} {
		if !isSQLKey(key) {
			t.Errorf("SQL key not detected: %q", key)
		}
	}
}

func TestBoundedDecoding(t *testing.T) {
	for _, input := range []string{`alice%40example.com`, `alice%2540example.com`, `alice\u0040example.com`, `alice\\u0040example.com`, `pass%77ord=secret`, `pass\u0077ord=secret`} {
		result := redactText(input)
		if strings.Contains(result, "alice") || strings.Contains(result, "secret") {
			t.Errorf("encoded PII survived: %q -> %q", input, result)
		}
	}
	if _, ok := decodeTextLayers(`alice%2525252540example.com`); ok {
		t.Error("more than 3 layers accepted")
	}
	if _, ok := decodeTextLayers("invalid\xff"); ok {
		t.Error("invalid UTF-8 accepted")
	}
	jsonBody := `{"message":"quote \" test", "email":"alice\\u0040example.com"}`
	if decoded, ok := decodeTextLayers(jsonBody); !ok || decoded != jsonBody {
		t.Errorf("valid JSON damaged before parser: %q %t", decoded, ok)
	}
}

func TestTextEmbeddedSQL(t *testing.T) {
	result := redactText(`INFO sql=SELECT name FROM people WHERE email='alice@example.com' AND id=42`)
	if strings.Contains(result, "alice") || strings.Contains(result, "42") || !strings.Contains(result, "SELECT") || !strings.Contains(result, "INFO sql=") {
		t.Fatalf("unsafe/lossy SQL: %q", result)
	}
	if result := redactText(`INFO query=SELECT name FROM people WHERE password='unterminated`); !strings.Contains(result, "[REDACTED:sql]") || strings.Contains(result, "unterminated") {
		t.Fatalf("malformed SQL leaked: %q", result)
	}
}

func TestUnterminatedQuotedSecretsFailClosed(t *testing.T) {
	for _, input := range []string{`INFO password="secret with private suffix`, `INFO password='secret with private suffix`} {
		result := redactText(input)
		if strings.Contains(result, "secret") || strings.Contains(result, "private") || !strings.HasPrefix(result, "INFO password=") {
			t.Errorf("malformed secret leaked: %q", result)
		}
	}
}

func TestEscapedQuotesNeverExposeCredentialSuffix(t *testing.T) {
	for _, input := range []string{`password="abc\"DEFSECRET" status=200`, `password="abc\\\"DEFSECRET" status=200`, `%70assword="abc%22DEFSECRET" status=200`, `pass\u0077ord="abc\u0022DEFSECRET" status=200`} {
		result := redactText(input)
		if strings.Contains(result, "DEFSECRET") || !strings.Contains(result, "status=200") {
			t.Errorf("escapedquote credential leaked/lostcontext: %q -> %q", input, result)
		}
	}
}

func TestAdjacentPersonalNumbersCannotHideInAggregate(t *testing.T) {
	for _, separator := range []string{" ", ",", "/"} {
		for _, number := range []string{"52998224725", "529.982.247-25", "11222333000181", "11.222.333/0001-81", "4111111111111111", "4111 1111 1111 1111"} {
			input := "processed " + number + separator + number + " status=ok"
			result := redactText(input)
			if strings.Contains(result, number) || !strings.Contains(result, "status=ok") {
				t.Errorf("adjacentPII leaked/lostcontext %q -> %q", input, result)
			}
		}
	}
	for _, input := range []string{"cpf 52998224725 42", "card 4111 1111 1111 1111 123", "card 4111 1111 1111 1111 duration_ms=42", "trace_id=1234567890123456 529.982.247-25"} {
		result := redactText(input)
		if strings.Contains(result, "52998224725") || strings.Contains(result, "529.982.247-25") || strings.Contains(result, "4111 1111 1111 1111") {
			t.Errorf("neighborPII leaked: %q", result)
		}
		if strings.Contains(input, "trace_id") && !strings.Contains(result, "trace_id=1234567890123456") {
			t.Errorf("lostcorrelation: %q", result)
		}
		if strings.HasSuffix(input, " 42") && !strings.HasSuffix(result, " 42") {
			t.Errorf("lostordinarycount: %q", result)
		}
		if strings.Contains(input, "duration_ms") && !strings.Contains(result, "duration_ms=42") {
			t.Errorf("lostduration: %q", result)
		}
	}
}

func TestEmbeddedSQLBudgetFailsClosed(t *testing.T) {
	input := strings.Repeat("update cache complete ", 257) + "SELECT fullname='SQL_PRIVATE'"
	result := redactText(input)
	if strings.Contains(result, "SQL_PRIVATE") || !strings.Contains(result, "[REDACTED:sql]") {
		t.Fatalf("budgetexhaustion leakedSQL: %q", result)
	}
}

func TestRelativeQueryDecodedValuesCannotBecomeOrphans(t *testing.T) {
	for _, input := range []string{
		`request /orders?customer=Synthetic%20Name completed`,
		`request /orders?customer=Synthetic%22Name completed`,
		`request /orders?name=Synthetic%2520Name&email=alice%40example.com completed`,
		`request /orders?%65mail=alice%40example.com completed`,
	} {
		result := redactText(input)
		for _, private := range []string{"Synthetic", "Name", "alice", "example.com"} {
			if strings.Contains(result, private) {
				t.Errorf("query orphan leaked %q: %q -> %q", private, input, result)
			}
		}
		if !strings.HasPrefix(result, "request ") || !strings.HasSuffix(result, " completed") {
			t.Errorf("lost request context: %q", result)
		}
		if twice := redactText(result); twice != result {
			t.Errorf("non-idempotent query: %q -> %q", result, twice)
		}
	}
}

func TestPortugueseSensitiveFieldsKeepUsefulText(t *testing.T) {
	for _, key := range []string{"senha", "segredo", "chave_api", "chavePrivada", "nome_completo", "nome_do_usuario", "usuário", "documento", "numeroDocumento", "data_de_nascimento", "dataNascimento", "endereco", "endereço", "cep", "numeroCartao", "cartão_de_crédito", "url.query", "http.query", "process.command_args", "process.command_line", "process.environment.API_KEY", "process.owner"} {
		if !isSensitiveKey(key) {
			t.Errorf("known sensitive alias missed: %q", key)
		}
	}
	for _, input := range []string{
		`Operação aprovada senha="segredo com espaços" duração=42ms`,
		`Operação aprovada senha=SEGREDO duração=42ms`,
		"Operação aprovada senha\u00a0=\u00a0SEGREDO duração=42ms",
		`Operação aprovada chave_api="CHAVE PRIVADA" duração=42ms`,
	} {
		result := redactText(input)
		for _, private := range []string{"segredo com espaços", "SEGREDO", "CHAVE PRIVADA"} {
			if strings.Contains(result, private) {
				t.Errorf("Portuguese secret leaked %q: %q", private, result)
			}
		}
		if !strings.HasPrefix(result, "Operação aprovada ") || !strings.HasSuffix(result, " duração=42ms") {
			t.Errorf("lost useful Portuguese text: %q", result)
		}
		if twice := redactText(result); twice != result {
			t.Errorf("non-idempotent Portuguese masking %q -> %q", result, twice)
		}
	}
	for _, key := range []string{"nome", "service.name", "operation.name", "duration", "duração"} {
		if isSensitiveKey(key) {
			t.Errorf("overbroad alias: %q", key)
		}
	}
}

func BenchmarkTextRedactionBounded(b *testing.B) {
	value := strings.Repeat("operation=checkout status=ok duration_ms=42 ", 4096) + " email=alice@example.com"
	b.SetBytes(int64(len(value)))
	for b.Loop() {
		_ = redactText(value)
	}
}
