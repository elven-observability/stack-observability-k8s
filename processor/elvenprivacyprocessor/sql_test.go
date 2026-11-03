// Copyright Elven Observability.
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"strings"
	"testing"
)

func TestSanitizeSQLSupportedShapes(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		keep   []string
		remove []string
	}{
		{"query shape", "SELECT name, count(*) FROM users WHERE email='alice@example.com' AND age >= 37", []string{"SELECT", "name", "count", "FROM users", "WHERE email", "age"}, []string{"alice", "example.com", "37"}},
		{"postgres escaped literals", `SELECT E'private\'suffix', 'private''double', U&'private\0040example', N'private_unicode'`, []string{"SELECT", "?"}, []string{"private", "suffix", "example", "0040"}},
		{"postgres dollar literals", `SELECT $$private_body$$, $body$private_tagged$body$, $1::text`, []string{"SELECT", ":: text"}, []string{"private", "body", "$1"}},
		{"bound parameters", `SELECT * FROM users WHERE id=:private_bind AND account=$private_bind AND secret=@private_bind AND id2=?`, []string{"WHERE id", "account", "AND secret"}, []string{"private_bind", ":private", "@private", "$private"}},
		{"quoted identifiers", "SELECT \"alice@example.com\", `private_name`, [private]]column] FROM [private_table]", []string{"SELECT", "FROM"}, []string{"alice", "example.com", "private"}},
		{"nested comments", "SELECT /* outer private /* nested private */ private */ 13 FROM users -- private\nWHERE enabled = true # private\n", []string{"SELECT", "FROM users", "WHERE enabled"}, []string{"private", "13", "true"}},
		{"numbers and encodings", `SELECT 0x12ABEF, 0b101101, 735.91, .67, 91e-3, -8221, TRUE, false, NULL`, []string{"SELECT"}, []string{"12ABEF", "101101", "735", "67", "91e", "8221", "TRUE", "false", "NULL"}},
		{"insert", `INSERT INTO accounts(email,password) VALUES ('alice@example.com','private_password')`, []string{"INSERT INTO accounts", "email", "password", "VALUES"}, []string{"alice@example.com", "private_password"}},
		{"insert select", `INSERT INTO archive SELECT * FROM events WHERE id=9876`, []string{"INSERT INTO archive", "SELECT", "events"}, []string{"9876"}},
		{"update", `UPDATE accounts SET password='private_password' WHERE id=9988`, []string{"UPDATE accounts SET password", "WHERE id"}, []string{"private_password", "9988"}},
		{"delete", `DELETE FROM users WHERE email='alice@example.com'`, []string{"DELETE FROM users", "WHERE email"}, []string{"alice@example.com"}},
		{"cte", `WITH recent AS (SELECT * FROM events WHERE stamp > 'private_date') SELECT * FROM recent WHERE id=$1`, []string{"WITH recent AS", "SELECT", "FROM recent"}, []string{"private_date", "$1"}},
		{"explain", `EXPLAIN (ANALYZE true, BUFFERS) SELECT * FROM orders WHERE total > 937.12`, []string{"EXPLAIN", "ANALYZE", "SELECT", "FROM orders"}, []string{"937", "12", "true"}},
		{"merge", `MERGE INTO customers USING incoming ON customers.id=incoming.id WHEN MATCHED THEN UPDATE SET email='alice@example.com'`, []string{"MERGE INTO customers", "USING incoming", "ON customers"}, []string{"alice@example.com"}},
		{"create table", `CREATE TABLE records (id integer, email text DEFAULT 'alice@example.com')`, []string{"CREATE TABLE records", "DEFAULT"}, []string{"alice@example.com"}},
		{"create temporary", `CREATE TEMPORARY TABLE records AS SELECT 'private_value'`, []string{"CREATE TEMPORARY TABLE records", "SELECT"}, []string{"private_value"}},
		{"alter table", `ALTER TABLE records ADD COLUMN email text DEFAULT 'alice@example.com'`, []string{"ALTER TABLE records", "ADD COLUMN email"}, []string{"alice@example.com"}},
		{"drop table", `DROP TABLE IF EXISTS records`, []string{"DROP TABLE IF EXISTS records"}, nil},
		{"truncate", `TRUNCATE TABLE records`, []string{"TRUNCATE TABLE records"}, nil},
		{"multiple supported statements", `SELECT 'private_one'; DELETE FROM records WHERE id=6389;`, []string{"SELECT", "; DELETE FROM records"}, []string{"private_one", "6389"}},
		{"identifier numbers retained", `SELECT field123, v2 FROM table42 WHERE elapsed_ms=3281`, []string{"field123", "v2", "table42", "elapsed_ms"}, []string{"3281"}},
		{"unicode private data in literal", "SELECT 'usuário privado 例' FROM users", []string{"SELECT", "FROM users"}, []string{"usuário", "privado", "例"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeSQL(tt.input)
			if !ok {
				t.Fatal("expected supported SQL shape")
			}
			for _, want := range tt.keep {
				if !strings.Contains(got, want) {
					t.Errorf("shape lost %q: %q", want, got)
				}
			}
			for _, secret := range tt.remove {
				if strings.Contains(got, secret) {
					t.Errorf("private literal %q survived: %q", secret, got)
				}
			}
			again, stable := sanitizeSQL(got)
			if !stable || again != got {
				t.Errorf("query shape is not idempotent: original=%q again=%q ok=%v", got, again, stable)
			}
		})
	}
}

func TestSanitizeSQLRejectsWithoutPartialOutput(t *testing.T) {
	inputs := []string{
		"", "   ", "SELECT", "SELECT FROM users", "SELECT 'private_unterminated",
		`SELECT 'private_backslash\`, "SELECT /* private_unterminated", "SELECT $$private_unterminated",
		"SELECT $tag$private_unterminated", "SELECT (1", "SELECT 1)", "SELECT [private_unterminated",
		"SELECT `private_unterminated", "SELECT \"private_unterminated", "SELECT 1e+", "SELECT 0x",
		"SELECT 0b102", "SELECT 12private", "SELECT .8private", "SELECT 1.2.3", "SELECT $",
		"SELECT @", "SELECT :", "SELECT alice@example.com", "SELECT secret$variable",
		"SELECT 'private'; EXEC private_password", "SELECT 1;;", "SELECT 1\x00private",
		"SELECT '\xff'", "SELECT usuário FROM users", "password=private_password",
		`{"password":"private_password"}`, "db.users.find({password:'private_password'})",
		"GET private_secret", "CREATE USER private_user IDENTIFIED BY 'private_password'",
		"ALTER ROLE private_user PASSWORD 'private_password'", "CREATE FUNCTION private_fun() RETURNS TEXT AS $$private$$",
		"CREATE TABLE private_table PASSWORD private_password", "ALTER TABLE records SET TOKEN private_token",
		`SELECT 'private\'quoted'`, "SELECT \"private\\\"quoted\"",
		"WITH private_only AS (SELECT 1)", "EXPLAIN private_arbitrary", "INSERT private_arbitrary", "UPDATE private_arbitrary", "DELETE private_arbitrary",
		"SELECT " + strings.Repeat("(", 65) + "'private'" + strings.Repeat(")", 65),
		"SELECT " + strings.Repeat("/*", 65) + "private" + strings.Repeat("*/", 65) + "1",
		"SELECT '" + strings.Repeat("private", 150000) + "'",
		"SELECT " + strings.Repeat("?,", 40000) + "?",
	}
	for i, input := range inputs {
		got, ok := sanitizeSQL(input)
		if ok || got != "" {
			t.Errorf("case %d accepted unsupported/malformed input or returned partial data: ok=%v output=%q", i, ok, got)
		}
	}
}

func BenchmarkSanitizeSQLLargeLiterals(b *testing.B) {
	input := "SELECT '" + strings.Repeat("private\n", 20000) + "' FROM users WHERE id=883782"
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := sanitizeSQL(input); !ok {
			b.Fatal("supported large literal rejected")
		}
	}
}

func BenchmarkSanitizeSQLAdversarialComments(b *testing.B) {
	input := "SELECT /*" + strings.Repeat("private /* ignored */ ", 10000) + "*/ 1"
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := sanitizeSQL(input); !ok {
			b.Fatal("supported comment rejected")
		}
	}
}

func FuzzSanitizeSQLLiteralNeverLeaks(f *testing.F) {
	for _, seed := range []string{"alice@example.com", "plain", "a'b", `a\'b`, "\u202eprivate", "/* private */", "$$private$$", "\x00private", "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		// A valid ANSI literal may contain any escaped single quote. If a
		// mode-ambiguous backslash/control/size budget is hit, fail closed is
		// acceptable; successful output must never contain the literal marker.
		query := "SELECT 'private_sentinel_" + strings.ReplaceAll(value, "'", "''") + "' FROM records"
		got, ok := sanitizeSQL(query)
		if !ok {
			if got != "" {
				t.Fatal("rejected query returned partial output")
			}
			return
		}
		if strings.Contains(got, "private_sentinel_") {
			t.Fatalf("literal survived: %q", got)
		}
		again, stable := sanitizeSQL(got)
		if !stable || got != again {
			t.Fatalf("shape not idempotent: %q -> %q", got, again)
		}
	})
}
