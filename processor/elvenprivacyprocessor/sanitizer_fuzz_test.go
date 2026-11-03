// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzSensitiveJSONValuesNeverExported(f *testing.F) {
	for _, seed := range []string{"plain", "space secret", "quoted\"value", `backslash\"tail`, "\u0040", "12345678909", "SELECT value FROM table WHERE value='literal'"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 65536 {
			t.Skip()
		}
		private := "ELVEN_PRIVATE_VALUE_" + input
		source, err := json.Marshal(map[string]any{
			"message":       "request completed in 42ms",
			"nested":        []any{map[string]any{"accessToken": private, "db.query.parameters": []any{private}}},
			"Authorization": map[string]any{"value": private},
		})
		if err != nil {
			t.Fatal(err)
		}
		p := testProcessor()
		result := p.cleanText(string(source))
		if strings.Contains(result, "ELVEN_PRIVATE_VALUE_") {
			t.Fatalf("private JSON value survived: %s", result)
		}
		if result != p.cleanText(result) {
			t.Fatalf("sanitization not idempotent: %s", result)
		}
		if !strings.Contains(result, "request completed in 42ms") {
			t.Fatalf("useful context lost: %s", result)
		}
	})
}
