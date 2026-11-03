// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

const mask = "[REDACTED]"

type sanitizer struct {
	config    Config
	remaining int
}

func isMarker(v string) bool {
	switch v {
	case mask, "[REDACTED:limit]", "[REDACTED:json]", "[REDACTED:sql]", "[REDACTED:bytes]", "[REDACTED:encoding]":
		return true
	default:
		return false
	}
}

// text canonicalizes bounded encoded/structured strings before redaction. JSON
// remains JSON, rather than regex-replacing fragments of its escaped grammar.
func (s *sanitizer) text(input string, depth int) string {
	if isMarker(input) {
		return input
	}
	if depth > s.config.MaxDepth || len(input) > s.config.MaxStringBytes {
		return "[REDACTED:limit]"
	}
	if !utf8.ValidString(input) {
		return "[REDACTED:encoding]"
	}
	// Parse JSON grammar before decoding textual escapes. Unescaping a quote
	// inside a valid JSON string first could destroy its structure or orphan
	// part of a credential. Nested JSON strings recurse through native().
	decoded := input
	if !looksLikeJSON(input) {
		var ok bool
		decoded, ok = decodeTextLayers(input)
		if !ok || !utf8.ValidString(decoded) {
			return "[REDACTED:encoding]"
		}
	}
	if len(decoded) > s.config.MaxStringBytes {
		return "[REDACTED:limit]"
	}
	if isMarker(decoded) {
		return decoded
	}
	if looksLikeJSON(decoded) {
		if !s.jsonDepthAllowed(decoded, depth) {
			return "[REDACTED:limit]"
		}
		decoder := json.NewDecoder(strings.NewReader(decoded))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return "[REDACTED:json]"
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return "[REDACTED:json]"
		}
		result := s.native(value, depth+1, "")
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > s.config.MaxStringBytes {
			return "[REDACTED:limit]"
		}
		return string(encoded)
	}
	return redactText(decoded)
}

func looksLikeJSON(input string) bool {
	v := strings.TrimSpace(input)
	if v == "" || isMarker(v) {
		return false
	}
	if v[0] == '{' {
		return true
	}
	if v[0] == '"' {
		return strings.HasSuffix(v, "\"") || strings.HasPrefix(v, "\"{\\\"")
	}
	if v[0] != '[' {
		return false
	}
	rest := strings.TrimSpace(v[1:])
	if rest == "" {
		return true
	}
	if strings.ContainsRune("[{\"-]", rune(rest[0])) {
		return true
	}
	if rest[0] >= '0' && rest[0] <= '9' {
		// A conventional [YYYY-MM-DD ...] log prefix is not a JSON array.
		if len(rest) > 7 && rest[4] == '-' && rest[7] == '-' {
			return false
		}
		return true
	}
	return strings.HasPrefix(rest, "true") || strings.HasPrefix(rest, "false") || strings.HasPrefix(rest, "null")
}

func (s *sanitizer) jsonDepthAllowed(input string, initial int) bool {
	depth, quoted, escaped := initial, false, false
	for _, r := range input {
		if quoted {
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == '"' {
				quoted = false
			}
			continue
		}
		switch r {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > s.config.MaxDepth {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true // json.Decoder is the authoritative syntax validator.
}

func (s *sanitizer) sql(input string) string {
	if isMarker(input) {
		return input
	}
	if len(input) > s.config.MaxStringBytes || !utf8.ValidString(input) {
		return "[REDACTED:limit]"
	}
	decoded, ok := decodeTextLayers(input)
	if !ok {
		return "[REDACTED:encoding]"
	}
	result, ok := sanitizeSQL(decoded)
	if !ok {
		return "[REDACTED:sql]"
	}
	return redactText(result)
}

func (s *sanitizer) key(input string, index int) string {
	if len(input) > s.config.MaxStringBytes || !utf8.ValidString(input) || redactText(input) != input {
		return fmt.Sprintf("elven.redacted_key_%d", index)
	}
	return input
}

func (s *sanitizer) attributes(input pcommon.Map) {
	output := pcommon.NewMap()
	if input.Len() > s.config.MaxCollectionItems {
		output.PutStr("elven.redaction", "[REDACTED:limit]")
	} else {
		s.mapInto(input, output, 0)
	}
	output.CopyTo(input)
}

func (s *sanitizer) mapInto(input, output pcommon.Map, depth int) {
	index := 0
	input.Range(func(key string, value pcommon.Value) bool {
		cleanKey := s.key(key, index)
		redactedKey := cleanKey != key
		index++
		if _, duplicate := output.Get(cleanKey); duplicate {
			// PII-containing field names can canonicalize to the same key. Never
			// retain either raw key or overwrite an earlier operational field.
			cleanKey = fmt.Sprintf("elven.redacted_key_%d", index)
			for {
				if _, exists := output.Get(cleanKey); !exists {
					break
				}
				index++
				cleanKey = fmt.Sprintf("elven.redacted_key_%d", index)
			}
		}
		if redactedKey {
			// A field keyed by an email, token or opaque encoded identity is
			// itself a sensitive section, including its associated value.
			output.PutStr(cleanKey, mask)
		} else {
			s.value(value, output.PutEmpty(cleanKey), depth+1, key)
		}
		return true
	})
}

func (s *sanitizer) valueInPlace(input pcommon.Value, depth int, key string) {
	output := pcommon.NewValueEmpty()
	s.value(input, output, depth, key)
	output.CopyTo(input)
}

func (s *sanitizer) value(input, output pcommon.Value, depth int, key string) {
	if isSensitiveKey(key) {
		output.SetStr(mask)
		return
	}
	if depth > s.config.MaxDepth || s.remaining <= 0 {
		output.SetStr("[REDACTED:limit]")
		return
	}
	s.remaining--
	if isSQLKey(key) {
		if input.Type() != pcommon.ValueTypeStr {
			output.SetStr("[REDACTED:sql]")
		} else {
			output.SetStr(s.sql(input.Str()))
		}
		return
	}
	switch input.Type() {
	case pcommon.ValueTypeEmpty:
	case pcommon.ValueTypeStr:
		output.SetStr(s.text(input.Str(), depth))
	case pcommon.ValueTypeInt:
		raw := strconv.FormatInt(input.Int(), 10)
		if cleaned := redactText(raw); cleaned != raw {
			output.SetStr(cleaned)
		} else {
			output.SetInt(input.Int())
		}
	case pcommon.ValueTypeDouble:
		// Inspect the complete decimal representation, not scientific notation:
		// an exactly representable CPF stored as Double must not evade matching.
		raw := strconv.FormatFloat(input.Double(), 'f', -1, 64)
		if cleaned := redactText(raw); cleaned != raw {
			output.SetStr(cleaned)
		} else {
			output.SetDouble(input.Double())
		}
	case pcommon.ValueTypeBool:
		output.SetBool(input.Bool())
	case pcommon.ValueTypeBytes:
		output.SetStr("[REDACTED:bytes]")
	case pcommon.ValueTypeMap:
		if input.Map().Len() > s.config.MaxCollectionItems || input.Map().Len() > s.remaining {
			output.SetStr("[REDACTED:limit]")
			return
		}
		s.mapInto(input.Map(), output.SetEmptyMap(), depth)
	case pcommon.ValueTypeSlice:
		if input.Slice().Len() > s.config.MaxCollectionItems || input.Slice().Len() > s.remaining {
			output.SetStr("[REDACTED:limit]")
			return
		}
		values := output.SetEmptySlice()
		for i := 0; i < input.Slice().Len(); i++ {
			s.value(input.Slice().At(i), values.AppendEmpty(), depth+1, "")
		}
	default:
		output.SetStr(mask)
	}
}

func (s *sanitizer) native(input any, depth int, key string) any {
	if isSensitiveKey(key) {
		return mask
	}
	if depth > s.config.MaxDepth || s.remaining <= 0 {
		return "[REDACTED:limit]"
	}
	s.remaining--
	if isSQLKey(key) {
		if value, ok := input.(string); ok {
			return s.sql(value)
		}
		return "[REDACTED:sql]"
	}
	switch value := input.(type) {
	case nil, bool:
		return value
	case string:
		return s.text(value, depth)
	case json.Number:
		if cleaned := redactText(value.String()); cleaned != value.String() {
			return cleaned
		}
		if strings.ContainsAny(value.String(), "eE") {
			if number, err := strconv.ParseFloat(value.String(), 64); err == nil {
				decimal := strconv.FormatFloat(number, 'f', -1, 64)
				if cleaned := redactText(decimal); cleaned != decimal {
					return cleaned
				}
			}
		}
		return value
	case map[string]any:
		if len(value) > s.config.MaxCollectionItems || len(value) > s.remaining {
			return "[REDACTED:limit]"
		}
		out := make(map[string]any, len(value))
		i := 0
		for k, v := range value {
			cleanKey := s.key(k, i)
			redactedKey := cleanKey != k
			i++
			for {
				if _, duplicate := out[cleanKey]; !duplicate {
					break
				}
				cleanKey = fmt.Sprintf("elven.redacted_key_%d", i)
				i++
			}
			if redactedKey {
				out[cleanKey] = mask
			} else {
				out[cleanKey] = s.native(v, depth+1, k)
			}
		}
		return out
	case []any:
		if len(value) > s.config.MaxCollectionItems || len(value) > s.remaining {
			return "[REDACTED:limit]"
		}
		out := make([]any, len(value))
		for i := range value {
			out[i] = s.native(value[i], depth+1, "")
		}
		return out
	default:
		return mask
	}
}
