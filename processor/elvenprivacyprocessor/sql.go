// Copyright Elven Observability.
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"strings"
	"unicode/utf8"
)

// sqlToken never contains a literal or comment. A token's depth is its nesting
// level before that token, excluding parentheses that belong to quoted data.
type sqlToken struct {
	text  string
	depth int
}

// sanitizeSQL returns a diagnostic query shape, not executable SQL. It supports
// a conservative SQL lexical subset, not every vendor grammar. Literal values,
// comments, parameters and quoted identifiers are never returned. Unsupported or
// malformed input returns no partial output: callers MUST replace it with a
// redaction marker, never fall back to the original query.
func sanitizeSQL(input string) (string, bool) {
	if len(input) == 0 || len(input) > 1<<20 || !utf8.ValidString(input) || strings.IndexByte(input, 0) >= 0 {
		return "", false
	}
	tokens := make([]sqlToken, 0, min(len(input)/4+1, 256))
	depth := 0
	appendToken := func(text string) bool {
		if len(tokens) >= 65536 {
			return false
		}
		tokens = append(tokens, sqlToken{text: text, depth: depth})
		return true
	}
	for i := 0; i < len(input); {
		c := input[i]
		if sqlSpace(c) {
			i++
			continue
		}
		if c < 0x20 || c >= utf8.RuneSelf {
			return "", false
		}
		// SQL comments may contain arbitrary private data. They are discarded,
		// including nested PostgreSQL block comments, without tokenizing content.
		if c == '#' || (c == '-' && i+1 < len(input) && input[i+1] == '-') {
			for i < len(input) && input[i] != '\n' && input[i] != '\r' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(input) && input[i+1] == '*' {
			var ok bool
			i, ok = sqlBlockCommentEnd(input, i+2)
			if !ok {
				return "", false
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' || c == '[' {
			var ok bool
			i, ok = sqlQuoteEnd(input, i)
			if !ok || !appendToken("?") {
				return "", false
			}
			continue
		}
		if c == '$' {
			if i > 0 && (sqlIdentContinue(input[i-1]) || input[i-1] == '.') {
				return "", false
			}
			if delimiter, after, ok := sqlDollarDelimiter(input, i); ok {
				end := strings.Index(input[after:], delimiter)
				if end < 0 {
					return "", false
				}
				i = after + end + len(delimiter)
			} else {
				i++
				start := i
				for i < len(input) && sqlIdentContinue(input[i]) {
					i++
				}
				if i == start {
					return "", false
				}
			}
			if !appendToken("?") {
				return "", false
			}
			continue
		}
		if (c == ':' && i+1 < len(input) && input[i+1] != ':' && sqlIdentContinue(input[i+1])) || c == '@' {
			if i > 0 && (sqlIdentContinue(input[i-1]) || input[i-1] == '.') {
				return "", false
			}
			i++
			if c == '@' && i < len(input) && input[i] == '@' {
				i++
			}
			start := i
			for i < len(input) && sqlIdentContinue(input[i]) {
				i++
			}
			if i == start || !appendToken("?") {
				return "", false
			}
			continue
		}
		if sqlDigit(c) || (c == '.' && i+1 < len(input) && sqlDigit(input[i+1])) {
			var ok bool
			i, ok = sqlNumberEnd(input, i)
			if !ok || !appendToken("?") {
				return "", false
			}
			continue
		}
		if sqlIdentStart(c) {
			start := i
			i++
			for i < len(input) && sqlIdentContinue(input[i]) {
				i++
			}
			word := input[start:i]
			switch strings.ToUpper(word) {
			case "TRUE", "FALSE", "NULL":
				word = "?"
			}
			if !appendToken(word) {
				return "", false
			}
			continue
		}
		switch c {
		case '(':
			if depth >= 64 || !appendToken("(") {
				return "", false
			}
			depth++
			i++
		case ')':
			if depth == 0 {
				return "", false
			}
			depth--
			if !appendToken(")") {
				return "", false
			}
			i++
		case ';':
			if depth != 0 || !appendToken(";") {
				return "", false
			}
			i++
		case ',', '.', '*', '=', '<', '>', '+', '-', '/', '%', '!', '|', '&', '^', '~', '?':
			if !appendToken(input[i : i+1]) {
				return "", false
			}
			i++
		case ':':
			if i+1 >= len(input) || input[i+1] != ':' || !appendToken("::") {
				return "", false
			}
			i += 2
		default:
			return "", false
		}
	}
	if depth != 0 || len(tokens) == 0 {
		return "", false
	}
	start := 0
	for i := 0; i <= len(tokens); i++ {
		if i != len(tokens) && tokens[i].text != ";" {
			continue
		}
		if i > start {
			if !sqlSupportedStatement(tokens[start:i]) {
				return "", false
			}
		} else if i != len(tokens) {
			return "", false
		}
		start = i + 1
	}
	parts := make([]string, len(tokens))
	for i := range tokens {
		parts[i] = tokens[i].text
	}
	return strings.Join(parts, " "), true
}

func sqlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' }
func sqlDigit(c byte) bool { return c >= '0' && c <= '9' }
func sqlIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}
func sqlIdentContinue(c byte) bool { return sqlIdentStart(c) || sqlDigit(c) }
func sqlHex(c byte) bool {
	return sqlDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func sqlBlockCommentEnd(input string, i int) (int, bool) {
	depth := 1
	for i < len(input)-1 {
		if input[i:i+2] == "/*" {
			depth++
			if depth > 64 {
				return 0, false
			}
			i += 2
		} else if input[i:i+2] == "*/" {
			depth--
			i += 2
			if depth == 0 {
				return i, true
			}
		} else {
			i++
		}
	}
	return 0, false
}

func sqlQuoteEnd(input string, start int) (int, bool) {
	end := input[start]
	// PostgreSQL E-strings explicitly select backslash escaping. In generic
	// strings/identifiers, an odd backslash before a quote is ambiguous across
	// SQL modes (e.g. MySQL NO_BACKSLASH_ESCAPES). Reject the complete query
	// rather than accidentally treating a literal segment as an identifier.
	explicitEscape := end == '\'' && start > 0 && (input[start-1] == 'E' || input[start-1] == 'e') &&
		(start == 1 || !sqlIdentContinue(input[start-2]))
	if end == '[' {
		end = ']'
	}
	for i := start + 1; i < len(input); i++ {
		if input[i] == '\\' && input[start] != '[' {
			if i+1 >= len(input) {
				return 0, false
			}
			if explicitEscape || input[i+1] == '\\' {
				i++
				continue
			}
			if input[i+1] == end {
				return 0, false
			}
		}
		if input[i] == end {
			if i+1 < len(input) && input[i+1] == end {
				i++
				continue
			}
			return i + 1, true
		}
	}
	return 0, false
}

func sqlDollarDelimiter(input string, start int) (string, int, bool) {
	i := start + 1
	if i < len(input) && input[i] == '$' {
		return "$$", i + 1, true
	}
	if i >= len(input) || !sqlIdentStart(input[i]) {
		return "", 0, false
	}
	for i < len(input) && sqlIdentContinue(input[i]) {
		i++
	}
	if i < len(input) && input[i] == '$' {
		return input[start : i+1], i + 1, true
	}
	return "", 0, false
}

func sqlNumberEnd(input string, start int) (int, bool) {
	i := start
	if i+1 < len(input) && input[i] == '0' && (input[i+1] == 'x' || input[i+1] == 'X' || input[i+1] == 'b' || input[i+1] == 'B') {
		binary := input[i+1] == 'b' || input[i+1] == 'B'
		i += 2
		first := i
		for i < len(input) && ((!binary && sqlHex(input[i])) || (binary && (input[i] == '0' || input[i] == '1'))) {
			i++
		}
		return i, i > first && (i == len(input) || (!sqlIdentContinue(input[i]) && input[i] != '.'))
	}
	for i < len(input) && sqlDigit(input[i]) {
		i++
	}
	if i < len(input) && input[i] == '.' {
		i++
		for i < len(input) && sqlDigit(input[i]) {
			i++
		}
	}
	if i < len(input) && (input[i] == 'e' || input[i] == 'E') {
		i++
		if i < len(input) && (input[i] == '+' || input[i] == '-') {
			i++
		}
		first := i
		for i < len(input) && sqlDigit(input[i]) {
			i++
		}
		if i == first {
			return 0, false
		}
	}
	return i, i > start && (i == len(input) || (!sqlIdentContinue(input[i]) && input[i] != '.'))
}

func sqlSupportedStatement(tokens []sqlToken) bool {
	if len(tokens) < 2 || tokens[0].depth != 0 {
		return false
	}
	verb := strings.ToUpper(tokens[0].text)
	has := func(word string) bool {
		for _, token := range tokens[1:] {
			if token.depth == 0 && strings.EqualFold(token.text, word) {
				return true
			}
		}
		return false
	}
	switch verb {
	case "SELECT":
		switch strings.ToUpper(tokens[1].text) {
		case "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "UNION", "JOIN", ")", ",":
			return false
		}
		return true
	case "INSERT":
		return has("INTO") && (has("VALUES") || has("SELECT"))
	case "UPDATE":
		return has("SET") && has("=")
	case "DELETE":
		return has("FROM") && len(tokens) >= 3
	case "MERGE":
		return has("INTO") && has("USING") && has("ON")
	case "WITH", "EXPLAIN":
		for i := 1; i < len(tokens)-1; i++ {
			if tokens[i].depth != 0 {
				continue
			}
			switch strings.ToUpper(tokens[i].text) {
			case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE":
				return sqlSupportedStatement(tokens[i:])
			}
		}
		return false
	case "CREATE", "ALTER", "DROP":
		// Account/role/password administration and function/procedure dialects
		// are intentionally unsupported, rather than guessing about secrets.
		for _, token := range tokens[1:] {
			switch strings.ToUpper(token.text) {
			case "PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "APITOKEN", "AUTHORIZATION", "CREDENTIAL", "CREDENTIALS", "ACCESSKEY", "IDENTIFIED", "AUTHENTICATION":
				return false
			}
		}
		for i := 1; i < len(tokens)-1 && i < 5; i++ {
			switch strings.ToUpper(tokens[i].text) {
			case "OR", "REPLACE", "TEMP", "TEMPORARY", "UNIQUE", "MATERIALIZED":
				continue
			case "TABLE", "INDEX", "VIEW", "SCHEMA", "DATABASE", "SEQUENCE":
				return true
			default:
				return false
			}
		}
		return false
	case "TRUNCATE":
		return true
	default:
		return false
	}
}
