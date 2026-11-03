// SPDX-License-Identifier: Apache-2.0
package elvenprivacyprocessor

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const textMask = "[REDACTED]"

var (
	emailPattern        = regexp.MustCompile(`[\p{L}\p{N}._%+\\-]+@[\p{L}\p{N}.\-]+`)
	jwtPattern          = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	bearerPattern       = regexp.MustCompile(`(?i)\b(Bearer|Basic)[\t ]+(?:\[REDACTED(?::[a-z-]+)?\]|[A-Za-z0-9._~+/=-]+)`)
	keyValuePattern     = regexp.MustCompile(`([\p{L}_][\p{L}\p{N}_.-]{0,95})(["']?[\t ]*[:=][\t ]*)`)
	keyValueAtStart     = regexp.MustCompile("^" + keyValuePattern.String())
	urlPattern          = regexp.MustCompile(`(?i)\b(?:[a-z][a-z0-9+.-]{1,24})://[^\s<>"']+`)
	relativeURLPattern  = regexp.MustCompile(`/[^\s<>"']*\?[^\s<>"']*`)
	encodedPattern      = regexp.MustCompile(`%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}`)
	plainNumberPattern  = regexp.MustCompile(`[0-9]{11,19}`)
	cpfPattern          = regexp.MustCompile(`[0-9]{3}[.]?[0-9]{3}[.]?[0-9]{3}-?[0-9]{2}`)
	cnpjPattern         = regexp.MustCompile(`[0-9]{2}[.]?[0-9]{3}[.]?[0-9]{3}/?[0-9]{4}-?[0-9]{2}`)
	cardSequencePattern = regexp.MustCompile(`[0-9][0-9 -]{11,62}[0-9]`)
	sqlPattern          = regexp.MustCompile(`(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|WITH|MERGE)\b`)
	sqlContext          = regexp.MustCompile(`(?i)(?:sql|query|statement)[\t :="']*$`)
	sqlSelectShape      = regexp.MustCompile(`(?is)^SELECT[\t ]+(?:[*?0-9(+\-'\"]|[^;\n]+\bFROM\b|[A-Za-z_][A-Za-z0-9_.]*[\t ]*\()`)
	sqlUpdateShape      = regexp.MustCompile(`(?is)^UPDATE[\t ]+[^;\n]+\bSET\b`)
	sqlWithShape        = regexp.MustCompile(`(?is)^WITH[\t ]+[^;\n]+\bAS[\t ]*\(`)
	correlationPrefix   = regexp.MustCompile(`(?i)(?:trace[_. -]?id|span[_. -]?id|request[_. -]?id|correlation[_. -]?id)[\t ]*[:=][\t ]*["']?$`)
)

func normalizedKey(key string) string {
	if decoded, ok := decodeTextLayers(key); ok {
		key = decoded
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, normalizeUnicode(key))
}

func isSQLKey(key string) bool {
	switch normalizedKey(key) {
	case "dbstatement", "dbquerytext", "sql", "query", "statement", "sqlquery", "sqlstatement", "querytext", "databasequery", "preparedstatement":
		return true
	}
	return false
}

func isSensitiveKey(key string) bool {
	if _, ok := decodeTextLayers(key); !ok {
		return true // An opaque/invalid encoded key must not hide a secret value.
	}
	k := normalizedKey(key)
	if strings.Contains(k, "password") || strings.Contains(k, "passwd") || strings.Contains(k, "passphrase") || strings.Contains(k, "secret") || strings.Contains(k, "token") || strings.Contains(k, "apikey") || strings.Contains(k, "privatekey") || strings.Contains(k, "authorization") || strings.Contains(k, "cookie") || strings.Contains(k, "senha") || strings.Contains(k, "segredo") || strings.Contains(k, "chaveapi") || strings.Contains(k, "chaveprivada") {
		return true
	}
	if strings.HasPrefix(k, "httprequestheader") || strings.HasPrefix(k, "httpresponseheader") || strings.HasPrefix(k, "requestheader") || strings.HasPrefix(k, "responseheader") {
		return true
	}
	if strings.Contains(k, "bind") && (strings.Contains(k, "param") || strings.Contains(k, "value")) {
		return true
	}
	for _, prefix := range []string{"dbqueryparameter", "dbqueryparam", "dbstatementparameter", "dboperationparameter", "dbparameter", "queryparameter", "bindparam", "bindvalue", "requestpayload", "responsepayload", "eventpayload", "processcommandargs", "processcommandline", "processenvironment"} {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	switch k {
	case "urlquery", "httpquery", "httpurlquery", "urlqueryparams", "processowner", "nomecompleto", "nomedousuario", "nomedousuário", "usuario", "usuário", "documento", "numerodocumento", "datadenascimento", "datanascimento", "endereco", "endereço", "enderecocompleto", "endereçocompleto", "cep", "numerocartao", "numerocartão", "cartaodecredito", "cartãodecrédito", "cartaocredito", "cartãocrédito":
		return true
	case "pwd", "credential", "credentials", "accesskey", "accesskeyid", "awsaccesskeyid", "secretkey", "sessionid", "session", "headers", "payload", "requestbody", "responsebody", "httprequestbody", "httpresponsebody", "dbqueryparameters", "dbqueryparams", "dbstatementparameters", "dbparameters", "queryparameters", "parameters", "sqlparams", "sqlparameters":
		return true
	case "email", "emailaddress", "useremail", "customeremail", "contactemail", "cpf", "cnpj", "ssn", "taxid", "document", "documentnumber", "socialsecuritynumber", "passport", "passportnumber", "fullname", "firstname", "lastname", "personname", "username", "userlogin", "userfullname", "userid", "useridentifier", "userphone", "useraddress", "customername", "customerid", "birthdate", "dateofbirth", "dob", "phone", "phonenumber", "telephone", "mobile", "mobilephone", "telefone", "celular", "whatsapp", "tel", "address", "streetaddress", "postaladdress", "creditcard", "cardnumber", "creditcardnumber", "ccnumber", "cvv", "cvc", "pin", "account", "accountnumber", "bankaccount", "bankaccountnumber", "iban", "clientip", "clientaddress", "userip", "sourceaddress", "enduseremail", "enduserid", "endusername":
		return true
	}
	return false
}

// decodeTextLayers deliberately does not decode a valid JSON document. The
// processor first parses that document, then visits each key/value independently.
// This prevents encoded quotes inside a JSON string from corrupting its shape.
func decodeTextLayers(input string) (string, bool) {
	if !utf8.ValidString(input) {
		return "", false
	}
	s := input
	for range 3 {
		if json.Valid([]byte(s)) {
			return s, true
		}
		s = normalizeUnicode(s)
		// Strip credentials before decoding an encoded space in a URL password.
		s = urlPattern.ReplaceAllStringFunc(s, sanitizeURL)
		// Relative request targets need the same protection: decoding %20 or
		// %22 first could detach a private suffix from its query value.
		s = relativeURLPattern.ReplaceAllStringFunc(s, sanitizeURL)
		before := s
		s = decodePercent(s)
		s = decodeEscapes(s)
		if !utf8.ValidString(s) {
			return "", false
		}
		if s == before {
			return s, true
		}
	}
	// Our own URL-encoded placeholders are harmless. Other still-encoded input
	// exceeded the decode budget and must not fall back to the original text.
	probe := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(s), "%5bredacted%5d", ""), "%5bredacted:url%5d", "")
	if encodedPattern.MatchString(probe) {
		return "", false
	}
	return s, true
}

func decodePercent(s string) string {
	var out strings.Builder
	quote := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if value, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				decoded := byte(value)
				if quote != 0 && (decoded == quote || decoded == '\\') {
					out.WriteByte('\\')
				}
				out.WriteByte(decoded)
				if quote == 0 && (decoded == '"' || decoded == '\'') {
					quote = decoded
				}
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if quote == 0 && (s[i] == '"' || s[i] == '\'') {
			quote = s[i]
		} else if s[i] == quote {
			quote = 0
		}
	}
	return out.String()
}

func normalizeUnicode(input string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0xff01 && r <= 0xff5e {
			r -= 0xfee0
		}
		if unicode.Is(unicode.Cf, r) || (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') {
			return -1
		}
		if unicode.IsSpace(r) && r != '\n' && r != '\r' && r != '\t' {
			return ' '
		}
		if r > 127 && unicode.Is(unicode.Nd, r) {
			for _, table := range unicode.Nd.R16 {
				if r >= rune(table.Lo) && r <= rune(table.Hi) && (r-rune(table.Lo))%rune(table.Stride) == 0 {
					return '0' + ((r-rune(table.Lo))/rune(table.Stride))%10
				}
			}
			for _, table := range unicode.Nd.R32 {
				if r >= rune(table.Lo) && r <= rune(table.Hi) && (r-rune(table.Lo))%rune(table.Stride) == 0 {
					return '0' + ((r-rune(table.Lo))/rune(table.Stride))%10
				}
			}
		}
		return r
	}, input)
}

func decodeEscapes(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			out.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case '\\':
			end := i
			for end < len(s) && s[end] == '\\' {
				end++
			}
			count := end - i
			if end < len(s) && s[end] == 'u' && count > 1 {
				count--
			}
			out.WriteString(strings.Repeat("\\", count))
			i = end
		case 'u':
			if i+6 > len(s) {
				out.WriteString("[REDACTED:encoding]")
				return out.String()
			}
			n, err := strconv.ParseUint(s[i+2:i+6], 16, 16)
			if err != nil {
				out.WriteByte(s[i])
				i++
				continue
			}
			r := rune(n)
			i += 6
			if utf16.IsSurrogate(r) {
				if i+6 <= len(s) && s[i:i+2] == `\u` {
					low, parseErr := strconv.ParseUint(s[i+2:i+6], 16, 16)
					if parseErr == nil {
						r = utf16.DecodeRune(r, rune(low))
						i += 6
					} else {
						r = utf8.RuneError
					}
				} else {
					r = utf8.RuneError
				}
			}
			if r == utf8.RuneError {
				out.WriteString("[REDACTED:encoding]")
			} else {
				if r == '"' || r == '\'' || r == '\\' {
					out.WriteByte('\\')
				}
				out.WriteRune(r)
			}
		default:
			out.WriteByte(s[i])
			i++
		}
	}
	return out.String()
}

func sanitizeURL(input string) string {
	u, err := url.Parse(input)
	if err != nil {
		return "[REDACTED:url]"
	}
	if u.User != nil {
		u.User = url.User(textMask)
	}
	if u.RawQuery != "" {
		values, queryErr := url.ParseQuery(u.RawQuery)
		if queryErr != nil {
			u.RawQuery = "redacted=" + url.QueryEscape(textMask)
		} else {
			clean := url.Values{}
			for key, vals := range values {
				key = emailPattern.ReplaceAllString(key, textMask)
				key = jwtPattern.ReplaceAllString(key, textMask)
				for range vals {
					clean.Add(key, textMask)
				}
			}
			u.RawQuery = clean.Encode()
		}
	}
	if u.Fragment != "" {
		u.Fragment = textMask
	}
	return u.String()
}

func redactText(input string) string {
	s, ok := decodeTextLayers(input)
	if !ok {
		return "[REDACTED:encoding]"
	}
	if pos := embeddedSQL(s); pos != nil {
		if query, valid := sanitizeSQL(s[pos[0]:]); valid {
			s = s[:pos[0]] + query
		} else {
			s = s[:pos[0]] + "[REDACTED:sql]"
		}
	}
	s = urlPattern.ReplaceAllStringFunc(s, sanitizeURL)
	s = relativeURLPattern.ReplaceAllStringFunc(s, sanitizeURL)
	s = redactKeyValues(s)
	s = bearerPattern.ReplaceAllStringFunc(s, func(value string) string {
		end := strings.IndexAny(value, "\t ")
		return value[:end] + " " + textMask
	})
	s = jwtPattern.ReplaceAllString(s, textMask)
	s = emailPattern.ReplaceAllString(s, textMask)
	return redactNumbers(s)
}

func embeddedSQL(s string) []int {
	matches := sqlPattern.FindAllStringIndex(s, 257)
	for index, pos := range matches {
		// Repeated non-SQL verbs cannot exhaust the detector and turn a later
		// SQL statement into an unchecked raw suffix.
		if index == 256 {
			return pos
		}
		if sqlContext.MatchString(s[max(0, pos[0]-48):pos[0]]) {
			return pos
		}
		window := s[pos[0]:min(len(s), pos[0]+4096)]
		upper := strings.ToUpper(window)
		switch strings.ToUpper(s[pos[0]:pos[1]]) {
		case "SELECT":
			if sqlSelectShape.MatchString(window) {
				return pos
			}
		case "UPDATE":
			if sqlUpdateShape.MatchString(window) {
				return pos
			}
		case "WITH":
			if sqlWithShape.MatchString(window) {
				return pos
			}
		case "INSERT":
			if strings.HasPrefix(upper, "INSERT INTO ") {
				return pos
			}
		case "DELETE":
			if strings.HasPrefix(upper, "DELETE FROM ") {
				return pos
			}
		case "MERGE":
			if strings.HasPrefix(upper, "MERGE INTO ") {
				return pos
			}
		}
	}
	return nil
}

// Values in logfmt-like text end at a clear following field, not punctuation
// that may be part of a credential. Quoted/compound values are consumed as a
// whole; malformed compounds fail closed through the remainder of the text.
// URL query ranges have already been sanitized by redactText and must not be
// reparsed as independent log fields with ambiguous URL delimiters.
func redactKeyValues(s string) string {
	var out strings.Builder
	position := 0
	queries := sanitizedQueryRanges(s)
	queryIndex := 0
	for position < len(s) {
		match := keyValuePattern.FindStringSubmatchIndex(s[position:])
		if match == nil {
			out.WriteString(s[position:])
			break
		}
		for i := range match {
			match[i] += position
		}
		start, valueStart := match[0], match[1]
		key := s[match[2]:match[3]]
		for queryIndex < len(queries) && queries[queryIndex].end <= start {
			queryIndex++
		}
		if queryIndex < len(queries) && start >= queries[queryIndex].start && start < queries[queryIndex].end {
			out.WriteString(s[position:valueStart])
			position = valueStart
			continue
		}
		if !isSensitiveKey(key) {
			out.WriteString(s[position:valueStart])
			position = valueStart
			continue
		}
		out.WriteString(s[position:valueStart])
		if valueStart >= len(s) {
			out.WriteString(textMask)
			break
		}
		quotedKey := match[2] > 0 && (s[match[2]-1] == '"' || s[match[2]-1] == '\'')
		end, quote := sensitiveValueEnd(s, valueStart, key, quotedKey)
		if quote != 0 {
			out.WriteByte(quote)
		}
		out.WriteString(textMask)
		if quote != 0 {
			out.WriteByte(quote)
		}
		position = end
		if position <= start { // Defensive progress invariant for malformed input.
			position = valueStart + 1
		}
	}
	return out.String()
}

type queryRange struct{ start, end int }

func sanitizedQueryRanges(s string) []queryRange {
	var ranges []queryRange
	for _, pattern := range []*regexp.Regexp{urlPattern, relativeURLPattern} {
		for _, interval := range pattern.FindAllStringIndex(s, -1) {
			if question := strings.IndexByte(s[interval[0]:interval[1]], '?'); question >= 0 {
				ranges = append(ranges, queryRange{interval[0] + question + 1, interval[1]})
			}
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:0]
	for _, r := range ranges {
		if len(merged) > 0 && r.start <= merged[len(merged)-1].end {
			merged[len(merged)-1].end = max(merged[len(merged)-1].end, r.end)
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}

func opaqueHeaderKey(key string) bool {
	switch normalizedKey(key) {
	case "cookie", "setcookie", "authorization", "proxyauthorization":
		return true
	default:
		return false
	}
}

func sensitiveValueEnd(s string, start int, key string, quotedKey bool) (int, byte) {
	if !quotedKey && opaqueHeaderKey(key) && s[start] != '"' && s[start] != '\'' {
		// Raw headers can contain their own comma/semicolon-separated key=value
		// parameters. They are not reliable boundaries of a new log field.
		return len(s), 0
	}
	end, quote := start, byte(0)
	completed := false
	switch s[start] {
	case '"', '\'':
		quote = s[start]
		end, completed = quotedSensitiveEnd(s, start)
		if !completed {
			return len(s), 0
		}
	case '{', '[':
		end, completed = compoundSensitiveEnd(s, start)
		if !completed {
			return len(s), 0
		}
	default:
		// Encoded placeholders generated for already-sanitized URLs are safe,
		// but must still consume any directly attached malformed suffix.
		if strings.HasPrefix(strings.ToLower(s[start:]), "%5bredacted") {
			if close := strings.Index(strings.ToLower(s[start:]), "%5d"); close >= 0 {
				end = start + close + 3
				completed = true
			}
		}
	}
	if completed {
		if end == len(s) || strings.ContainsRune(" \t\r\n", rune(s[end])) {
			return end, quote
		}
		if quotedKey && strings.ContainsRune(",}]", rune(s[end])) {
			return end, quote
		}
		// "one"PRIVATE or {"one":"two"}PRIVATE is malformed, not an
		// independent public suffix. Consume through the next clear field.
	}
	return nextClearField(s, end), quote
}

func quotedSensitiveEnd(s string, start int) (int, bool) {
	quote := s[start]
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' {
			if i+1 >= len(s) {
				return len(s), false
			}
			i++
			continue
		}
		if s[i] == quote {
			return i + 1, true
		}
	}
	return len(s), false
}

func compoundSensitiveEnd(s string, start int) (int, bool) {
	var stack [24]byte
	depth := 0
	quote := byte(0)
	for i := start; i < len(s); i++ {
		if quote != 0 {
			if s[i] == '\\' {
				if i+1 >= len(s) {
					return len(s), false
				}
				i++
				continue
			}
			if s[i] == quote {
				quote = 0
			}
			continue
		}
		switch s[i] {
		case '"', '\'':
			quote = s[i]
		case '{', '[':
			if depth == len(stack) {
				return len(s), false
			}
			stack[depth] = s[i]
			depth++
		case '}', ']':
			if depth == 0 || (s[i] == '}' && stack[depth-1] != '{') || (s[i] == ']' && stack[depth-1] != '[') {
				return len(s), false
			}
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return len(s), false
}

func nextClearField(s string, start int) int {
	for end := start; end < len(s); end++ {
		if strings.ContainsRune(" \t\r\n", rune(s[end])) {
			next := end
			for next < len(s) && strings.ContainsRune(" \t\r\n", rune(s[next])) {
				next++
			}
			if keyValueAtStart.MatchString(s[next:]) {
				return end
			}
			// Scan each whitespace run once. Searching the whole suffix at
			// every space would make an ambiguous large secret quadratic.
			end = next - 1
		}
	}
	return len(s)
}

func redactNumbers(s string) string {
	// Process exact formats separately so adjacent CPF/CNPJ/PAN values cannot
	// aggregate into a longer nonmatching number and hide each other.
	s = redactNumberMatches(s, cnpjPattern, func(string) bool { return true })
	s = redactNumberMatches(s, cpfPattern, func(string) bool { return true })
	s = redactNumberMatches(s, plainNumberPattern, func(digits string) bool {
		return len(digits) == 11 || len(digits) == 14 || (len(digits) >= 13 && len(digits) <= 19 && luhn(digits))
	})
	return redactFormattedCards(s)
}

func numberBoundary(s string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	if end < len(s) {
		r, _ := utf8.DecodeRuneInString(s[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	return true
}

func correlationNumber(s string, start int, value string) bool {
	if len(value) != 16 && len(value) != 32 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return correlationPrefix.MatchString(s[max(0, start-48):start])
}

func redactNumberMatches(s string, pattern *regexp.Regexp, classify func(string) bool) string {
	var out strings.Builder
	previous := 0
	for _, match := range pattern.FindAllStringIndex(s, -1) {
		start, end := match[0], match[1]
		if !numberBoundary(s, start, end) || correlationNumber(s, start, s[start:end]) {
			continue
		}
		value := s[start:end]
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, value)
		if !classify(digits) {
			continue
		}
		out.WriteString(s[previous:start])
		out.WriteString(textMask)
		previous = end
	}
	out.WriteString(s[previous:])
	return out.String()
}

func redactFormattedCards(s string) string {
	var out strings.Builder
	previous := 0
	for _, match := range cardSequencePattern.FindAllStringIndex(s, -1) {
		sequence := s[match[0]:match[1]]
		for start := 0; start < len(sequence); start++ {
			if sequence[start] < '0' || sequence[start] > '9' || (start > 0 && sequence[start-1] >= '0' && sequence[start-1] <= '9') {
				continue
			}
			digits := make([]byte, 0, 19)
			best := 0
			for end := start; end < len(sequence); end++ {
				c := sequence[end]
				if c >= '0' && c <= '9' {
					digits = append(digits, c)
					if len(digits) > 19 {
						break
					}
					if len(digits) >= 13 && (end+1 == len(sequence) || sequence[end+1] < '0' || sequence[end+1] > '9') && luhn(string(digits)) && numberBoundary(s, match[0]+start, match[0]+end+1) && !correlationNumber(s, match[0]+start, sequence[start:end+1]) {
						best = end + 1
					}
				} else if c != ' ' && c != '-' {
					break
				}
			}
			if best > start {
				globalStart, globalEnd := match[0]+start, match[0]+best
				out.WriteString(s[previous:globalStart])
				out.WriteString(textMask)
				previous = globalEnd
				start = best - 1
			}
		}
	}
	out.WriteString(s[previous:])
	return out.String()
}

func luhn(digits string) bool {
	sum := 0
	double := false
	allZero := true
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		allZero = allZero && n == 0
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return !allZero && sum%10 == 0
}
