// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Redis operands are keys, values or scripts, not SQL identifiers. Preserve only
// a finite operation name; parsing arbitrary RESP, Lua or command subgrammars
// would risk treating private operands as harmless query structure.
func redisOperation(input string) string {
	if input == mask || input == "[REDACTED:redis]" {
		return input
	}
	if len(input) > 262144 || !utf8.ValidString(input) {
		return "[REDACTED:redis]"
	}
	decoded, ok := decodeTextLayers(input)
	if !ok {
		return "[REDACTED:redis]"
	}
	parts := strings.Fields(decoded)
	if len(parts) == 0 {
		return "[REDACTED:redis]"
	}
	command := strings.ToUpper(parts[0])
	switch command {
	case "GET", "MGET", "SET", "MSET", "SETNX", "GETSET", "GETDEL", "GETEX", "DEL", "UNLINK", "EXISTS",
		"EXPIRE", "EXPIREAT", "PEXPIRE", "PEXPIREAT", "TTL", "PTTL", "PERSIST", "INCR", "INCRBY", "DECR", "DECRBY",
		"HGET", "HMGET", "HGETALL", "HSET", "HSETNX", "HDEL", "HEXISTS", "HLEN", "HINCRBY",
		"LPUSH", "RPUSH", "LPOP", "RPOP", "LRANGE", "LLEN", "SADD", "SREM", "SMEMBERS", "SISMEMBER", "SCARD",
		"ZADD", "ZREM", "ZRANGE", "ZSCORE", "ZCARD", "PING", "AUTH", "SELECT", "MULTI", "EXEC", "DISCARD",
		"WATCH", "UNWATCH", "EVAL", "EVALSHA", "PUBLISH", "SUBSCRIBE", "PSUBSCRIBE", "XADD", "XREAD", "XREADGROUP",
		"SCAN", "HSCAN", "SSCAN", "ZSCAN", "KEYS", "INFO", "CLIENT", "CONFIG", "CLUSTER", "COMMAND", "SCRIPT":
		return command
	default:
		return "[REDACTED:redis]"
	}
}

func redisAttributes(input pcommon.Map) bool {
	redis := false
	input.Range(func(key string, value pcommon.Value) bool {
		k := normalizedKey(key)
		if k == "rediscommand" || k == "dbrediscommand" {
			redis = true // Explicit Redis command attribute is sufficient context.
		}
		if (k == "dbsystem" || k == "dbsystemname") && value.Type() == pcommon.ValueTypeStr {
			decoded, ok := decodeTextLayers(value.Str())
			redis = redis || ok && strings.EqualFold(strings.TrimSpace(decoded), "redis")
		}
		return true
	})
	return redis
}

func redisField(key string) bool {
	k := normalizedKey(key)
	return isSQLKey(key) || k == "dbquerysummary" || k == "dboperation" || k == "dboperationname" || k == "rediscommand" || k == "dbrediscommand"
}

func sanitizeRedisException(input pcommon.Map, maxStringBytes int) {
	// Redis errors can echo an unlabelled arbitrary key/script. Preserve the
	// exception type, event identity and correlation, not the echoed operands.
	input.Range(func(key string, value pcommon.Value) bool {
		if redisDiagnostic(key) {
			clean := mask
			if value.Type() == pcommon.ValueTypeStr && len(value.Str()) <= maxStringBytes {
				clean = redisDiagnosticValue(key, value.Str())
			}
			value.SetStr(clean)
		}
		return true
	})
}

// Redis protocol error categories are finite public tokens. Never decode an
// encoded prefix or keep following operands, addresses, messages or frames.
// https://redis.io/docs/latest/develop/reference/protocol-spec/#simple-errors
func redisErrorMarker(code string) string {
	switch code {
	case "WRONGTYPE", "NOAUTH", "WRONGPASS", "NOPERM", "OOM", "READONLY", "MISCONF", "BUSY", "NOSCRIPT", "LOADING",
		"CLUSTERDOWN", "CROSSSLOT", "TRYAGAIN", "MOVED", "ASK", "EXECABORT", "ERR":
		return "[REDACTED:redis:" + code + "]"
	default:
		return mask
	}
}

func isRedisDiagnosticMarker(input string) bool {
	const prefix = "[REDACTED:redis:"
	if !strings.HasPrefix(input, prefix) || !strings.HasSuffix(input, "]") {
		return false
	}
	return redisErrorMarker(input[len(prefix):len(input)-1]) == input
}

func redisDiagnosticValue(key, input string) string {
	if normalizedKey(key) == "exceptionstacktrace" || len(input) > 262144 || !utf8.ValidString(input) {
		return mask
	}
	if isRedisDiagnosticMarker(input) {
		return input // Only the exact finite generated marker is idempotent.
	}
	end := strings.IndexAny(input, " \t\r\n\v\f")
	if end < 0 {
		end = len(input)
	}
	return redisErrorMarker(input[:end])
}

func redisDiagnostic(key string) bool {
	k := normalizedKey(key)
	return k == "exceptionmessage" || k == "exceptionstacktrace" || k == "statusdescription"
}
