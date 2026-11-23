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

func sanitizeRedisException(input pcommon.Map) {
	// Redis errors can echo an unlabelled arbitrary key/script. Preserve the
	// exception type, event identity and correlation, not the echoed operands.
	input.Range(func(key string, value pcommon.Value) bool {
		if k := normalizedKey(key); k == "exceptionmessage" || k == "exceptionstacktrace" {
			value.SetStr(mask)
		}
		return true
	})
}
