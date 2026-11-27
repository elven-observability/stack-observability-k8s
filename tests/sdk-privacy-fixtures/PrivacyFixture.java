import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Scope;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.params.SetParams;
import redis.clients.jedis.exceptions.JedisDataException;

/** API only: no SDK/provider/exporter or fabricated OTLP in the application. */
public final class PrivacyFixture {
    private static final String EMAIL = "sdk.synthetic.customer@example.invalid";
    private static final String PASSWORD = "ELVEN_SDK_PRIVATE_PASSWORD";
    private static final String REDIS_VALUE = "sdk.synthetic.value@example.invalid password=" + PASSWORD;
    private static final String RUNTIME = "java" + Runtime.version().feature();
    private static final String MESSAGE = "checkout failed pricing upstream for " + EMAIL + " password=" + PASSWORD + " retry=false";

    private static String environment(String name, String fallback) {
        return System.getenv().getOrDefault(name, fallback);
    }

    private static void reply(HttpExchange exchange, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (var out = exchange.getResponseBody()) { out.write(body); }
    }

    private static boolean database() throws Exception {
        try (var connection = DriverManager.getConnection("jdbc:h2:mem:elven_sdk_privacy");
             var statement = connection.createStatement();
             var rows = statement.executeQuery("SELECT '" + EMAIL + "' AS customer_email, '" + PASSWORD + "' AS password, 42 AS answer")) {
            if (!rows.next() || rows.getInt("answer") != 42 || !EMAIL.equals(rows.getString("customer_email"))) {
                throw new IllegalStateException("JDBC result assertion failed");
            }
            try (var prepared = connection.prepareStatement("SELECT ? AS bound_email")) {
                prepared.setString(1, EMAIL);
                try (var result = prepared.executeQuery()) {
                    if (!result.next() || !EMAIL.equals(result.getString(1))) throw new IllegalStateException("JDBC bind assertion failed");
                }
            }
            try { statement.executeQuery("SELECT 1 / 0"); }
            catch (SQLException expected) { return true; }
            throw new IllegalStateException("Expected SQL error did not occur");
        }
    }

    private static boolean redis() throws Exception {
        try (var client = new Jedis(environment("REDIS_HOST", "redis"), Integer.parseInt(environment("REDIS_PORT", "6379")), 5000)) {
            String password = environment("REDIS_PASSWORD", "");
            if (!password.isEmpty()) client.auth(password);
            String key = "elven-sdk-privacy:" + RUNTIME + ":" + EMAIL;
            if (!"OK".equals(client.set(key, REDIS_VALUE, SetParams.setParams().ex(120))) || !REDIS_VALUE.equals(client.get(key))) {
                throw new IllegalStateException("Redis SET/GET result assertion failed");
            }
            try { client.hget(key, "field"); }
            catch (JedisDataException expected) {
                if (expected.getMessage().contains("WRONGTYPE")) return true;
                throw expected;
            }
            throw new IllegalStateException("Expected Redis WRONGTYPE error did not occur");
        }
    }

    private static void fetchPrice() { throw new IllegalStateException(MESSAGE); }

    private static String quoted(String input) {
        StringBuilder result = new StringBuilder("\"");
        for (char c : input.toCharArray()) {
            switch (c) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 32) result.append(String.format("\\u%04x", (int) c)); else result.append(c);
            }
        }
        return result.append('"').toString();
    }

    private static void exercise(HttpExchange exchange) throws IOException {
        try {
            exerciseWithTelemetry(exchange);
        } catch (Exception | LinkageError failure) {
            // Do not print exception messages/cause strings: they can contain PII.
            System.err.println("Synthetic exercise infrastructure failure: " + failure.getClass().getName());
            StackTraceElement[] frames = failure.getStackTrace();
            for (int index = 0; index < Math.min(frames.length, 32); index++) {
                System.err.println("\tat " + frames[index]);
            }
            if (exchange.getResponseCode() < 0) reply(exchange, 500, "{\"ok\":false}");
        } finally { exchange.close(); }
    }

    private static void exerciseWithTelemetry(HttpExchange exchange) throws IOException {
        Span span = GlobalOpenTelemetry.getTracer("elven.sdk.privacy.fixture").spanBuilder("elven.privacy.exception").startSpan();
        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute("elven.test.case", "sdk-exception-" + RUNTIME);
            span.setAttribute("http.route", "/exercise");
            span.setAttribute("http.request.method", "GET");
            span.setAttribute("http.response.status_code", 502);
            boolean sqlError = database();
            boolean redisError = redis();
            try { fetchPrice(); }
            catch (IllegalStateException expected) {
                span.recordException(expected);
                span.setStatus(StatusCode.ERROR, expected.getMessage());
                // A real application stdout log; IDs come from the injected SDK.
                // This is not an SDK-log-export assertion or an OTLP message.
                StringWriter stack = new StringWriter();
                expected.printStackTrace(new PrintWriter(stack));
                System.out.println("{\"severity\":\"ERROR\",\"elven.test.case\":\"sdk-exception-" + RUNTIME
                    + "\",\"trace_id\":" + quoted(span.getSpanContext().getTraceId())
                    + ",\"span_id\":" + quoted(span.getSpanContext().getSpanId())
                    + ",\"exception.type\":" + quoted(expected.getClass().getName())
                    + ",\"exception.message\":" + quoted(expected.getMessage())
                    + ",\"exception.stacktrace\":" + quoted(stack.toString()) + "}");
            }
            boolean active = span.getSpanContext().isValid();
            if (!active) throw new IllegalStateException("Injected SDK did not provide an active span");
            reply(exchange, 502, "{\"ok\":true,\"sql\":true,\"sqlError\":" + sqlError
                + ",\"redisSet\":true,\"redisGet\":true,\"redisError\":" + redisError
                + ",\"exception\":true,\"activeSpan\":true,\"runtime\":\"" + RUNTIME + "\"}");
        } catch (Exception failure) {
            System.err.println("Synthetic exercise infrastructure failure: " + failure.getClass().getSimpleName());
            reply(exchange, 500, "{\"ok\":false}");
        } finally { span.end(); }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--check-dependencies".equals(args[0])) {
            for (String name : new String[]{"io.opentelemetry.common.ComponentLoader", "io.opentelemetry.context.Context",
                    "io.opentelemetry.api.GlobalOpenTelemetry", "redis.clients.jedis.Jedis", "org.h2.Driver",
                    "org.slf4j.Logger", "org.apache.commons.pool2.impl.GenericObjectPool", "org.json.JSONObject",
                    "com.google.gson.Gson", "com.google.errorprone.annotations.CanIgnoreReturnValue"}) {
                Class.forName(name);
            }
            System.out.println("API/client dependency classes verified; no SDK/provider or HTTP server started");
            return;
        }
        Class.forName("org.h2.Driver");
        HttpServer server = HttpServer.create(new InetSocketAddress(environment("BIND_ADDRESS", "0.0.0.0"), Integer.parseInt(environment("PORT", "8080"))), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.createContext("/ready", exchange -> reply(exchange, 200, "{\"ready\":true}"));
        server.createContext("/exercise", PrivacyFixture::exercise);
        server.start();
    }
}
