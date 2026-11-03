import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.concurrent.Executors;

/** No tracing API or SDK imports: only the separately injected Java agent can emit spans. */
public final class JavaFixture {
    private static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
    // Deliberately synthetic PII. The Java agent may replace SQL literals before
    // export; this proves real JDBC statement spans, not gateway-only redaction.
    private static final String QUERY =
        "SELECT 'synthetic-customer@example.invalid' AS email, " +
        "'4111111111111111' AS card_number, 42 AS answer";

    private static void reply(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static int downstream() throws IOException {
        String endpoint = System.getenv().getOrDefault(
            "OUTBOUND_URL", "http://127.0.0.1:" + PORT + "/downstream");
        HttpURLConnection connection = (HttpURLConnection) new URL(endpoint).openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        try {
            int status = connection.getResponseCode();
            try (var input = status < 400 ? connection.getInputStream() : connection.getErrorStream()) {
                if (input != null) {
                    input.transferTo(java.io.OutputStream.nullOutputStream());
                }
            }
            return status;
        } finally {
            connection.disconnect();
        }
    }

    private static void exercise(HttpExchange exchange) throws IOException {
        try (Connection connection = DriverManager.getConnection("jdbc:h2:mem:elven_fixture");
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(QUERY)) {
            if (!result.next() || result.getInt("answer") != 42) {
                throw new IllegalStateException("Synthetic JDBC assertion failed");
            }
            int status = downstream();
            if (status != 200) {
                throw new IOException("Synthetic downstream returned " + status);
            }
            reply(exchange, 200, "{\"ok\":true,\"jdbc\":true,\"downstream\":200}");
        } catch (Exception error) {
            // Avoid including query/PII in response or stdout. The real JDBC
            // instrumentation sees the query directly at Statement.executeQuery.
            System.err.println("Synthetic exercise failure: " + error.getClass().getSimpleName());
            reply(exchange, 500, "{\"ok\":false}");
        }
    }

    public static void main(String[] args) throws Exception {
        Class.forName("org.h2.Driver");
        HttpServer server = HttpServer.create(new InetSocketAddress(
            System.getenv().getOrDefault("BIND_ADDRESS", "0.0.0.0"), PORT), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/ready", exchange -> reply(exchange, 200, "{\"ready\":true}"));
        server.createContext("/downstream", exchange -> reply(exchange, 200, "{\"downstream\":true}"));
        server.createContext("/exercise", JavaFixture::exercise);
        server.start();
        System.out.println("Synthetic fixture ready; java=" + Runtime.version().feature());
    }
}
