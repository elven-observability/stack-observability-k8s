FROM docker.io/library/php:8.5-cli-bookworm@sha256:050713ce008e2360ea9dc96e1f9a075690132388d917fc3552806f7a7be6f2a0
COPY app.php /app/app.php
RUN php -r 'if (PHP_VERSION_ID < 80512) { exit(1); }'
USER 10001:10001
ENTRYPOINT ["php", "-S", "0.0.0.0:8080", "/app/app.php"]
