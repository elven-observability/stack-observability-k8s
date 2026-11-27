"""Real Flask/SQLite/Redis app; only the external injected SDK emits telemetry."""
import logging
import os
import sqlite3
from contextlib import closing

from flask import Flask, jsonify
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from redis import Redis
from redis.backoff import NoBackoff
from redis.exceptions import ResponseError
from redis.retry import Retry

EMAIL = "sdk.synthetic.customer@example.invalid"
PASSWORD = "ELVEN_SDK_PRIVATE_PASSWORD"
VALUE = "sdk.synthetic.value@example.invalid password=" + PASSWORD
MESSAGE = "checkout failed pricing upstream for " + EMAIL + " password=" + PASSWORD + " retry=false"
CASE = "python314"
app = Flask(__name__)


def database():
    with closing(sqlite3.connect(":memory:", timeout=3)) as connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT '" + EMAIL + "' AS customer_email, '" + PASSWORD + "' AS password, 42 AS answer")
            row = cursor.fetchone()
            if row != (EMAIL, PASSWORD, 42):
                raise RuntimeError("SQLite literal result assertion failed")
            cursor.execute("SELECT ? AS bound_email", (EMAIL,))
            if cursor.fetchone() != (EMAIL,):
                raise RuntimeError("SQLite bind result assertion failed")
            # SQLite SELECT 1/0 is NULL, NOT an error. Require a missing function.
            try:
                cursor.execute("SELECT ELVEN_MISSING_FUNCTION()")
            except sqlite3.OperationalError as expected:
                if "ELVEN_MISSING_FUNCTION" not in str(expected):
                    raise
                return True
            raise RuntimeError("Expected SQLite missing-function error did not occur")
        finally:
            cursor.close()


def redis_work():
    client = Redis(host=os.environ.get("REDIS_HOST", "redis"), port=int(os.environ.get("REDIS_PORT", "6379")),
                   password=os.environ.get("REDIS_PASSWORD") or None, decode_responses=True,
                   socket_connect_timeout=3, socket_timeout=3, retry=Retry(NoBackoff(), 0),
                   retry_on_timeout=False)
    try:
        key = "elven-sdk-privacy:" + CASE + ":" + EMAIL
        if client.set(key, VALUE, ex=120) is not True or client.get(key) != VALUE:
            raise RuntimeError("Redis SET/GET result assertion failed")
        try:
            client.hget(key, "field")
        except ResponseError as expected:
            if not str(expected).startswith("WRONGTYPE "):
                raise
            return True
        raise RuntimeError("Expected Redis WRONGTYPE error did not occur")
    finally:
        client.close()


def fetchPrice():
    raise ValueError(MESSAGE)


@app.get("/ready")
def ready():
    return jsonify(ready=True)


@app.get("/exercise")
def exercise():
    try:
        parent = trace.get_current_span().get_span_context()
        if not parent.is_valid:
            raise RuntimeError("Injected HTTP instrumentation did not provide a parent span")
        with trace.get_tracer("elven.sdk.privacy.fixture").start_as_current_span("elven.privacy.exception") as span:
            span.set_attributes({"elven.test.case": "sdk-exception-" + CASE, "http.route": "/exercise",
                                 "http.request.method": "GET", "http.response.status_code": 502})
            sql_error = database()
            redis_error = redis_work()
            try:
                fetchPrice()
            except ValueError as expected:
                span.record_exception(expected)
                span.set_status(Status(StatusCode.ERROR, str(expected)))
                # A real standard-library application log under the injected
                # SDK context. Its delivery is NOT presumed by this fixture.
                logging.getLogger("elven.sdk.privacy.fixture").error("%s", expected,
                    exc_info=(type(expected), expected, expected.__traceback__))
            if not span.get_span_context().is_valid:
                raise RuntimeError("Injected SDK did not provide an active span")
            return jsonify(ok=True, sql=True, sqlError=sql_error, redisSet=True, redisGet=True,
                           redisError=redis_error, exception=True, activeSpan=True, runtime=CASE), 502
    except Exception as failure:
        # Suppress message/traceback here: infrastructure errors can echo inputs.
        logging.getLogger("elven.sdk.privacy.fixture").error("Synthetic exercise infrastructure failure: %s", type(failure).__name__)
        return jsonify(ok=False), 500


if __name__ == "__main__":
    app.run(host=os.environ.get("BIND_ADDRESS", "0.0.0.0"), port=int(os.environ.get("PORT", "8080")),
            debug=False, use_reloader=False, threaded=True)
