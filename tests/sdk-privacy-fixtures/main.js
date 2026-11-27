'use strict';

// API only. SDK/provider/instrumentations/exporters must be injected externally.
const http = require('node:http');
const {trace, SpanStatusCode, isSpanContextValid} = require('@opentelemetry/api');
const {createClient} = require('@redis/client');
const {Client} = require('pg');
const EMAIL = 'sdk.synthetic.customer@example.invalid';
const PASSWORD = 'ELVEN_SDK_PRIVATE_PASSWORD';
const MESSAGE = `checkout failed pricing upstream for ${EMAIL} password=${PASSWORD} retry=false`;
const VALUE = `sdk.synthetic.value@example.invalid password=${PASSWORD}`;

function fetchPrice() { throw new Error(MESSAGE); }

function reply(response, status, body) {
  response.writeHead(status, {'content-type': 'application/json'});
  response.end(JSON.stringify(body));
}

async function database() {
  const client = new Client({connectionTimeoutMillis: 5000, query_timeout: 5000,
    host: process.env.PGHOST || 'postgres', port: Number(process.env.PGPORT || 5432),
    database: process.env.PGDATABASE || 'fixture', user: process.env.PGUSER || 'fixture',
    password: process.env.PGPASSWORD || 'synthetic-fixture-password'});
  await client.connect();
  try {
    const result = await client.query(`SELECT '${EMAIL}' AS customer_email, '${PASSWORD}' AS password, 42 AS answer`);
    if (result.rows[0].answer !== 42 || result.rows[0].customer_email !== EMAIL) throw new Error('SQL result assertion failed');
    const bound = await client.query('SELECT $1::text AS bound_email', [EMAIL]);
    if (bound.rows[0].bound_email !== EMAIL) throw new Error('SQL bind assertion failed');
    try { await client.query('SELECT 1 / 0'); }
    catch (expected) { if (expected.code === '22012') return true; throw expected; }
    throw new Error('Expected SQL error did not occur');
  } finally { await client.end(); }
}

async function redis() {
  const client = createClient({socket: {host: process.env.REDIS_HOST || 'redis',
    port: Number(process.env.REDIS_PORT || 6379), connectTimeout: 5000, reconnectStrategy: false},
    password: process.env.REDIS_PASSWORD || undefined});
  client.on('error', () => {}); // Expected dependency failures are returned without private details.
  await client.connect();
  try {
    const key = `elven-sdk-privacy:node22:${EMAIL}`;
    if (await client.set(key, VALUE, {EX: 120}) !== 'OK' || await client.get(key) !== VALUE) {
      throw new Error('Redis SET/GET result assertion failed');
    }
    try { await client.hGet(key, 'field'); }
    catch (expected) { if (expected.message.includes('WRONGTYPE')) return true; throw expected; }
    throw new Error('Expected Redis WRONGTYPE error did not occur');
  } finally { await client.quit(); }
}

async function exercise(response) {
  await trace.getTracer('elven.sdk.privacy.fixture').startActiveSpan('elven.privacy.exception', async (span) => {
    try {
      span.setAttributes({'elven.test.case': 'sdk-exception-node22', 'http.route': '/exercise',
        'http.request.method': 'GET', 'http.response.status_code': 502});
      const sqlError = await database();
      const redisError = await redis();
      try { fetchPrice(); }
      catch (expected) {
        span.recordException(expected);
        span.setStatus({code: SpanStatusCode.ERROR, message: expected.message});
        // Real stdout log, not an SDK-log-export or custom OTLP implementation.
        console.log(JSON.stringify({severity: 'ERROR', 'elven.test.case': 'sdk-exception-node22',
          trace_id: span.spanContext().traceId, span_id: span.spanContext().spanId,
          'exception.type': expected.name, 'exception.message': expected.message, 'exception.stacktrace': expected.stack}));
      }
      if (!isSpanContextValid(span.spanContext())) throw new Error('Injected SDK did not provide an active span');
      reply(response, 502, {ok: true, sql: true, sqlError, redisSet: true, redisGet: true, redisError,
        exception: true, activeSpan: true, runtime: 'node22'});
    } catch (failure) {
      console.error('Synthetic exercise infrastructure failure: ' + failure.name);
      reply(response, 500, {ok: false});
    } finally { span.end(); }
  });
}

http.createServer((request, response) => {
  const path = new URL(request.url, 'http://fixture.invalid').pathname;
  if (path === '/ready') return reply(response, 200, {ready: true});
  if (path !== '/exercise' || request.method !== 'GET') return reply(response, 404, {ok: false});
  exercise(response).catch(() => { if (!response.headersSent) reply(response, 500, {ok: false}); });
}).listen(Number(process.env.PORT || 8080), process.env.BIND_ADDRESS || '0.0.0.0');
