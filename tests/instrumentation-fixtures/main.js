'use strict';

// No OpenTelemetry dependency or API: the external SDK preload instruments core HTTP.
const http = require('node:http');
const port = Number(process.env.PORT || 8080);

function reply(response, status, body) {
  response.writeHead(status, {'content-type': 'application/json'});
  response.end(JSON.stringify(body));
}

const server = http.createServer((request, response) => {
  const path = new URL(request.url, 'http://fixture.invalid').pathname;
  if (path === '/ready') return reply(response, 200, {ready: true});
  if (path === '/downstream') return reply(response, 200, {downstream: true});
  if (path !== '/exercise') return reply(response, 404, {ok: false});
  const endpoint = process.env.OUTBOUND_URL || `http://127.0.0.1:${port}/downstream`;
  const downstream = http.get(endpoint, (result) => {
    result.resume();
    result.on('end', () => reply(response, result.statusCode === 200 ? 200 : 502,
      {ok: result.statusCode === 200, downstream: result.statusCode}));
  });
  downstream.setTimeout(5000, () => downstream.destroy(new Error('Synthetic downstream timeout')));
  downstream.on('error', () => reply(response, 502, {ok: false}));
});

server.listen(port, process.env.BIND_ADDRESS || '0.0.0.0', () => {
  console.log(`Synthetic fixture ready; node=${process.versions.node}`);
});
