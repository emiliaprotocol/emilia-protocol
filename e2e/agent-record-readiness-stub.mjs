// SPDX-License-Identifier: Apache-2.0

import http from 'node:http';

const HOST = '127.0.0.1';
const PORT = 54_321;
const SERVICE_ROLE_KEY = 'e2e-service-role-key';
const UPSTASH_TOKEN = 'e2e-upstash-token';
const CREATION_CAPABILITY = `earc1_${'0'.repeat(64)}`;

const ERROR_CODE_BY_RPC = Object.freeze({
  create_agent_record_with_capability: '22023',
  read_agent_adoption_session: 'P0002',
  read_agent_record_refusal_source: 'P0002',
  read_agent_record_public: 'P0002',
  revoke_agent_record: '22023',
});

function reply(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
  });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1024) throw new Error('request_too_large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const server = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url === '/health') {
    return reply(response, 200, { status: 'ready' });
  }
  if (request.method === 'POST'
      && request.url === '/upstash'
      && request.headers.authorization === `Bearer ${UPSTASH_TOKEN}`) {
    let command;
    try {
      command = await readJson(request);
    } catch {
      return reply(response, 400, { error: 'invalid_json' });
    }
    const maximum = Number(command?.[5]);
    const windowSeconds = Number(command?.[6]);
    if (!Array.isArray(command)
        || command[0] !== 'EVAL'
        || command[2] !== '1'
        || !Number.isSafeInteger(maximum)
        || maximum < 1
        || !Number.isSafeInteger(windowSeconds)
        || windowSeconds < 1) {
      return reply(response, 400, { error: 'unexpected_rate_limit_command' });
    }
    return reply(response, 200, { result: [1, maximum - 1, windowSeconds] });
  }
  if (request.method !== 'POST'
      || !request.url?.startsWith('/rest/v1/rpc/')
      || request.headers.apikey !== SERVICE_ROLE_KEY
      || request.headers.authorization !== `Bearer ${SERVICE_ROLE_KEY}`) {
    return reply(response, 404, { code: 'not_found' });
  }

  const rpc = request.url.slice('/rest/v1/rpc/'.length);
  let input;
  try {
    input = await readJson(request);
  } catch {
    return reply(response, 400, { code: 'invalid_json' });
  }

  if (rpc === 'check_agent_record_creation_capability') {
    return reply(response, 200, input?.p_creation_capability === CREATION_CAPABILITY);
  }
  if (rpc === 'check_agent_record_storage_contract') {
    return reply(response, 200, input && Object.keys(input).length === 0);
  }

  const expectedCode = ERROR_CODE_BY_RPC[rpc];
  if (!expectedCode) return reply(response, 404, { code: 'unknown_rpc' });
  return reply(response, 400, {
    code: expectedCode,
    details: null,
    hint: null,
    message: 'Expected inert E2E readiness probe.',
  });
});

server.listen(PORT, HOST);

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
