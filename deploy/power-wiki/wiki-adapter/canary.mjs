import {createHmac, randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const baseUrl = process.env.WIKI_CANARY_URL ?? 'http://127.0.0.1:18060';
const audience = process.env.POWER_WIKI_GATEWAY_ID;
const serviceToken = (await readFile(process.env.SERVICE_TOKEN_FILE, 'utf8')).trim();
const identityKey = (await readFile(process.env.IDENTITY_SECRET_FILE, 'utf8')).trim();

if (!audience || serviceToken.length < 32 || identityKey.length < 32) {
  throw new Error('INVALID_CANARY_CONFIGURATION');
}

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sign(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const protectedSegment = encode({alg: 'HS256', typ: 'JWT'});
  const payloadSegment = encode({
    id: 'power-wiki-upgrade-canary',
    email: 'power-wiki-upgrade-canary@local.invalid',
    is_admin: false,
    iss: 'mcpgateway-identity-propagation',
    aud: audience,
    iat: now,
    exp: now + 60,
    jti: randomUUID().replaceAll('-', ''),
    ...overrides,
  });
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = createHmac('sha256', identityKey).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

async function post(body, {signature, expectedStatus = 200} = {}) {
  const headers = {
    accept: 'application/json, text/event-stream',
    authorization: `Bearer ${serviceToken}`,
    'content-type': 'application/json',
  };
  if (signature) {
    headers['x-forwarded-user-claims-signature'] = signature;
  }
  const response = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (response.status !== expectedStatus) {
    throw new Error(`UNEXPECTED_STATUS_${response.status}_EXPECTED_${expectedStatus}`);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

const healthResponse = await fetch(`${baseUrl}/health`);
const health = await healthResponse.json();
if (!healthResponse.ok || health.status !== 'ready') {
  throw new Error('CANARY_NOT_READY');
}

const listed = await post({jsonrpc: '2.0', id: 'list', method: 'tools/list', params: {}});
if (!Array.isArray(listed?.result?.tools) || listed.result.tools.length !== 14) {
  throw new Error('CANARY_TOOL_CATALOG_MISMATCH');
}

const headerCall = await post(
  {jsonrpc: '2.0', id: 'header', method: 'tools/call', params: {name: 'wiki_status', arguments: {}}},
  {signature: sign()},
);
if (headerCall?.result?.isError || !Array.isArray(headerCall?.result?.content)) {
  throw new Error('CANARY_HEADER_CALL_FAILED');
}

const metaCall = await post({
  jsonrpc: '2.0',
  id: 'meta',
  method: 'tools/call',
  params: {
    name: 'wiki_status',
    arguments: {},
    _meta: {user: {claims_signature: sign()}},
  },
});
if (metaCall?.result?.isError || !Array.isArray(metaCall?.result?.content)) {
  throw new Error('CANARY_META_CALL_FAILED');
}

const legacySignature = createHmac('sha256', identityKey)
  .update('power-wiki-upgrade-canary:power-wiki-upgrade-canary@local.invalid')
  .digest('hex');
await post(
  {jsonrpc: '2.0', id: 'legacy', method: 'tools/call', params: {name: 'wiki_status', arguments: {}}},
  {signature: legacySignature, expectedStatus: 401},
);
await post(
  {jsonrpc: '2.0', id: 'aud', method: 'tools/call', params: {name: 'wiki_status', arguments: {}}},
  {signature: sign({aud: 'wrong-gateway'}), expectedStatus: 401},
);

console.log(JSON.stringify({status: 'ok', tools: listed.result.tools.length, checks: 5}));
