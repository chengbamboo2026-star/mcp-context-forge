import http from 'node:http';
import {randomUUID} from 'node:crypto';
import {appendFile, cp, lstat, mkdir, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import Ajv from 'ajv';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {createMcpServer} from '../upstream/packages/core/dist/mcp/server.js';
import {READ_TOOLS, handleReadToolCall} from '../upstream/packages/core/dist/mcp/read-tools.js';
import {WRITE_TOOLS, handleWriteToolCall} from '../upstream/packages/core/dist/mcp/write-tools.js';
import {initWiki} from '../upstream/packages/core/dist/init.js';
import {OAuthAuthorizationError, bearerChallenge, createOAuthVerifier} from './oauth-jwt.mjs';

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Required environment variable is empty: ${name}`);
  }
  return value;
}

const data = resolve(process.env.WIKI_DATA_DIR || '/data');
const root = join(data, '.wiki');
const publicUrl = requiredEnvironment('POWER_WIKI_PUBLIC_URL').replace(/\/$/, '');
const resourceUrl = requiredEnvironment('POWER_WIKI_RESOURCE_URL');
const issuer = requiredEnvironment('OAUTH_ISSUER').replace(/\/$/, '');
if (
  resourceUrl !== 'https://kb.bamboo9527.top/mcp' ||
  issuer !== 'https://auth.bamboo9527.top/realms/power-wiki-direct-dev'
) {
  throw new Error('DIRECT_PROFILE_BOUNDARY_VIOLATION');
}
const requiredScope = process.env.OAUTH_REQUIRED_SCOPE?.trim() || 'mcp:tools';
const requiredRole = process.env.OAUTH_REQUIRED_ROLE?.trim() || 'power-wiki-operator';
const metadataUrl = `${publicUrl}/.well-known/oauth-protected-resource`;
const oauth = createOAuthVerifier({
  issuer,
  resource: resourceUrl,
  jwksUrl: process.env.OAUTH_JWKS_URL?.trim() || `${issuer}/protocol/openid-connect/certs`,
  requiredScope,
  requiredRole,
});

await mkdir(data, {recursive: true});

async function restore() {
  await rm(root, {recursive: true, force: true});
  await cp(join(data, 'rollback'), root, {recursive: true});
  await rm(join(data, 'pending'), {force: true});
}

try {
  await lstat(join(data, 'pending'));
  await restore();
} catch (error) {
  if (error.code !== 'ENOENT') {
    throw error;
  }
}

await initWiki(data);
process.chdir(root);

const writeTools = new Set(WRITE_TOOLS.map((tool) => tool.name));
const ajv = new Ajv({strict: false});
const validators = new Map([...READ_TOOLS, ...WRITE_TOOLS].map((tool) => [tool.name, ajv.compile(tool.inputSchema)]));

async function rejectSymbolicLinks(path) {
  for (const entry of await readdir(path, {withFileTypes: true})) {
    if (entry.isSymbolicLink()) {
      throw new Error('UNSAFE_PATH');
    }
    if (entry.isDirectory()) {
      await rejectSymbolicLinks(join(path, entry.name));
    }
  }
}

function validatePaths(args) {
  for (const key of ['path', 'pagePath', 'sourcePath']) {
    if (args[key] === undefined) {
      continue;
    }
    const value = args[key];
    if (
      typeof value !== 'string' ||
      value.startsWith('/') ||
      /[\\\x00%]/.test(value) ||
      value.split('/').some((part) => part === '..' || part === '.')
    ) {
      throw new Error('UNSAFE_PATH');
    }
    if (key === 'sourcePath' && !value.startsWith('raw/')) {
      throw new Error('SOURCE_MUST_BE_IN_RAW');
    }
  }
}

function sendJson(response, status, payload, headers = {}) {
  response.writeHead(status, {'content-type': 'application/json', ...headers});
  response.end(JSON.stringify(payload));
}

function metadata() {
  return {
    resource: resourceUrl,
    authorization_servers: [issuer],
    bearer_methods_supported: ['header'],
    scopes_supported: [requiredScope],
    resource_name: 'Power LLM Wiki',
  };
}

let queue = Promise.resolve();
let stopping = false;

const app = http.createServer(async (request, response) => {
  const requestPath = new URL(request.url, publicUrl).pathname;
  if (requestPath === '/health' && request.method === 'GET') {
    sendJson(response, stopping ? 503 : 200, {status: stopping ? 'stopping' : 'ready'});
    return;
  }
  if (
    (requestPath === '/.well-known/oauth-protected-resource' || requestPath === '/.well-known/oauth-protected-resource/mcp') &&
    request.method === 'GET'
  ) {
    sendJson(response, 200, metadata(), {'cache-control': 'public, max-age=300'});
    return;
  }
  if (requestPath !== '/mcp') {
    sendJson(response, 404, {error: 'NOT_FOUND'});
    return;
  }
  if (request.method !== 'POST') {
    response.writeHead(405, {Allow: 'POST'});
    response.end();
    return;
  }

  let identity;
  try {
    identity = await oauth.authenticate(request.headers);
  } catch (error) {
    const status = error instanceof OAuthAuthorizationError ? error.status : 503;
    const code = error instanceof OAuthAuthorizationError ? error.code : 'OAUTH_UNAVAILABLE';
    const headers = status === 401 || status === 403 ? {'www-authenticate': bearerChallenge(metadataUrl, requiredScope)} : {};
    sendJson(response, status, {error: code}, headers);
    return;
  }

  let body;
  try {
    let bytes = 0;
    const chunks = [];
    for await (const chunk of request) {
      bytes += chunk.length;
      if (bytes > 2_000_000) {
        throw new Error('REQUEST_TOO_LARGE');
      }
      chunks.push(chunk);
    }
    body = JSON.parse(Buffer.concat(chunks).toString());
    if (!body || Array.isArray(body)) {
      throw new Error('INVALID_REQUEST');
    }
  } catch {
    sendJson(response, 400, {error: 'INVALID_REQUEST'});
    return;
  }

  let release;
  const previous = queue;
  queue = new Promise((resolveQueue) => {
    release = resolveQueue;
  });
  await previous;

  const server = createMcpServer(root);
  const transport = new StreamableHTTPServerTransport({sessionIdGenerator: undefined, enableJsonResponse: true});
  server.setRequestHandler(CallToolRequestSchema, async (toolRequest) => {
    const {name, arguments: args = {}} = toolRequest.params;
    let pending = false;
    const operationId = randomUUID();
    try {
      if (!validators.get(name)?.(args)) {
        throw new Error('INVALID_ARGUMENT');
      }
      validatePaths(args);
      await rejectSymbolicLinks(root);
      if (writeTools.has(name)) {
        await rm(join(data, 'rollback'), {recursive: true, force: true});
        await cp(root, join(data, 'rollback'), {recursive: true});
        await writeFile(join(data, 'pending'), operationId);
        pending = true;
      }
      const text = await (writeTools.has(name) ? handleWriteToolCall : handleReadToolCall)(name, args, root);
      let structured;
      try {
        structured = JSON.parse(text);
      } catch {
        structured = undefined;
      }
      if (structured?.status === 'error' || structured?.ingest?.status === 'error') {
        throw new Error('OPERATION_FAILED');
      }
      await appendFile(
        join(data, 'audit.jsonl'),
        `${JSON.stringify({at: new Date().toISOString(), id: operationId, actor: identity.id, tool: name, outcome: 'success'})}\n`,
      );
      if (pending) {
        await rm(join(data, 'pending'));
        pending = false;
      }
      return {content: [{type: 'text', text}]};
    } catch (error) {
      if (pending) {
        try {
          await restore();
        } catch {
          stopping = true;
          process.exitCode = 1;
          throw new Error('RECOVERY_REQUIRED');
        }
      }
      const safeCodes = new Set(['INVALID_ARGUMENT', 'UNSAFE_PATH', 'SOURCE_MUST_BE_IN_RAW']);
      const code = safeCodes.has(error.message) ? error.message : 'WIKI_OPERATION_FAILED';
      return {isError: true, content: [{type: 'text', text: code}]};
    }
  });

  try {
    if (stopping) {
      throw new Error('WIKI_STOPPING');
    }
    await rejectSymbolicLinks(root);
    await server.connect(transport);
    await transport.handleRequest(request, response, body);
  } catch {
    if (!response.headersSent) {
      sendJson(response, 500, {error: 'WIKI_UNAVAILABLE'});
    }
  } finally {
    await server.close().catch(() => {});
    release();
  }
});

app.requestTimeout = 30000;
app.headersTimeout = 15000;
app.listen(Number(process.env.PORT || 8060), '0.0.0.0', () => console.log('{"event":"wiki_direct_started"}'));
process.on('SIGTERM', () => {
  stopping = true;
  app.close(() => process.exit(0));
});
