import assert from 'node:assert/strict';
import {createSign, generateKeyPairSync} from 'node:crypto';
import test from 'node:test';

import {
  OAuthAuthorizationError,
  bearerChallenge,
  createOAuthVerifier,
} from '../../../deploy/power-wiki/wiki-adapter/oauth-jwt.mjs';

const issuer = 'https://auth.example.test/realms/power-wiki';
const resource = 'https://kb.example.test/mcp';
const requiredScope = 'mcp:tools';
const requiredRole = 'power-wiki-operator';
const now = 1_800_000_000;
const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
const jwk = {
  ...publicKey.export({format: 'jwk'}),
  alg: 'RS256',
  kid: 'power-wiki-test-key',
  use: 'sig',
};

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function token(overrides = {}, protectedHeader = {alg: 'RS256', kid: jwk.kid, typ: 'JWT'}, signingKey = privateKey) {
  const payload = {
    iss: issuer,
    aud: resource,
    sub: 'operator-id',
    email: 'operator@example.test',
    iat: now - 1,
    exp: now + 60,
    scope: `openid ${requiredScope}`,
    realm_access: {roles: [requiredRole]},
    ...overrides,
  };
  const signingInput = `${encode(protectedHeader)}.${encode(payload)}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(signingKey).toString('base64url')}`;
}

function jsonResponse(body, ok = true) {
  return {ok, json: async () => body};
}

function verifier(fetchImpl = async () => jsonResponse({keys: [jwk]})) {
  return createOAuthVerifier({
    issuer,
    resource,
    jwksUrl: `${issuer}/protocol/openid-connect/certs`,
    requiredScope,
    requiredRole,
    fetchImpl,
    now: () => now,
  });
}

function authorization(value) {
  return {authorization: `Bearer ${value}`};
}

async function rejectsWith(value, status, code) {
  await assert.rejects(
    value,
    (error) => error instanceof OAuthAuthorizationError && error.status === status && error.code === code,
  );
}

test('accepts only an RS256 token with the exact issuer, audience, scope, and realm role', async () => {
  const identity = await verifier().authenticate(authorization(token()));

  assert.equal(identity.id, 'operator-id');
  assert.equal(identity.email, 'operator@example.test');
  assert.deepEqual(identity.roles, [requiredRole]);
  assert.ok(identity.scope.includes(requiredScope));
});

test('accepts the exact resource in a standards-compliant audience array', async () => {
  const identity = await verifier().authenticate(authorization(token({aud: ['account', resource]})));

  assert.equal(identity.id, 'operator-id');
});

test('rejects missing scope and missing role as distinct authorization failures', async () => {
  await rejectsWith(
    verifier().authenticate(authorization(token({scope: 'openid'}))),
    403,
    'INSUFFICIENT_SCOPE',
  );
  await rejectsWith(
    verifier().authenticate(authorization(token({realm_access: {roles: ['another-role']}}))),
    403,
    'INSUFFICIENT_ROLE',
  );
});

test('rejects wrong issuer, wrong audience, expired, future, and malformed claims', async () => {
  for (const invalidToken of [
    token({iss: 'https://issuer.example.invalid'}),
    token({aud: 'https://kb.example.test/other'}),
    token({exp: now - 1}),
    token({iat: now + 6, exp: now + 60}),
    token({sub: ''}),
    token({nbf: now + 6}),
  ]) {
    await rejectsWith(verifier().authenticate(authorization(invalidToken)), 401, 'AUTHENTICATION_REQUIRED');
  }
});

test('rejects algorithm confusion, an unknown key, a bad signature, and malformed bearer syntax', async () => {
  const otherPair = generateKeyPairSync('rsa', {modulusLength: 2048});
  await rejectsWith(
    verifier().authenticate(authorization(token({}, {alg: 'HS256', kid: jwk.kid, typ: 'JWT'}))),
    401,
    'AUTHENTICATION_REQUIRED',
  );
  await rejectsWith(
    verifier().authenticate(authorization(token({}, {alg: 'RS256', kid: 'unknown', typ: 'JWT'}))),
    401,
    'AUTHENTICATION_REQUIRED',
  );
  await rejectsWith(
    verifier().authenticate(authorization(token({}, undefined, otherPair.privateKey))),
    401,
    'AUTHENTICATION_REQUIRED',
  );
  assert.throws(
    () => verifier().authenticate({authorization: 'Basic value'}),
    (error) => error instanceof OAuthAuthorizationError && error.status === 401 && error.code === 'AUTHENTICATION_REQUIRED',
  );
});

test('caches valid JWKS responses and fails closed when keys are unavailable', async () => {
  let calls = 0;
  const cachedVerifier = verifier(async () => {
    calls += 1;
    return jsonResponse({keys: [jwk]});
  });
  await cachedVerifier.authenticate(authorization(token()));
  await cachedVerifier.authenticate(authorization(token()));
  assert.equal(calls, 1);

  await rejectsWith(
    verifier(async () => {
      throw new Error('network unavailable');
    }).authenticate(authorization(token())),
    503,
    'OAUTH_KEYS_UNAVAILABLE',
  );
});

test('publishes an RFC 9728 bearer challenge without credentials', () => {
  assert.equal(
    bearerChallenge('https://kb.example.test/.well-known/oauth-protected-resource', requiredScope),
    'Bearer resource_metadata="https://kb.example.test/.well-known/oauth-protected-resource", scope="mcp:tools"',
  );
});
