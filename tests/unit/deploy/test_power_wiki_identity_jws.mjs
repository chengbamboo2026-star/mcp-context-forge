import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import test from 'node:test';

import {
  CONTEXTFORGE_IDENTITY_ISSUER,
  createIdentityVerifier,
} from '../../../deploy/power-wiki/wiki-adapter/identity-jws.mjs';

const serviceToken = 'service-token-0123456789abcdef0123456789abcdef';
const identityKey = 'identity-key-0123456789abcdef0123456789abcdef';
const audience = 'f3e121c0e35c4167a02b9e2c4736e6b9';
const now = 1_800_000_000;

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sign(overrides = {}, protectedHeader = {alg: 'HS256', typ: 'JWT'}, key = identityKey) {
  const payload = {
    id: 'user@example.com',
    email: 'user@example.com',
    is_admin: false,
    iss: CONTEXTFORGE_IDENTITY_ISSUER,
    aud: audience,
    iat: now,
    exp: now + 60,
    jti: '0123456789abcdef0123456789abcdef',
    ...overrides,
  };
  const signingInput = `${encode(protectedHeader)}.${encode(payload)}`;
  const signature = createHmac('sha256', key).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

function verifier() {
  return createIdentityVerifier({serviceToken, identityKey, audience, now: () => now});
}

function authorizedHeaders(signature) {
  return {
    authorization: `Bearer ${serviceToken}`,
    'x-forwarded-user-claims-signature': signature,
  };
}

test('accepts the v1.1.2 header JWS and authorizes only its signed identity', () => {
  const auth = verifier();
  const headers = {
    ...authorizedHeaders(sign()),
    'x-forwarded-user-id': 'forged@example.com',
  };
  auth.authenticateService(headers);
  assert.equal(auth.resolveIdentity(headers, {method: 'tools/call'}).id, 'user@example.com');
});

test('does not require the non-contractual JWT typ header', () => {
  const tokenWithoutType = sign({}, {alg: 'HS256'});
  assert.equal(verifier().resolveIdentity(authorizedHeaders(tokenWithoutType), {}).id, 'user@example.com');
});

test('prefers the fresh request-scoped meta JWS used by pooled sessions', () => {
  const auth = verifier();
  const body = {
    method: 'tools/call',
    params: {_meta: {user: {claims_signature: sign({id: 'fresh@example.com'})}}},
  };
  assert.equal(auth.resolveIdentity({authorization: `Bearer ${serviceToken}`}, body).id, 'fresh@example.com');
});

test('accepts distinct header and meta tokens for the same signed identity', () => {
  const body = {
    params: {_meta: {user: {claims_signature: sign({jti: '11111111111111111111111111111111'})}}},
  };
  assert.equal(verifier().resolveIdentity(authorizedHeaders(sign()), body).id, 'user@example.com');
});

test('rejects conflicting signed identities when both proof locations are present', () => {
  const body = {
    params: {_meta: {user: {claims_signature: sign({id: 'other@example.com'})}}},
  };
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign()), body), /AUTHENTICATION_REQUIRED/);
});

test('allows unsigned discovery but returns no authorized user', () => {
  assert.equal(verifier().resolveIdentity({authorization: `Bearer ${serviceToken}`}, {method: 'tools/list'}), null);
});

test('rejects a wrong service bearer token', () => {
  assert.throws(() => verifier().authenticateService({authorization: 'Bearer wrong'}), /AUTHENTICATION_REQUIRED/);
});

test('rejects the legacy hexadecimal HMAC signature', () => {
  const legacy = createHmac('sha256', identityKey).update('user@example.com:user@example.com').digest('hex');
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(legacy), {}), /AUTHENTICATION_REQUIRED/);
});

test('rejects a token signed by another key', () => {
  assert.throws(
    () => verifier().resolveIdentity(authorizedHeaders(sign({}, undefined, 'attacker-key-0123456789abcdef0123456789abcdef')), {}),
    /AUTHENTICATION_REQUIRED/,
  );
});

test('rejects algorithm confusion and non-canonical compact JWS', () => {
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({}, {alg: 'HS512', typ: 'JWT'})), {}), /AUTHENTICATION_REQUIRED/);
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(`${sign()}=`), {}), /AUTHENTICATION_REQUIRED/);
});

test('rejects the wrong issuer or gateway audience', () => {
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({iss: 'mcpgateway'})), {}), /AUTHENTICATION_REQUIRED/);
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({aud: 'another-gateway'})), {}), /AUTHENTICATION_REQUIRED/);
});

test('rejects expired, future, or overlong tokens', () => {
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({iat: now - 120, exp: now - 60})), {}), /AUTHENTICATION_REQUIRED/);
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({iat: now + 6, exp: now + 66})), {}), /AUTHENTICATION_REQUIRED/);
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({exp: now + 61})), {}), /AUTHENTICATION_REQUIRED/);
});

test('rejects missing or malformed required identity claims', () => {
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({id: ''})), {}), /AUTHENTICATION_REQUIRED/);
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({jti: 'not-a-jti'})), {}), /AUTHENTICATION_REQUIRED/);
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign({is_admin: 'false'})), {}), /AUTHENTICATION_REQUIRED/);
});

test('fails closed when request meta contains a malformed proof even if a header proof is valid', () => {
  const body = {params: {_meta: {user: {claims_signature: 'malformed'}}}};
  assert.throws(() => verifier().resolveIdentity(authorizedHeaders(sign()), body), /AUTHENTICATION_REQUIRED/);
});
