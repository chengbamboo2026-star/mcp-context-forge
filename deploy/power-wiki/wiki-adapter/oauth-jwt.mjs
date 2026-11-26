import {createPublicKey, verify as verifySignature} from 'node:crypto';

const DEFAULT_CLOCK_SKEW_SECONDS = 5;
const DEFAULT_JWKS_CACHE_SECONDS = 300;

export class OAuthAuthorizationError extends Error {
  constructor(status, code) {
    super(code);
    this.name = 'OAuthAuthorizationError';
    this.status = status;
    this.code = code;
  }
}

function authorizationError(status = 401, code = 'AUTHENTICATION_REQUIRED') {
  return new OAuthAuthorizationError(status, code);
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`INVALID_${name}`);
  }
  return value;
}

function decodeBase64Url(segment) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw authorizationError();
  }
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.length === 0 || decoded.toString('base64url') !== segment) {
    throw authorizationError();
  }
  return decoded;
}

function decodeJsonObject(segment) {
  let value;
  try {
    value = JSON.parse(decodeBase64Url(segment).toString('utf8'));
  } catch {
    throw authorizationError();
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authorizationError();
  }
  return value;
}

function bearerToken(headers) {
  const value = headers?.authorization;
  if (typeof value !== 'string' || !value.startsWith('Bearer ')) {
    throw authorizationError();
  }
  const token = value.slice('Bearer '.length);
  if (!token || token.includes(' ')) {
    throw authorizationError();
  }
  return token;
}

function audiences(payload) {
  if (typeof payload.aud === 'string') {
    return [payload.aud];
  }
  if (Array.isArray(payload.aud) && payload.aud.every((item) => typeof item === 'string')) {
    return payload.aud;
  }
  throw authorizationError();
}

function scopes(payload) {
  if (typeof payload.scope !== 'string') {
    return new Set();
  }
  return new Set(payload.scope.split(' ').filter(Boolean));
}

function roles(payload) {
  const values = payload.realm_access?.roles;
  if (!Array.isArray(values) || !values.every((item) => typeof item === 'string')) {
    return new Set();
  }
  return new Set(values);
}

function validateClaims(payload, {issuer, resource, requiredScope, requiredRole, clockSkewSeconds, now}) {
  const currentTime = Math.floor(now());
  if (
    payload.iss !== issuer ||
    !audiences(payload).includes(resource) ||
    typeof payload.sub !== 'string' ||
    payload.sub.length === 0 ||
    !Number.isInteger(payload.iat) ||
    !Number.isInteger(payload.exp) ||
    payload.iat > currentTime + clockSkewSeconds ||
    payload.exp <= currentTime - clockSkewSeconds ||
    payload.exp <= payload.iat ||
    (payload.nbf !== undefined && (!Number.isInteger(payload.nbf) || payload.nbf > currentTime + clockSkewSeconds))
  ) {
    throw authorizationError();
  }
  if (!scopes(payload).has(requiredScope)) {
    throw authorizationError(403, 'INSUFFICIENT_SCOPE');
  }
  if (!roles(payload).has(requiredRole)) {
    throw authorizationError(403, 'INSUFFICIENT_ROLE');
  }
  if (payload.email !== undefined && (typeof payload.email !== 'string' || payload.email.length === 0)) {
    throw authorizationError();
  }
  return {
    id: payload.sub,
    email: payload.email,
    roles: [...roles(payload)],
    scope: [...scopes(payload)],
  };
}

export function createOAuthVerifier({
  issuer,
  resource,
  jwksUrl,
  requiredScope = 'mcp:tools',
  requiredRole = 'power-wiki-operator',
  fetchImpl = globalThis.fetch,
  now = () => Date.now() / 1000,
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
  jwksCacheSeconds = DEFAULT_JWKS_CACHE_SECONDS,
}) {
  requireString(issuer, 'ISSUER');
  requireString(resource, 'RESOURCE');
  requireString(jwksUrl, 'JWKS_URL');
  requireString(requiredScope, 'SCOPE');
  requireString(requiredRole, 'ROLE');
  if (typeof fetchImpl !== 'function') {
    throw new Error('INVALID_FETCH');
  }
  if (!Number.isInteger(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > 30) {
    throw new Error('INVALID_CLOCK_SKEW');
  }
  if (!Number.isInteger(jwksCacheSeconds) || jwksCacheSeconds < 1 || jwksCacheSeconds > 3600) {
    throw new Error('INVALID_JWKS_CACHE');
  }

  let cachedAt = 0;
  let cachedKeys = new Map();

  async function loadKeys(force = false) {
    const currentTime = Math.floor(now());
    if (!force && cachedKeys.size > 0 && currentTime - cachedAt < jwksCacheSeconds) {
      return cachedKeys;
    }
    let response;
    try {
      response = await fetchImpl(jwksUrl, {headers: {Accept: 'application/json'}, signal: AbortSignal.timeout(5000)});
    } catch {
      throw authorizationError(503, 'OAUTH_KEYS_UNAVAILABLE');
    }
    if (!response.ok) {
      throw authorizationError(503, 'OAUTH_KEYS_UNAVAILABLE');
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw authorizationError(503, 'OAUTH_KEYS_UNAVAILABLE');
    }
    if (!Array.isArray(payload?.keys)) {
      throw authorizationError(503, 'OAUTH_KEYS_UNAVAILABLE');
    }
    const keys = new Map();
    for (const key of payload.keys) {
      if (key?.kty === 'RSA' && key.use === 'sig' && key.alg === 'RS256' && typeof key.kid === 'string' && key.kid) {
        keys.set(key.kid, key);
      }
    }
    if (keys.size === 0) {
      throw authorizationError(503, 'OAUTH_KEYS_UNAVAILABLE');
    }
    cachedAt = currentTime;
    cachedKeys = keys;
    return cachedKeys;
  }

  async function verifyToken(token) {
    const segments = token.split('.');
    if (segments.length !== 3) {
      throw authorizationError();
    }
    const [protectedSegment, payloadSegment, signatureSegment] = segments;
    const protectedHeader = decodeJsonObject(protectedSegment);
    if (
      protectedHeader.alg !== 'RS256' ||
      typeof protectedHeader.kid !== 'string' ||
      protectedHeader.kid.length === 0 ||
      (protectedHeader.typ !== undefined && protectedHeader.typ !== 'JWT') ||
      protectedHeader.crit !== undefined ||
      protectedHeader.b64 !== undefined
    ) {
      throw authorizationError();
    }
    let keys = await loadKeys();
    let jwk = keys.get(protectedHeader.kid);
    if (!jwk) {
      keys = await loadKeys(true);
      jwk = keys.get(protectedHeader.kid);
    }
    if (!jwk) {
      throw authorizationError();
    }
    let signatureValid = false;
    try {
      signatureValid = verifySignature(
        'RSA-SHA256',
        Buffer.from(`${protectedSegment}.${payloadSegment}`, 'utf8'),
        createPublicKey({key: jwk, format: 'jwk'}),
        decodeBase64Url(signatureSegment),
      );
    } catch {
      throw authorizationError();
    }
    if (!signatureValid) {
      throw authorizationError();
    }
    return validateClaims(decodeJsonObject(payloadSegment), {
      issuer,
      resource,
      requiredScope,
      requiredRole,
      clockSkewSeconds,
      now,
    });
  }

  return {
    authenticate(headers) {
      return verifyToken(bearerToken(headers));
    },
  };
}

export function bearerChallenge(metadataUrl, requiredScope = 'mcp:tools') {
  return `Bearer resource_metadata="${metadataUrl}", scope="${requiredScope}"`;
}
