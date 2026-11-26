import {createHmac, timingSafeEqual} from 'node:crypto';

export const CONTEXTFORGE_IDENTITY_ISSUER = 'mcpgateway-identity-propagation';

const AUTHENTICATION_ERROR = 'AUTHENTICATION_REQUIRED';
const MAX_TOKEN_TTL_SECONDS = 60;
const DEFAULT_CLOCK_SKEW_SECONDS = 5;

function authenticationError() {
  return new Error(AUTHENTICATION_ERROR);
}

function requireNonEmptyString(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw authenticationError();
  }
  return value;
}

function constantTimeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function headerValue(headers, name) {
  const value = headers?.[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw authenticationError();
  }
  return value;
}

function decodeBase64Url(segment) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw authenticationError();
  }
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.length === 0 || decoded.toString('base64url') !== segment) {
    throw authenticationError();
  }
  return decoded;
}

function decodeJsonObject(segment) {
  let value;
  try {
    value = JSON.parse(decodeBase64Url(segment).toString('utf8'));
  } catch {
    throw authenticationError();
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authenticationError();
  }
  return value;
}

function validateOptionalClaims(payload) {
  for (const key of ['email', 'full_name', 'auth_method', 'service_account']) {
    if (payload[key] !== undefined && (typeof payload[key] !== 'string' || payload[key].length === 0)) {
      throw authenticationError();
    }
  }
  for (const key of ['groups', 'teams', 'roles', 'delegation_chain']) {
    if (
      payload[key] !== undefined &&
      (!Array.isArray(payload[key]) || payload[key].length === 0 || payload[key].some((item) => typeof item !== 'string' || item.length === 0))
    ) {
      throw authenticationError();
    }
  }
  if (typeof payload.is_admin !== 'boolean') {
    throw authenticationError();
  }
}

function verifyClaimsToken(token, {identityKey, audience, issuer, clockSkewSeconds, now}) {
  if (typeof token !== 'string') {
    throw authenticationError();
  }
  const segments = token.split('.');
  if (segments.length !== 3) {
    throw authenticationError();
  }

  const [protectedSegment, payloadSegment, signatureSegment] = segments;
  const protectedHeader = decodeJsonObject(protectedSegment);
  if (
    protectedHeader.alg !== 'HS256' ||
    (protectedHeader.typ !== undefined && protectedHeader.typ !== 'JWT') ||
    protectedHeader.crit !== undefined ||
    protectedHeader.b64 !== undefined
  ) {
    throw authenticationError();
  }

  const actualSignature = decodeBase64Url(signatureSegment);
  const expectedSignature = createHmac('sha256', identityKey)
    .update(`${protectedSegment}.${payloadSegment}`)
    .digest();
  if (actualSignature.length !== expectedSignature.length || !timingSafeEqual(actualSignature, expectedSignature)) {
    throw authenticationError();
  }

  const payload = decodeJsonObject(payloadSegment);
  const currentTime = Math.floor(now());
  if (
    payload.iss !== issuer ||
    payload.aud !== audience ||
    !Number.isInteger(payload.iat) ||
    !Number.isInteger(payload.exp) ||
    payload.iat > currentTime + clockSkewSeconds ||
    payload.exp <= currentTime - clockSkewSeconds ||
    payload.exp <= payload.iat ||
    payload.exp - payload.iat > MAX_TOKEN_TTL_SECONDS ||
    typeof payload.jti !== 'string' ||
    !/^[0-9a-f]{32}$/.test(payload.jti) ||
    typeof payload.id !== 'string' ||
    payload.id.length === 0
  ) {
    throw authenticationError();
  }
  validateOptionalClaims(payload);
  return payload;
}

function metaClaimsToken(body) {
  const user = body?.params?._meta?.user;
  if (user === undefined) {
    return undefined;
  }
  if (user === null || typeof user !== 'object' || Array.isArray(user)) {
    throw authenticationError();
  }
  const token = user.claims_signature;
  if (token !== undefined && typeof token !== 'string') {
    throw authenticationError();
  }
  return token;
}

export function createIdentityVerifier({
  serviceToken,
  identityKey,
  audience,
  issuer = CONTEXTFORGE_IDENTITY_ISSUER,
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
  now = () => Date.now() / 1000,
}) {
  requireNonEmptyString(serviceToken);
  requireNonEmptyString(identityKey);
  requireNonEmptyString(audience);
  requireNonEmptyString(issuer);
  if (serviceToken.length < 32 || identityKey.length < 32) {
    throw new Error('INVALID_SECRET');
  }
  if (!Number.isInteger(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > 30) {
    throw new Error('INVALID_CLOCK_SKEW');
  }

  return {
    authenticateService(headers) {
      if (!constantTimeEqual(headerValue(headers, 'authorization'), `Bearer ${serviceToken}`)) {
        throw authenticationError();
      }
    },

    resolveIdentity(headers, body) {
      // A pooled ContextForge session removes the expiring HTTP signature.
      // It places a fresh request JWS in params._meta.user.
      // Prefer the request JWS when it is present.
      // Never use plaintext X-Forwarded-User-* headers for authorization.
      const requestToken = metaClaimsToken(body);
      const headerToken = headerValue(headers, 'x-forwarded-user-claims-signature');
      if (requestToken === undefined && headerToken === undefined) {
        return null;
      }
      const verificationOptions = {
        identityKey,
        audience,
        issuer,
        clockSkewSeconds,
        now,
      };
      const requestClaims = requestToken === undefined ? undefined : verifyClaimsToken(requestToken, verificationOptions);
      const headerClaims = headerToken === undefined ? undefined : verifyClaimsToken(headerToken, verificationOptions);
      if (requestClaims && headerClaims) {
        for (const key of ['id', 'email', 'full_name', 'groups', 'teams', 'roles', 'is_admin', 'auth_method', 'service_account', 'delegation_chain']) {
          if (JSON.stringify(requestClaims[key]) !== JSON.stringify(headerClaims[key])) {
            throw authenticationError();
          }
        }
      }
      return requestClaims ?? headerClaims;
    },
  };
}
