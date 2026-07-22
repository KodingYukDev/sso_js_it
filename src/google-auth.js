import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const COOKIE_NAME = 'ky_google_oauth';
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
const STATE_TTL_MS = 10 * 60 * 1000;

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sign(value, key) {
  return createHmac('sha256', key).update(value).digest('base64url');
}

function encodeStateCookie(payload, keys) {
  const body = base64urlJson(payload);
  return `${body}.${sign(body, keys[0])}`;
}

function decodeStateCookie(raw, keys) {
  const [body, signature] = String(raw || '').split('.');
  if (!body || !signature) return null;
  const signatureBuffer = Buffer.from(signature);
  const valid = keys.some((key) => {
    const expected = Buffer.from(sign(body, key));
    return expected.length === signatureBuffer.length && timingSafeEqual(expected, signatureBuffer);
  });
  if (!valid) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.expiresAt || payload.expiresAt < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function cookieOptions(config) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.NODE_ENV === 'production',
    path: '/auth/google/callback',
    maxAge: STATE_TTL_MS,
  };
}

export function isGoogleConfigured(config) {
  return Boolean(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET);
}

export function buildGoogleAuthorizationUrl({ config, uid }) {
  if (!isGoogleConfigured(config)) throw new Error('Google SSO belum dikonfigurasi.');
  const state = randomBytes(32).toString('base64url');
  const nonce = randomBytes(32).toString('base64url');
  const url = new URL(GOOGLE_AUTH_URL);
  url.search = new URLSearchParams({
    client_id: config.GOOGLE_CLIENT_ID,
    redirect_uri: config.googleRedirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    prompt: 'select_account',
  });
  const cookie = encodeStateCookie({ state, nonce, uid, expiresAt: Date.now() + STATE_TTL_MS }, config.cookieKeys);
  return { url, cookie };
}

export function setGoogleStateCookie(res, config, value) {
  res.cookie(COOKIE_NAME, value, cookieOptions(config));
}

export function clearGoogleStateCookie(res, config) {
  res.clearCookie(COOKIE_NAME, { ...cookieOptions(config), maxAge: undefined });
}

export function readGoogleStateCookie(req, config) {
  const raw = String(req.headers.cookie || '')
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE_NAME}=`))
    ?.slice(COOKIE_NAME.length + 1);
  return decodeStateCookie(raw ? decodeURIComponent(raw) : '', config.cookieKeys);
}

export async function exchangeGoogleCode(config, code) {
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: config.GOOGLE_CLIENT_ID,
      client_secret: config.GOOGLE_CLIENT_SECRET,
      redirect_uri: config.googleRedirectUri,
      grant_type: 'authorization_code',
    }),
  });
  if (!response.ok) throw new Error('Google token exchange gagal.');
  return response.json();
}

export async function verifyGoogleIdToken(config, idToken, nonce) {
  const { payload } = await jwtVerify(idToken, GOOGLE_JWKS, {
    issuer: ['https://accounts.google.com', 'accounts.google.com'],
    audience: config.GOOGLE_CLIENT_ID,
  });
  if (payload.nonce !== nonce) throw new Error('Google nonce tidak valid.');
  if (!payload.sub) throw new Error('Google subject tidak tersedia.');
  if (!payload.email || payload.email_verified !== true) {
    throw new Error('Email Google harus terverifikasi.');
  }
  return payload;
}
