import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import test from 'node:test';

import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createProvider } from '../src/provider.js';

function base64url(value) { return value.toString('base64url'); }

test('authorization code + PKCE completes without exposing an Odoo session', async (t) => {
  const port = 32000 + Math.floor(Math.random() * 1000);
  const origin = `http://localhost:${port}`;
  const callback = 'http://localhost:4000/callback';
  const account = {
    sub: '0ed352c9-589b-4f67-80dd-d804ff599eca', name: 'Siswa Demo',
    preferred_username: 'siswa.demo', email: 'siswa@example.test',
    email_verified: false, account_type: 'public', is_student: false,
    locale: 'id_ID', zoneinfo: 'Asia/Jakarta',
  };
  const audits = [];
  const odoo = {
    clients: async () => [{
      client_id: 'integration-test', client_name: 'Integration Test',
      redirect_uris: [callback], response_types: ['code'],
      post_logout_redirect_uris: ['http://localhost:4000/logout'],
      grant_types: ['authorization_code'], token_endpoint_auth_method: 'none',
    }],
    authenticate: async () => ({ account }),
    claims: async () => ({ account }),
    claimStudent: async () => ({ claim: { status: 'pending' } }),
    audit: async (entry) => { audits.push(entry); },
  };
  const config = loadConfig({
    NODE_ENV: 'test', PORT: String(port), PUBLIC_ORIGIN: origin,
    ODOO_BASE_URL: 'http://odoo.test', ODOO_ACCOUNTS_API_KEY: 'test-key',
    COOKIE_KEYS: 'test-cookie-key-one,test-cookie-key-two', OIDC_CLIENTS_JSON: '[]',
  });
  const logger = { warn() {}, error() {}, log() {} };
  const provider = await createProvider({ config, odoo, logger });
  const app = createApp({ config, odoo, provider, logger });
  const server = app.listen(port);
  await once(server, 'listening');
  t.after(() => server.close());

  const cookies = new Map();
  async function request(url, options = {}) {
    const cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    const response = await fetch(new URL(url, origin), {
      redirect: 'manual', ...options,
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(options.headers || {}) },
    });
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(';');
      const index = pair.indexOf('=');
      cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return response;
  }

  const verifier = base64url(randomBytes(48));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  const authorize = new URL('/oauth/authorize', origin);
  authorize.search = new URLSearchParams({
    client_id: 'integration-test', redirect_uri: callback, response_type: 'code',
    scope: 'openid profile email student.basic', state: 'fixed-state', nonce: 'fixed-nonce',
    code_challenge: challenge, code_challenge_method: 'S256',
  });

  let response = await request(authorize);
  assert.ok([302, 303].includes(response.status));
  let location = response.headers.get('location');
  assert.match(location, /^\/interaction\//);

  response = await request(location);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Selamat datang kembali/);

  response = await request(`${location}/login`, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ identifier: 'siswa@example.test', password: 'valid-password' }),
  });
  assert.equal(response.status, 303);
  location = response.headers.get('location');

  response = await request(location);
  assert.ok([302, 303].includes(response.status));
  location = response.headers.get('location');
  assert.match(location, /^\/interaction\//);

  response = await request(location);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Persetujuan akses/);

  response = await request(`${location}/confirm`, {
    method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(response.status, 303);
  location = response.headers.get('location');

  response = await request(location);
  assert.ok([302, 303].includes(response.status));
  const callbackUrl = new URL(response.headers.get('location'));
  assert.equal(callbackUrl.origin + callbackUrl.pathname, callback);
  assert.equal(callbackUrl.searchParams.get('state'), 'fixed-state');
  const code = callbackUrl.searchParams.get('code');
  assert.ok(code);

  response = await request('/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: 'integration-test', code,
      redirect_uri: callback, code_verifier: verifier,
    }),
  });
  assert.equal(response.status, 200);
  const tokens = await response.json();
  assert.equal(tokens.token_type, 'Bearer');
  assert.ok(tokens.access_token);
  assert.ok(tokens.id_token);
  assert.equal('session_id' in tokens, false);
  assert.ok(audits.some((entry) => entry.event === 'oidc.authorization_succeeded'));
  assert.ok(audits.some((entry) => entry.event === 'oidc.token_issued'));

  const nextVerifier = base64url(randomBytes(48));
  const nextChallenge = base64url(createHash('sha256').update(nextVerifier).digest());
  const nextAuthorize = new URL('/oauth/authorize', origin);
  nextAuthorize.search = new URLSearchParams({
    client_id: 'integration-test', redirect_uri: callback, response_type: 'code',
    scope: 'openid profile email student.basic', state: 'next-state', nonce: 'next-nonce',
    code_challenge: nextChallenge, code_challenge_method: 'S256',
  });

  response = await request(nextAuthorize);
  assert.ok([302, 303].includes(response.status));
  location = response.headers.get('location');
  const nextCallbackUrl = new URL(location);
  assert.equal(nextCallbackUrl.origin + nextCallbackUrl.pathname, callback);
  assert.equal(nextCallbackUrl.searchParams.get('state'), 'next-state');
  assert.ok(nextCallbackUrl.searchParams.get('code'));

  const logoutUrl = new URL('/oauth/logout', origin);
  logoutUrl.search = new URLSearchParams({
    client_id: 'integration-test',
    id_token_hint: tokens.id_token,
    post_logout_redirect_uri: 'http://localhost:4000/logout',
  });
  response = await request(logoutUrl);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-security-policy'), /script-src 'unsafe-inline'/);
  const logoutHtml = await response.text();
  assert.match(logoutHtml, /name="logout" value="yes"/);
  assert.match(logoutHtml, /Lanjut keluar/);
  const logoutAction = logoutHtml.match(/<form id="op\.logoutForm" method="post" action="([^"]+)"/)?.[1];
  const xsrf = logoutHtml.match(/name="xsrf" value="([^"]+)"/)?.[1];
  assert.ok(logoutAction);
  assert.ok(xsrf);

  response = await request(logoutAction, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ xsrf, logout: 'yes' }),
  });
  assert.ok([302, 303].includes(response.status));
  assert.equal(response.headers.get('location'), 'http://localhost:4000/logout');
});

test('consent confirmation recreates missing grants and normalizes scopes', async (t) => {
  const port = 33000 + Math.floor(Math.random() * 1000);
  const origin = `http://localhost:${port}`;
  const grants = [];
  class TestGrant {
    constructor({ accountId, clientId }) {
      this.accountId = accountId;
      this.clientId = clientId;
      this.oidcScopes = [];
      this.oidcClaims = [];
      this.resourceScopes = [];
    }

    addOIDCScope(scope) { this.oidcScopes.push(scope); }
    addOIDCClaims(claims) { this.oidcClaims.push(...claims); }
    addResourceScope(indicator, scope) { this.resourceScopes.push([indicator, scope]); }
    async save() { grants.push(this); return 'new-grant-id'; }
    static async find() { return null; }
  }
  const config = loadConfig({
    NODE_ENV: 'test', PORT: String(port), PUBLIC_ORIGIN: origin,
    ODOO_BASE_URL: 'http://odoo.test', ODOO_ACCOUNTS_API_KEY: 'test-key',
    COOKIE_KEYS: 'test-cookie-key-one,test-cookie-key-two', OIDC_CLIENTS_JSON: '[]',
  });
  const logger = { warn() {}, error() {}, log() {} };
  const provider = {
    Grant: TestGrant,
    interactionDetails: async () => ({
      prompt: {
        name: 'consent',
        details: {
          missingOIDCScope: new Set(['profile', 'email']),
          missingOIDCClaims: 'email_verified',
          missingResourceScopes: { 'https://api.example.test': 'student.basic' },
        },
      },
      grantId: 'stale-grant-id',
      session: { accountId: '4c321528-d54e-44c0-b455-4a45b039f1f0' },
      params: { client_id: 'integration-test' },
    }),
    interactionFinished: async (_req, res, result) => res.status(303).json(result),
    callback: () => (_req, res) => res.status(404).end(),
  };
  const odoo = {};
  const app = createApp({ config, odoo, provider, logger });
  const server = app.listen(port);
  await once(server, 'listening');
  t.after(() => server.close());

  const response = await fetch(new URL('/interaction/test-uid/confirm', origin), {
    redirect: 'manual',
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(response.status, 303);
  assert.equal(grants.length, 1);
  assert.deepEqual(grants[0].oidcScopes, ['profile email']);
  assert.deepEqual(grants[0].oidcClaims, ['email_verified']);
  assert.deepEqual(grants[0].resourceScopes, [['https://api.example.test', 'student.basic']]);
});

test('expired consent interaction returns a restart page', async (t) => {
  const port = 34000 + Math.floor(Math.random() * 1000);
  const origin = `http://localhost:${port}`;
  const config = loadConfig({
    NODE_ENV: 'test', PORT: String(port), PUBLIC_ORIGIN: origin,
    ODOO_BASE_URL: 'http://odoo.test', ODOO_ACCOUNTS_API_KEY: 'test-key',
    COOKIE_KEYS: 'test-cookie-key-one,test-cookie-key-two', OIDC_CLIENTS_JSON: '[]',
  });
  const provider = {
    interactionDetails: async () => { throw new Error('interaction session not found'); },
    callback: () => (_req, res) => res.status(404).end(),
  };
  const logger = { warn() {}, error() {}, log() {} };
  const app = createApp({ config, odoo: {}, provider, logger });
  const server = app.listen(port);
  await once(server, 'listening');
  t.after(() => server.close());

  const response = await fetch(new URL('/interaction/expired/confirm', origin), {
    redirect: 'manual',
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(response.status, 410);
  const html = await response.text();
  assert.match(html, /Sesi masuk kedaluwarsa/);
  assert.doesNotMatch(html, /Proses masuk tidak dapat dilanjutkan/);
});

test('consent confirmation does not fall back to generic text when error rendering fails', async (t) => {
  const port = 35000 + Math.floor(Math.random() * 1000);
  const origin = `http://localhost:${port}`;
  const config = loadConfig({
    NODE_ENV: 'test', PORT: String(port), PUBLIC_ORIGIN: origin,
    ODOO_BASE_URL: 'http://odoo.test', ODOO_ACCOUNTS_API_KEY: 'test-key',
    COOKIE_KEYS: 'test-cookie-key-one,test-cookie-key-two', OIDC_CLIENTS_JSON: '[]',
  });
  class BrokenGrant {
    static async find() { return null; }
    addOIDCScope() {}
    addOIDCClaims() {}
    addResourceScope() {}
    async save() { throw new Error('grant storage unavailable'); }
  }
  const provider = {
    interactionDetails: async () => ({
      uid: 'broken',
      prompt: { name: 'consent', details: { missingOIDCScope: ['email'] } },
      session: { accountId: 'account-1' },
      params: { client_id: 'broken-client' },
    }),
    Client: { find: async () => { throw new Error('client lookup unavailable'); } },
    Grant: BrokenGrant,
    callback: () => (_req, res) => res.status(404).end(),
  };
  const logger = { warn() {}, error() {}, log() {} };
  const app = createApp({ config, odoo: {}, provider, logger });
  const server = app.listen(port);
  await once(server, 'listening');
  t.after(() => server.close());

  const response = await fetch(new URL('/interaction/broken/confirm', origin), {
    redirect: 'manual',
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(response.status, 503);
  const html = await response.text();
  assert.match(html, /Persetujuan belum diproses/);
  assert.doesNotMatch(html, /Proses masuk tidak dapat dilanjutkan/);
});
