import assert from 'node:assert/strict';
import test from 'node:test';

import { loadConfig } from '../src/config.js';

test('development configuration has safe parsed defaults', () => {
  const config = loadConfig({});
  assert.equal(config.publicOrigin, 'http://localhost:3000');
  assert.deepEqual(config.fallbackClients, []);
  assert.equal(config.NODE_ENV, 'development');
  assert.equal(config.googleEnabled, false);
  assert.equal(config.googleRedirectUri, 'http://localhost:3000/auth/google/callback');
});

test('google configuration enables upstream SSO', () => {
  const config = loadConfig({
    PUBLIC_ORIGIN: 'https://account.kodingyuk.id',
    GOOGLE_CLIENT_ID: 'google-client',
    GOOGLE_CLIENT_SECRET: 'google-secret',
  });
  assert.equal(config.googleEnabled, true);
  assert.equal(config.googleRedirectUri, 'https://account.kodingyuk.id/auth/google/callback');
});

test('production requires persistent Redis and signing keys', () => {
  assert.throws(() => loadConfig({
    NODE_ENV: 'production',
    PUBLIC_ORIGIN: 'https://account.kodingyuk.id',
    ODOO_ACCOUNTS_API_KEY: 'secret',
    COOKIE_KEYS: `${'a'.repeat(32)},${'b'.repeat(32)}`,
  }), /REDIS_URL/);
});
