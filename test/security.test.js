import assert from 'node:assert/strict';
import test from 'node:test';

import { sameOrigin } from '../src/app.js';
import { escapeHtml, loginView } from '../src/views.js';

function invoke(origin) {
  const middleware = sameOrigin('https://account.kodingyuk.id');
  let status;
  let sent;
  let nextCalled = false;
  middleware({ get: () => origin }, {
    status(value) { status = value; return this; }, send(value) { sent = value; return this; },
  }, () => { nextCalled = true; });
  return { status, sent, nextCalled };
}

test('HTML output escapes untrusted values', () => {
  assert.equal(escapeHtml('<script>"x"</script>'), '&lt;script&gt;&quot;x&quot;&lt;/script&gt;');
});

test('POST origin guard accepts only the configured origin', () => {
  assert.equal(invoke('https://account.kodingyuk.id/register').nextCalled, true);
  assert.equal(invoke('https://evil.example').status, 403);
  assert.equal(invoke(undefined).status, 403);
});

test('login view exposes Google SSO only when configured', () => {
  assert.match(loginView({ uid: 'abc', clientName: 'Demo', googleEnabled: true }), /Masuk dengan Google/);
  assert.doesNotMatch(loginView({ uid: 'abc', clientName: 'Demo', googleEnabled: false }), /Masuk dengan Google/);
});
