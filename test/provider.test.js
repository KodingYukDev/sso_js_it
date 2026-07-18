import assert from 'node:assert/strict';
import test from 'node:test';

import { loadClients } from '../src/provider.js';

test('OIDC clients from Odoo override and merge with fallback clients', async () => {
  const clients = await loadClients(
    {
      clients: async () => [{
        client_id: 'kodingyuk-library',
        client_name: 'Library from Odoo',
        redirect_uris: ['https://library.kodingyuk.id/api/auth/callback/kodingyuk'],
      }],
    },
    [
      {
        client_id: 'kodingyuk-library',
        client_name: 'Library fallback',
        redirect_uris: ['http://localhost:3000/api/auth/callback/kodingyuk'],
      },
      {
        client_id: 'emergency-client',
        client_name: 'Emergency fallback',
        redirect_uris: ['https://emergency.example.test/callback'],
      },
    ],
  );

  assert.equal(clients.length, 2);
  assert.equal(
    clients.find((client) => client.client_id === 'kodingyuk-library').client_name,
    'Library from Odoo',
  );
  assert.ok(clients.some((client) => client.client_id === 'emergency-client'));
});
