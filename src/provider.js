import { exportJWK, generateKeyPair } from 'jose';
import Provider from 'oidc-provider';

async function developmentJwks() {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const key = await exportJWK(privateKey);
  return { keys: [{ ...key, use: 'sig', alg: 'RS256', kid: `dev-${Date.now()}` }] };
}

function attachAuditEvents(provider, odoo, logger) {
  const mappings = [
    ['authorization.success', 'oidc.authorization_succeeded', 'success'],
    ['authorization.error', 'oidc.authorization_failed', 'failure'],
    ['grant.success', 'oidc.token_issued', 'success'],
    ['grant.error', 'oidc.token_failed', 'failure'],
    ['end_session.success', 'oidc.logout_succeeded', 'success'],
  ];
  for (const [providerEvent, auditEvent, outcome] of mappings) {
    provider.on(providerEvent, (ctx, error) => {
      if (typeof odoo.audit !== 'function') return;
      const oidc = ctx?.oidc;
      const entities = oidc?.entities || {};
      const subjectUuid = oidc?.account?.accountId
        || oidc?.session?.accountId
        || entities.AccessToken?.accountId
        || entities.AuthorizationCode?.accountId
        || entities.RefreshToken?.accountId
        || '';
      const clientId = oidc?.client?.clientId
        || oidc?.params?.client_id
        || entities.Client?.clientId
        || '';
      const headers = ctx?.req?.headers || {};
      void odoo.audit({
        event: auditEvent,
        outcome,
        subjectUuid,
        clientId,
        details: error ? { error: error.error || error.name || 'oidc_error' } : {},
        context: {
          request_id: headers['x-request-id'] || '',
          ip_address: ctx?.request?.ip || '',
          user_agent: headers['user-agent'] || '',
          source: 'oidc_provider',
          client_id: clientId,
        },
      }).catch((auditError) => logger.warn(`OIDC audit event could not be recorded: ${auditError.message}`));
    });
  }
}

async function autoSubmitLogoutSource(ctx, form) {
  const confirmedForm = form.replace('</form>', '<input type="hidden" name="logout" value="yes"/></form>');
  ctx.set('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  ctx.type = 'html';
  ctx.body = `<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Keluar</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;background:#f4f8ff;color:#10254b}.card{width:min(360px,calc(100vw - 32px));padding:28px;border:1px solid #dce6f3;border-radius:18px;background:#fff;text-align:center;box-shadow:0 18px 45px #092b6314}h1{font-size:22px;margin:0 0 8px}p{margin:0 0 18px;color:#64748b;line-height:1.5}.button{display:inline-flex;justify-content:center;width:100%;border:0;border-radius:13px;padding:13px 18px;font:inherit;font-weight:900;cursor:pointer;background:#246bfd;color:white}</style></head><body><main class="card"><h1>Keluar dari Account</h1><p>Sesi sedang ditutup. Jika tidak berpindah otomatis, tekan tombol lanjut.</p>${confirmedForm}<button class="button" type="submit" form="op.logoutForm" name="logout" value="yes">Lanjut keluar</button></main><script>document.getElementById('op.logoutForm').submit();</script></body></html>`;
}

async function postLogoutSuccessSource(ctx) {
  ctx.type = 'html';
  ctx.body = '<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Sudah Keluar</title></head><body>Anda sudah keluar dari KodingYuk Account.</body></html>';
}

export async function loadClients(odoo, fallbackClients, logger = console) {
  let registryClients = [];
  try {
    registryClients = await odoo.clients();
  } catch (error) {
    logger.warn(`OIDC client registry in Odoo unavailable: ${error.message}`);
  }

  const byClientId = new Map();
  for (const client of fallbackClients) byClientId.set(client.client_id, client);
  for (const client of registryClients) byClientId.set(client.client_id, client);

  const clients = [...byClientId.values()];
  if (clients.length) return clients;
  throw new Error('No active OIDC clients are configured in Odoo or OIDC_CLIENTS_JSON');
}

export async function createProvider({ config, odoo, adapter, logger = console }) {
  const clients = await loadClients(odoo, config.fallbackClients, logger);
  const jwks = config.jwks || await developmentJwks();
  if (!config.jwks) logger.warn('Using an ephemeral development signing key; sessions will not survive restart.');

  const provider = new Provider(config.publicOrigin, {
    adapter,
    clients,
    jwks,
    cookies: {
      keys: config.cookieKeys,
      long: { signed: true, httpOnly: true, sameSite: 'lax', secure: config.productionLike },
      short: { signed: true, httpOnly: true, sameSite: 'lax', secure: config.productionLike },
    },
    claims: {
      openid: ['sub'],
      profile: ['name', 'preferred_username', 'locale', 'zoneinfo', 'account_type'],
      email: ['email', 'email_verified'],
      'student.basic': ['is_student'],
    },
    scopes: ['openid', 'profile', 'email', 'offline_access', 'student.basic'],
    responseTypes: ['code'],
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: autoSubmitLogoutSource,
        postLogoutSuccessSource,
      },
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    findAccount: async (_ctx, subject) => {
      try {
        const { account } = await odoo.claims(subject);
        return { accountId: account.sub, claims: async () => account };
      } catch (error) {
        logger.warn(`Account claims unavailable for ${subject}: ${error.message}`);
        return undefined;
      }
    },
    routes: {
      authorization: '/oauth/authorize',
      token: '/oauth/token',
      userinfo: '/oauth/userinfo',
      jwks: '/oauth/jwks',
      revocation: '/oauth/revoke',
      end_session: '/oauth/logout',
      introspection: '/oauth/introspect',
      registration: '/oauth/register',
      device_authorization: '/oauth/device/auth',
      code_verification: '/oauth/device',
      pushed_authorization_request: '/oauth/request',
      backchannel_authentication: '/oauth/backchannel',
      challenge: '/oauth/challenge',
    },
    ttl: {
      AccessToken: 60 * 15,
      AuthorizationCode: 60,
      Grant: 60 * 60 * 24 * 14,
      IdToken: 60 * 15,
      Interaction: 60 * 10,
      RefreshToken: 60 * 60 * 24 * 30,
      Session: 60 * 60 * 12,
    },
  });
  provider.proxy = config.TRUST_PROXY > 0;
  attachAuditEvents(provider, odoo, logger);
  return provider;
}
