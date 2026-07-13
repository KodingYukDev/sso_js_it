# KodingYuk Accounts Web

Web register/login dan OpenID Connect Provider untuk
`https://account.kodingyuk.id`. Service ini melayani akun publik KodingYuk,
sementara data akun, consent, student link, dan audit log disimpan oleh addon
Odoo pada repository
[`KodingYukDev/sso_odoo_it`](https://github.com/KodingYukDev/sso_odoo_it).

## Fitur V1

- Register dan verifikasi email.
- Login serta lupa/reset password.
- OpenID Connect Authorization Code + PKCE S256.
- Session dan token persistence menggunakan Redis.
- Consent serta optional claim kode siswa.
- Audit event register/login/verification/reset/OIDC dikirim ke Odoo.
- Rate limiting, same-origin protection, secure cookie, dan production config
  validation.

## Development

Prasyarat: Node.js 22 LTS atau lebih baru.

```powershell
Copy-Item .env.example .env
npm ci
npm test
npm run dev
```

Discovery OIDC tersedia di
`http://localhost:3000/.well-known/openid-configuration`.

## Production

Production membutuhkan:

- Addon `kodingyuk_accounts` yang sudah terpasang di Odoo 17.
- Secret API yang sama dengan `accounts.api_key` di Odoo.
- Redis persisten.
- HTTPS pada exact origin `account.kodingyuk.id`.
- Private signing JWKS yang disimpan di secret manager.
- Minimal dua cookie signing key.
- URL Ketentuan Layanan dan Kebijakan Privasi.

Generate signing key sekali lalu simpan output sebagai secret `OIDC_JWKS`:

```powershell
npm run generate:jwks
```

Deploy menggunakan Docker Compose:

```powershell
Copy-Item .env.example .env
docker compose up -d --build
```

Jangan commit `.env`, signing JWKS, API key, atau credential Redis/Odoo.

## Dokumentasi

- [Deployment](docs/DEPLOYMENT.md)
- [Integrasi Produk](docs/PRODUCT-INTEGRATION.md)
