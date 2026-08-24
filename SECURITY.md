# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately to the maintainers. Do not open a public issue for sensitive reports.

Include: affected version, reproduction steps, impact, and any PoC (encrypted if possible).

## Security Measures

- All traffic is routed through Tor (`arti-client`); no clearnet fallback.
- ECIES encryption (secp256k1, AES-256-CBC + HMAC-SHA256, constant-time verification).
- Private keys stored encrypted on disk (AES-256-CBC + HMAC-SHA256, Argon2id KDF with per-DB random 16-byte salt stored in `settings.kdf_salt`, params m=19456 KiB, t=2, p=1; legacy 200k SHA-256 KDF supported for migration via `migrate_to_argon2id`). Secrets are `Zeroizing`/`ZeroizeOnDrop` in memory (`KeyPair`, `session_key`). DB file is `0600`, data dir `0700`.
- Proof-of-Work verified before storage/relay; payload sizes bounded to prevent OOM.
- Protocol parsers enforce strict limits (`MAX_VARSTR 1MiB`, `MAX_VARINT_LIST 1024`, `MAX_PAYLOAD 1.6MiB`, `x_len==32 && y_len==32`).
- Attachments capped at 10 MiB / 64 chunks, filenames sanitized.

## Hardening Checklist (implemented)

- [x] Tor-only networking, no DNS leak (hostnames resolved via Tor)
- [x] Parametrized SQL via `rusqlite`
- [x] No `unsafe` code (`#![forbid(unsafe_code)]` lint)
- [x] `cargo audit` / `cargo deny` in CI (pins updated via `cargo update`)
- [x] Authenticated encryption for local DB (Encrypt-then-MAC)
- [x] File permissions 0600/0700 for DB and data dir
- [x] Argon2id with per-DB salt, Zeroizing secrets on drop

## Recommended Deployment

- Use a strong password (>12 chars) to encrypt identities.
- Keep dependencies updated (`cargo audit` weekly via CI).
- Run under an unprivileged user; filesystem isolated.
