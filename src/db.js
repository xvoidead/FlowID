import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { config } from './config.js';

mkdirSync(config.dataDir, { recursive: true });

export const db = new DatabaseSync(join(config.dataDir, 'flowid.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  password_hash   TEXT,
  name            TEXT NOT NULL DEFAULT '',
  username        TEXT UNIQUE,
  avatar_url      TEXT,
  disabled        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
  id               TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider         TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  email            TEXT,
  display_name     TEXT,
  avatar_url       TEXT,
  profile_url      TEXT,
  created_at       INTEGER NOT NULL,
  UNIQUE (provider, provider_user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL UNIQUE,
  ip           TEXT,
  user_agent   TEXT,
  method       TEXT NOT NULL DEFAULT 'password',
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  revoked_at   INTEGER
);

CREATE TABLE IF NOT EXISTS email_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id      TEXT PRIMARY KEY,
  secret_hash    TEXT,
  name           TEXT NOT NULL,
  description    TEXT NOT NULL DEFAULT '',
  logo_url       TEXT,
  website        TEXT,
  owner_user_id  TEXT REFERENCES users(id) ON DELETE CASCADE,
  redirect_uris  TEXT NOT NULL,
  scopes         TEXT NOT NULL DEFAULT 'openid profile email',
  is_public      INTEGER NOT NULL DEFAULT 0,
  is_trusted     INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash             TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id            TEXT,
  redirect_uri          TEXT NOT NULL,
  scope                 TEXT NOT NULL,
  nonce                 TEXT,
  code_challenge        TEXT,
  code_challenge_method TEXT,
  expires_at            INTEGER NOT NULL,
  used_at               INTEGER,
  created_at            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,
  parent_id  TEXT,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_grants (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS auth_requests (
  id         TEXT PRIMARY KEY,
  client_id  TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  params     TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ext_states (
  state        TEXT PRIMARY KEY,
  provider     TEXT NOT NULL,
  verifier     TEXT NOT NULL,
  next_url     TEXT,
  link_user_id TEXT,
  expires_at   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT,
  event      TEXT NOT NULL,
  detail     TEXT,
  ip         TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user   ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_user     ON oauth_tokens(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_identities_user ON identities(user_id);
CREATE INDEX IF NOT EXISTS idx_clients_owner   ON oauth_clients(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user      ON audit_log(user_id, created_at);
`);

export const now = () => Date.now();

export const one = (sql, ...params) => db.prepare(sql).get(...params) ?? null;
export const all = (sql, ...params) => db.prepare(sql).all(...params);
export const run = (sql, ...params) => db.prepare(sql).run(...params);

export function audit(event, { userId = null, detail = null, ip = null } = {}) {
  run('INSERT INTO audit_log (user_id, event, detail, ip, created_at) VALUES (?,?,?,?,?)',
    userId, event, detail ? JSON.stringify(detail) : null, ip, now());
}

/** Периодическая уборка просроченных записей. */
export function sweepExpired() {
  const t = now();
  run('DELETE FROM oauth_codes  WHERE expires_at < ?', t - 60_000);
  run('DELETE FROM ext_states    WHERE expires_at < ?', t);
  run('DELETE FROM auth_requests WHERE expires_at < ?', t);
  run('DELETE FROM email_tokens WHERE expires_at < ?', t - 86_400_000);
  run('DELETE FROM oauth_tokens WHERE expires_at < ? AND kind = ?', t - 86_400_000, 'access');
  run('DELETE FROM sessions     WHERE expires_at < ?', t - 86_400_000);
}
