import { one, all, run, now, audit } from '../db.js';
import { newId, hashPassword, randomToken, tokenHash } from './crypto.js';
import { config } from '../config.js';
import { badRequest } from './http.js';

export const publicUser = (user) => user && ({
  id: user.id,
  email: user.email,
  email_verified: Boolean(user.email_verified),
  name: user.name,
  username: user.username,
  avatar_url: user.avatar_url,
  has_password: Boolean(user.password_hash),
  created_at: user.created_at,
});

export const findUserById = (id) => one('SELECT * FROM users WHERE id = ?', id);
export const findUserByEmail = (email) => one('SELECT * FROM users WHERE email = ?', email);
export const findUserByUsername = (username) => one('SELECT * FROM users WHERE username = ?', username);

export async function createUser({ email, password, name, username = null, avatarUrl = null, emailVerified = false }) {
  if (email && findUserByEmail(email)) {
    throw badRequest('email_taken', 'Аккаунт с такой почтой уже есть. Войдите или восстановите пароль', { field: 'email' });
  }
  if (username && findUserByUsername(username)) {
    throw badRequest('username_taken', 'Этот ник уже занят', { field: 'username' });
  }
  const t = now();
  const user = {
    id: newId('usr'),
    email,
    email_verified: emailVerified ? 1 : 0,
    password_hash: password ? await hashPassword(password) : null,
    name,
    username,
    avatar_url: avatarUrl,
    created_at: t,
    updated_at: t,
  };
  run(`INSERT INTO users (id, email, email_verified, password_hash, name, username, avatar_url, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    user.id, user.email, user.email_verified, user.password_hash,
    user.name, user.username, user.avatar_url, user.created_at, user.updated_at);
  return findUserById(user.id);
}

// --- Сессии ---------------------------------------------------------------

export function createSession(userId, { ip, userAgent, method = 'password' }) {
  const token = randomToken(32);
  const t = now();
  const expiresAt = t + config.session.ttlDays * 86_400_000;
  run(`INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, method, created_at, last_seen_at, expires_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    newId('ses'), userId, tokenHash(token), ip || null, (userAgent || '').slice(0, 300), method, t, t, expiresAt);
  audit('session.created', { userId, ip, detail: { method } });
  return { token, expiresAt };
}

export function resolveSession(token) {
  if (!token) return null;
  const session = one('SELECT * FROM sessions WHERE token_hash = ?', tokenHash(token));
  if (!session || session.revoked_at || session.expires_at < now()) return null;
  const user = findUserById(session.user_id);
  if (!user || user.disabled) return null;
  if (now() - session.last_seen_at > 60_000) {
    run('UPDATE sessions SET last_seen_at = ? WHERE id = ?', now(), session.id);
  }
  return { session, user };
}

export const revokeSession = (id) => run('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', now(), id);

export const revokeSessionByToken = (token) =>
  run('UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL', now(), tokenHash(token));

export const revokeOtherSessions = (userId, keepId) =>
  run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL', now(), userId, keepId);

export const listSessions = (userId) =>
  all(`SELECT id, ip, user_agent, method, created_at, last_seen_at, expires_at
       FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
       ORDER BY last_seen_at DESC`, userId, now());

// --- Одноразовые токены из писем -----------------------------------------

export function issueEmailToken(userId, kind, ttlMs) {
  const token = randomToken(32);
  run('INSERT INTO email_tokens (id, user_id, kind, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?)',
    newId('etk'), userId, kind, tokenHash(token), now() + ttlMs, now());
  return token;
}

export function consumeEmailToken(token, kind) {
  const row = one('SELECT * FROM email_tokens WHERE token_hash = ? AND kind = ?', tokenHash(token || ''), kind);
  if (!row || row.used_at || row.expires_at < now()) return null;
  run('UPDATE email_tokens SET used_at = ? WHERE id = ?', now(), row.id);
  return findUserById(row.user_id);
}

// --- Внешние аккаунты -----------------------------------------------------

export const findIdentity = (provider, providerUserId) =>
  one('SELECT * FROM identities WHERE provider = ? AND provider_user_id = ?', provider, String(providerUserId));

export const listIdentities = (userId) =>
  all('SELECT id, provider, provider_user_id, email, display_name, avatar_url, profile_url, created_at FROM identities WHERE user_id = ?', userId);

export function linkIdentity(userId, { provider, providerUserId, email, displayName, avatarUrl, profileUrl }) {
  const existing = findIdentity(provider, providerUserId);
  if (existing && existing.user_id !== userId) {
    throw badRequest('identity_taken', 'Этот профиль уже привязан к другому аккаунту FlowID');
  }
  if (existing) return existing;
  run(`INSERT INTO identities (id, user_id, provider, provider_user_id, email, display_name, avatar_url, profile_url, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    newId('idn'), userId, provider, String(providerUserId), email || null,
    displayName || null, avatarUrl || null, profileUrl || null, now());
  audit('identity.linked', { userId, detail: { provider } });
  return findIdentity(provider, providerUserId);
}

export function unlinkIdentity(userId, identityId) {
  const identity = one('SELECT * FROM identities WHERE id = ? AND user_id = ?', identityId, userId);
  if (!identity) throw badRequest('not_found', 'Такой привязки нет');
  const user = findUserById(userId);
  const otherIdentities = all('SELECT id FROM identities WHERE user_id = ? AND id <> ?', userId, identityId);
  if (!user.password_hash && otherIdentities.length === 0) {
    throw badRequest('last_login_method',
      'Это единственный способ входа. Сначала задайте пароль, потом отвязывайте профиль');
  }
  run('DELETE FROM identities WHERE id = ?', identityId);
  audit('identity.unlinked', { userId, detail: { provider: identity.provider } });
}
