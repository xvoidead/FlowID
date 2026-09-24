import { one, all, run, now, audit } from '../db.js';
import { randomToken, tokenHash, safeEqual } from './crypto.js';
import { config } from '../config.js';
import { badRequest } from './http.js';

export const getClient = (clientId) => one('SELECT * FROM oauth_clients WHERE client_id = ?', clientId);

export const publicClient = (client) => client && ({
  client_id: client.client_id,
  name: client.name,
  description: client.description,
  logo_url: client.logo_url,
  website: client.website,
  redirect_uris: JSON.parse(client.redirect_uris),
  scopes: client.scopes.split(' '),
  is_public: Boolean(client.is_public),
  is_trusted: Boolean(client.is_trusted),
  created_at: client.created_at,
});

/**
 * Почему адрес не годится в redirect URI, или null, если годится.
 * Разрешены https, http на localhost и собственные схемы нативных приложений
 * в обратной доменной записи (RFC 8252: com.example.app:/cb). Всё прочее —
 * javascript:, data:, file: и т. п. — исполнилось бы на странице FlowID.
 */
export function redirectUriProblem(uri) {
  let parsed;
  try { parsed = new URL(uri); } catch { return `Не похоже на адрес: ${uri}`; }
  if (parsed.hash) return 'Redirect URI не может содержать #fragment';
  const scheme = parsed.protocol.slice(0, -1);
  if (scheme === 'https') return null;
  if (scheme === 'http') {
    const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    return isLocal ? null : 'Вне localhost разрешён только https';
  }
  if (/^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+$/.test(scheme)) return null;
  return `Схема ${scheme}: не подходит. Используйте https или схему приложения вида com.example.app:/`;
}

export function validateRedirectUri(client, redirectUri) {
  // Повторная проверка схемы ловит адреса, сохранённые до появления правила.
  if (redirectUriProblem(redirectUri)) return false;
  const allowed = JSON.parse(client.redirect_uris);
  return allowed.some((uri) => safeEqual(uri, redirectUri));
}

export function normalizeRedirectUris(input) {
  const list = (Array.isArray(input) ? input : String(input ?? '').split(/[\s,]+/))
    .map((uri) => String(uri).trim())
    .filter(Boolean);
  if (list.length === 0) throw badRequest('invalid_redirect_uri', 'Добавьте хотя бы один redirect URI', { field: 'redirect_uris' });
  if (list.length > 10) throw badRequest('invalid_redirect_uri', 'Не больше 10 redirect URI', { field: 'redirect_uris' });
  for (const uri of list) {
    const problem = redirectUriProblem(uri);
    if (problem) throw badRequest('invalid_redirect_uri', problem, { field: 'redirect_uris' });
  }
  return list;
}

export function normalizeScopes(input, fallback = 'openid profile email') {
  const known = Object.keys(config.oauth.scopes);
  const list = (Array.isArray(input) ? input : String(input ?? fallback).split(/[\s,]+/))
    .map((s) => s.trim()).filter(Boolean);
  const unknown = list.filter((s) => !known.includes(s));
  if (unknown.length) throw badRequest('invalid_scope', `Неизвестные разрешения: ${unknown.join(', ')}`, { field: 'scopes' });
  const unique = [...new Set(list.length ? list : fallback.split(' '))];
  if (!unique.includes('openid')) unique.unshift('openid');
  return unique.join(' ');
}

export function createClient({ ownerUserId, name, description = '', website = null, logoUrl = null, redirectUris, scopes, isPublic = false }) {
  const clientId = `flow_${randomToken(12).toLowerCase().replace(/[-_]/g, '').slice(0, 20)}`;
  const secret = isPublic ? null : `fsec_${randomToken(32)}`;
  run(`INSERT INTO oauth_clients (client_id, secret_hash, name, description, logo_url, website, owner_user_id, redirect_uris, scopes, is_public, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    clientId, secret ? tokenHash(secret) : null, name, description, logoUrl, website, ownerUserId,
    JSON.stringify(redirectUris), scopes, isPublic ? 1 : 0, now());
  audit('client.created', { userId: ownerUserId, detail: { clientId } });
  return { client: getClient(clientId), secret };
}

export function rotateSecret(clientId) {
  const secret = `fsec_${randomToken(32)}`;
  run('UPDATE oauth_clients SET secret_hash = ?, is_public = 0 WHERE client_id = ?', tokenHash(secret), clientId);
  return secret;
}

export const listClientsByOwner = (ownerUserId) =>
  all('SELECT * FROM oauth_clients WHERE owner_user_id = ? ORDER BY created_at DESC', ownerUserId).map(publicClient);

export const verifyClientSecret = (client, secret) =>
  Boolean(client.secret_hash) && Boolean(secret) && safeEqual(client.secret_hash, tokenHash(secret));

/** Приложения, которым пользователь выдал доступ. */
export const listGrants = (userId) =>
  all(`SELECT g.client_id, g.scope, g.created_at, g.updated_at, c.name, c.logo_url, c.website
       FROM oauth_grants g JOIN oauth_clients c ON c.client_id = g.client_id
       WHERE g.user_id = ? ORDER BY g.updated_at DESC`, userId);

export function revokeGrant(userId, clientId) {
  run('DELETE FROM oauth_grants WHERE user_id = ? AND client_id = ?', userId, clientId);
  run('UPDATE oauth_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL', now(), userId, clientId);
  run('DELETE FROM oauth_codes WHERE user_id = ? AND client_id = ?', userId, clientId);
  audit('grant.revoked', { userId, detail: { clientId } });
}

export function saveGrant(userId, clientId, scope) {
  const existing = one('SELECT * FROM oauth_grants WHERE user_id = ? AND client_id = ?', userId, clientId);
  const merged = existing
    ? [...new Set([...existing.scope.split(' '), ...scope.split(' ')])].join(' ')
    : scope;
  if (existing) {
    run('UPDATE oauth_grants SET scope = ?, updated_at = ? WHERE user_id = ? AND client_id = ?', merged, now(), userId, clientId);
  } else {
    run('INSERT INTO oauth_grants (user_id, client_id, scope, created_at, updated_at) VALUES (?,?,?,?,?)',
      userId, clientId, merged, now(), now());
  }
  return merged;
}

export const getGrant = (userId, clientId) =>
  one('SELECT * FROM oauth_grants WHERE user_id = ? AND client_id = ?', userId, clientId);
