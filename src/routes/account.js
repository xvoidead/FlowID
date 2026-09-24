import { run, now, audit, all } from '../db.js';
import {
  publicUser, findUserById, findUserByUsername, listSessions, revokeSession,
  revokeOtherSessions, listIdentities, unlinkIdentity,
} from '../lib/users.js';
import {
  listClientsByOwner, createClient, getClient, rotateSecret, publicClient,
  normalizeRedirectUris, normalizeScopes, listGrants, revokeGrant,
} from '../lib/clients.js';
import { hashPassword, verifyPassword } from '../lib/crypto.js';
import { requireCsrf } from '../lib/csrf.js';
import { requireName, optionalUsername, requirePassword } from '../lib/validate.js';
import { json, readJson, badRequest, unauthorized, forbidden, notFound } from '../lib/http.js';

function requireAuth(req) {
  if (!req.auth) throw unauthorized('unauthenticated', 'Сначала войдите в аккаунт');
  return req.auth;
}

export function overview(req, res) {
  const { user, session } = requireAuth(req);
  json(res, 200, {
    user: publicUser(user),
    current_session_id: session.id,
    sessions: listSessions(user.id),
    identities: listIdentities(user.id),
    apps: listGrants(user.id).map((g) => ({
      client_id: g.client_id,
      name: g.name,
      logo_url: g.logo_url,
      website: g.website,
      scope: g.scope.split(' '),
      granted_at: g.created_at,
      updated_at: g.updated_at,
    })),
    clients: listClientsByOwner(user.id),
    activity: all(`SELECT event, detail, ip, created_at FROM audit_log
                   WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`, user.id)
      .map((row) => ({ ...row, detail: row.detail ? JSON.parse(row.detail) : null })),
  });
}

export async function updateProfile(req, res) {
  const { user } = requireAuth(req);
  const body = await readJson(req);
  requireCsrf(req, body);

  const name = requireName(body.name);
  const username = optionalUsername(body.username);
  if (username && username !== user.username) {
    const taken = findUserByUsername(username);
    if (taken && taken.id !== user.id) throw badRequest('username_taken', 'Этот ник уже занят', { field: 'username' });
  }
  let avatar = body.avatar_url ? String(body.avatar_url).trim() : null;
  if (avatar) {
    try {
      const parsed = new URL(avatar);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('scheme');
    } catch { throw badRequest('invalid_avatar', 'Ссылка на аватар должна начинаться с https://', { field: 'avatar_url' }); }
  }
  run('UPDATE users SET name = ?, username = ?, avatar_url = ?, updated_at = ? WHERE id = ?',
    name, username, avatar, now(), user.id);
  audit('profile.updated', { userId: user.id });
  json(res, 200, { user: publicUser(findUserById(user.id)) });
}

export async function changePassword(req, res) {
  const { user, session } = requireAuth(req);
  const body = await readJson(req);
  requireCsrf(req, body);

  if (user.password_hash) {
    const ok = await verifyPassword(String(body.current_password ?? ''), user.password_hash);
    if (!ok) throw badRequest('invalid_password', 'Текущий пароль не подошёл', { field: 'current_password' });
  }
  const password = requirePassword(body.password);
  run('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', await hashPassword(password), now(), user.id);
  if (body.revoke_others !== false) revokeOtherSessions(user.id, session.id);
  audit('password.changed', { userId: user.id });
  json(res, 200, { ok: true, user: publicUser(findUserById(user.id)) });
}

export async function endSession(req, res, url, params) {
  const { user, session } = requireAuth(req);
  requireCsrf(req, await readJson(req).catch(() => ({})));
  if (params.id === session.id) throw badRequest('current_session', 'Это текущая сессия — выйдите обычной кнопкой');
  const target = listSessions(user.id).find((s) => s.id === params.id);
  if (!target) throw notFound('Сессия не найдена');
  revokeSession(params.id);
  audit('session.revoked', { userId: user.id, detail: { sessionId: params.id } });
  json(res, 200, { ok: true, sessions: listSessions(user.id) });
}

export async function endOtherSessions(req, res) {
  const { user, session } = requireAuth(req);
  requireCsrf(req, await readJson(req).catch(() => ({})));
  revokeOtherSessions(user.id, session.id);
  audit('session.revoked_all', { userId: user.id });
  json(res, 200, { ok: true, sessions: listSessions(user.id) });
}

export async function removeIdentity(req, res, url, params) {
  const { user } = requireAuth(req);
  requireCsrf(req, await readJson(req).catch(() => ({})));
  unlinkIdentity(user.id, params.id);
  json(res, 200, { ok: true, identities: listIdentities(user.id) });
}

export async function removeGrant(req, res, url, params) {
  const { user } = requireAuth(req);
  requireCsrf(req, await readJson(req).catch(() => ({})));
  revokeGrant(user.id, params.id);
  json(res, 200, { ok: true });
}

// --- Приложения разработчика ---------------------------------------------

export async function addClient(req, res) {
  const { user } = requireAuth(req);
  const body = await readJson(req);
  requireCsrf(req, body);

  const name = String(body.name ?? '').trim();
  if (name.length < 2 || name.length > 60) {
    throw badRequest('invalid_name', 'Название приложения: 2–60 символов', { field: 'name' });
  }
  if (listClientsByOwner(user.id).length >= 20) {
    throw badRequest('too_many_clients', 'Достигнут предел в 20 приложений');
  }
  const redirectUris = normalizeRedirectUris(body.redirect_uris);
  const scopes = normalizeScopes(body.scopes);
  const { client, secret } = createClient({
    ownerUserId: user.id,
    name,
    description: String(body.description ?? '').slice(0, 200),
    website: body.website ? String(body.website).trim() : null,
    redirectUris,
    scopes,
    isPublic: Boolean(body.is_public),
  });
  json(res, 201, { client: publicClient(client), client_secret: secret });
}

function ownedClient(user, clientId) {
  const client = getClient(clientId);
  if (!client) throw notFound('Приложение не найдено');
  if (client.owner_user_id !== user.id) throw forbidden('not_owner', 'Это приложение принадлежит другому аккаунту');
  return client;
}

export async function updateClient(req, res, url, params) {
  const { user } = requireAuth(req);
  const body = await readJson(req);
  requireCsrf(req, body);
  const client = ownedClient(user, params.id);

  const name = body.name !== undefined ? String(body.name).trim() : client.name;
  const redirectUris = body.redirect_uris !== undefined
    ? normalizeRedirectUris(body.redirect_uris) : JSON.parse(client.redirect_uris);
  const scopes = body.scopes !== undefined ? normalizeScopes(body.scopes) : client.scopes;

  run(`UPDATE oauth_clients SET name = ?, description = ?, website = ?, redirect_uris = ?, scopes = ?, is_public = ?
       WHERE client_id = ?`,
    name,
    body.description !== undefined ? String(body.description).slice(0, 200) : client.description,
    body.website !== undefined ? (String(body.website).trim() || null) : client.website,
    JSON.stringify(redirectUris), scopes,
    body.is_public !== undefined ? (body.is_public ? 1 : 0) : client.is_public,
    client.client_id);
  audit('client.updated', { userId: user.id, detail: { clientId: client.client_id } });
  json(res, 200, { client: publicClient(getClient(client.client_id)) });
}

export async function rotateClientSecret(req, res, url, params) {
  const { user } = requireAuth(req);
  requireCsrf(req, await readJson(req).catch(() => ({})));
  const client = ownedClient(user, params.id);
  const secret = rotateSecret(client.client_id);
  audit('client.secret_rotated', { userId: user.id, detail: { clientId: client.client_id } });
  json(res, 200, { client_secret: secret, client: publicClient(getClient(client.client_id)) });
}

export async function deleteClient(req, res, url, params) {
  const { user } = requireAuth(req);
  requireCsrf(req, await readJson(req).catch(() => ({})));
  const client = ownedClient(user, params.id);
  run('DELETE FROM oauth_clients WHERE client_id = ?', client.client_id);
  audit('client.deleted', { userId: user.id, detail: { clientId: client.client_id } });
  json(res, 200, { ok: true });
}
