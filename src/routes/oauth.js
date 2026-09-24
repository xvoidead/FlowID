import { config } from '../config.js';
import { one, run, now, audit } from '../db.js';
import {
  getClient, publicClient, validateRedirectUri, verifyClientSecret,
  getGrant, saveGrant,
} from '../lib/clients.js';
import { findUserById, publicUser, listIdentities } from '../lib/users.js';
import {
  newId, randomToken, tokenHash, signJwt, publicJwk, verifyPkce, sha256b64u,
} from '../lib/crypto.js';
import { requireCsrf } from '../lib/csrf.js';
import {
  json, readJson, redirect, badRequest, unauthorized, HttpError,
  clientIp, enforceRateLimit, sendPage, safeDecode,
} from '../lib/http.js';

const SUPPORTED_SCOPES = Object.keys(config.oauth.scopes);

// --- Метаданные -----------------------------------------------------------

export function discovery(req, res) {
  const i = config.issuer;
  json(res, 200, {
    issuer: i,
    authorization_endpoint: `${i}/oauth/authorize`,
    token_endpoint: `${i}/oauth/token`,
    userinfo_endpoint: `${i}/oauth/userinfo`,
    jwks_uri: `${i}/oauth/jwks.json`,
    revocation_endpoint: `${i}/oauth/revoke`,
    introspection_endpoint: `${i}/oauth/introspect`,
    end_session_endpoint: `${i}/logout`,
    scopes_supported: SUPPORTED_SCOPES,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'preferred_username', 'picture', 'email', 'email_verified'],
  });
}

export const jwks = (req, res) => json(res, 200, { keys: [publicJwk()] });

// --- Вспомогательное ------------------------------------------------------

function redirectWithError(res, redirectUri, state, error, description) {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  if (description) url.searchParams.set('error_description', description);
  if (state) url.searchParams.set('state', state);
  redirect(res, url.toString());
}

function authorizeErrorPage(res, message) {
  const url = new URL(`${config.issuer}/oauth/error`);
  url.searchParams.set('message', message);
  redirect(res, url.toString());
}

function parseAuthorizeParams(url) {
  const q = url.searchParams;
  return {
    response_type: q.get('response_type') || '',
    client_id: q.get('client_id') || '',
    redirect_uri: q.get('redirect_uri') || '',
    scope: (q.get('scope') || 'openid profile email').trim(),
    state: q.get('state') || '',
    nonce: q.get('nonce') || '',
    prompt: q.get('prompt') || '',
    code_challenge: q.get('code_challenge') || '',
    code_challenge_method: q.get('code_challenge_method') || '',
  };
}

function issueCode({ clientId, userId, sessionId, redirectUri, scope, nonce, challenge, method }) {
  const code = randomToken(32);
  run(`INSERT INTO oauth_codes
       (code_hash, client_id, user_id, session_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    tokenHash(code), clientId, userId, sessionId || null, redirectUri, scope, nonce || null,
    challenge || null, method || null, now() + config.oauth.codeTtlSeconds * 1000, now());
  return code;
}

// --- /oauth/authorize -----------------------------------------------------

export function authorize(req, res, url) {
  const p = parseAuthorizeParams(url);

  const client = p.client_id && getClient(p.client_id);
  if (!client) return authorizeErrorPage(res, 'Приложение не найдено. Проверьте client_id в настройках интеграции.');
  if (!p.redirect_uri || !validateRedirectUri(client, p.redirect_uri)) {
    return authorizeErrorPage(res, 'redirect_uri не совпадает с адресом, указанным в настройках приложения.');
  }
  // Дальше ошибки можно безопасно возвращать на redirect_uri.
  if (p.response_type !== 'code') {
    return redirectWithError(res, p.redirect_uri, p.state, 'unsupported_response_type', 'Поддерживается только response_type=code');
  }
  const requested = [...new Set(p.scope.split(/\s+/).filter(Boolean))];
  const unknown = requested.filter((s) => !SUPPORTED_SCOPES.includes(s));
  if (unknown.length) {
    return redirectWithError(res, p.redirect_uri, p.state, 'invalid_scope', `Неизвестные разрешения: ${unknown.join(' ')}`);
  }
  const allowed = client.scopes.split(' ');
  const forbiddenScopes = requested.filter((s) => !allowed.includes(s));
  if (forbiddenScopes.length) {
    return redirectWithError(res, p.redirect_uri, p.state, 'invalid_scope', `Приложению не разрешены: ${forbiddenScopes.join(' ')}`);
  }
  if (client.is_public && !p.code_challenge) {
    return redirectWithError(res, p.redirect_uri, p.state, 'invalid_request', 'Публичному клиенту обязателен PKCE (code_challenge)');
  }
  if (p.code_challenge && p.code_challenge_method !== 'S256') {
    return redirectWithError(res, p.redirect_uri, p.state, 'invalid_request', 'code_challenge_method должен быть S256');
  }

  const scope = requested.join(' ');
  const prompts = new Set(p.prompt.split(/\s+/).filter(Boolean));
  if (prompts.has('none') && prompts.size > 1) {
    return redirectWithError(res, p.redirect_uri, p.state, 'invalid_request', 'prompt=none нельзя сочетать с другими значениями');
  }

  // prompt=none обещает приложению, что никакого интерфейса не будет.
  if (prompts.has('none') && !req.auth) {
    return redirectWithError(res, p.redirect_uri, p.state, 'login_required', 'Пользователь не вошёл в FlowID');
  }

  // Повторный вход по prompt=login: в адрес возврата вместо prompt=login кладём
  // момент запроса. Сессия, созданная раньше него, не годится, а новая — годится,
  // так что после входа человек идёт дальше, а не по кругу на страницу входа.
  const loginAfter = Number(url.searchParams.get('login_after')) || 0;
  const staleSession = req.auth && loginAfter > 0 && req.auth.session.created_at < loginAfter;
  if (!req.auth || prompts.has('login') || staleSession) {
    const back = new URL(url);
    if (prompts.has('login')) {
      prompts.delete('login');
      if (prompts.size) back.searchParams.set('prompt', [...prompts].join(' '));
      else back.searchParams.delete('prompt');
      back.searchParams.set('login_after', String(now()));
    }
    const next = `${back.pathname}${back.search}`;
    const reauth = back.searchParams.has('login_after') ? '&reauth=1' : '';
    return redirect(res, `/login?next=${encodeURIComponent(next)}${reauth}`);
  }

  const grant = getGrant(req.auth.user.id, client.client_id);
  const granted = grant ? grant.scope.split(' ') : [];
  const needsConsent = prompts.has('consent') || !client.is_trusted && requested.some((s) => !granted.includes(s));

  if (prompts.has('none') && needsConsent) {
    return redirectWithError(res, p.redirect_uri, p.state, 'consent_required', 'Нужно согласие пользователя');
  }

  if (!needsConsent) {
    const code = issueCode({
      clientId: client.client_id, userId: req.auth.user.id, sessionId: req.auth.session.id,
      redirectUri: p.redirect_uri, scope, nonce: p.nonce,
      challenge: p.code_challenge, method: p.code_challenge_method,
    });
    audit('oauth.code_issued', { userId: req.auth.user.id, ip: clientIp(req), detail: { client_id: client.client_id, scope, silent: true } });
    const target = new URL(p.redirect_uri);
    target.searchParams.set('code', code);
    if (p.state) target.searchParams.set('state', p.state);
    return redirect(res, target.toString());
  }

  // Сохраняем запрос и отправляем на экран согласия.
  const id = newId('areq');
  run('INSERT INTO auth_requests (id, client_id, params, expires_at, created_at) VALUES (?,?,?,?,?)',
    id, client.client_id, JSON.stringify(p), now() + 15 * 60_000, now());
  redirect(res, `/consent?request=${id}`);
}

function loadAuthRequest(id) {
  const row = id && one('SELECT * FROM auth_requests WHERE id = ?', id);
  if (!row || row.expires_at < now()) {
    throw badRequest('request_expired', 'Запрос авторизации устарел. Вернитесь в приложение и начните вход заново');
  }
  return { row, params: JSON.parse(row.params) };
}

/** Данные для экрана согласия. */
export function consentInfo(req, res, url) {
  if (!req.auth) throw unauthorized('unauthenticated', 'Сначала войдите в аккаунт');
  const { row, params } = loadAuthRequest(url.searchParams.get('request'));
  const client = getClient(row.client_id);
  const grant = getGrant(req.auth.user.id, client.client_id);
  const granted = grant ? grant.scope.split(' ') : [];
  const scopes = params.scope.split(' ').map((key) => ({
    key,
    title: config.oauth.scopes[key],
    required: key === 'openid',
    already_granted: granted.includes(key),
  }));
  json(res, 200, {
    request: row.id,
    client: {
      name: client.name,
      description: client.description,
      logo_url: client.logo_url,
      website: client.website,
    },
    redirect_host: new URL(params.redirect_uri).host,
    scopes,
    user: publicUser(req.auth.user),
  });
}

export async function consentDecision(req, res) {
  const body = await readJson(req);
  requireCsrf(req, body);
  if (!req.auth) throw unauthorized('unauthenticated', 'Сначала войдите в аккаунт');

  const { row, params } = loadAuthRequest(body.request);
  const client = getClient(row.client_id);
  run('DELETE FROM auth_requests WHERE id = ?', row.id);

  const target = new URL(params.redirect_uri);
  if (params.state) target.searchParams.set('state', params.state);

  if (!body.allow) {
    target.searchParams.set('error', 'access_denied');
    target.searchParams.set('error_description', 'Пользователь отклонил запрос');
    audit('oauth.consent_denied', { userId: req.auth.user.id, ip: clientIp(req), detail: { client_id: client.client_id } });
    return json(res, 200, { redirect: target.toString() });
  }

  const requested = params.scope.split(' ');
  const optional = Array.isArray(body.scopes) ? body.scopes : requested;
  const scope = requested.filter((s) => s === 'openid' || optional.includes(s)).join(' ');

  saveGrant(req.auth.user.id, client.client_id, scope);
  const code = issueCode({
    clientId: client.client_id, userId: req.auth.user.id, sessionId: req.auth.session.id,
    redirectUri: params.redirect_uri, scope, nonce: params.nonce,
    challenge: params.code_challenge, method: params.code_challenge_method,
  });
  audit('oauth.code_issued', { userId: req.auth.user.id, ip: clientIp(req), detail: { client_id: client.client_id, scope } });

  target.searchParams.set('code', code);
  json(res, 200, { redirect: target.toString() });
}

// --- /oauth/token ---------------------------------------------------------

function tokenError(status, error, description) {
  return new HttpError(status, error, description, { oauth: true });
}

function authenticateClient(req, body) {
  const header = req.headers.authorization || '';
  let clientId = body.client_id || '';
  let secret = body.client_secret || '';
  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    clientId = sep === -1 ? null : safeDecode(decoded.slice(0, sep));
    secret = sep === -1 ? null : safeDecode(decoded.slice(sep + 1));
    if (clientId === null || secret === null) throw tokenError(401, 'invalid_client', 'Заголовок Authorization: Basic повреждён');
  }
  const client = clientId && getClient(clientId);
  if (!client) throw tokenError(401, 'invalid_client', 'Клиент не найден');
  if (client.is_public) {
    if (secret) throw tokenError(401, 'invalid_client', 'Публичный клиент не использует client_secret');
  } else if (!verifyClientSecret(client, secret)) {
    throw tokenError(401, 'invalid_client', 'Неверный client_secret');
  }
  return client;
}

function issueTokens(client, user, scope, { nonce } = {}) {
  const accessToken = randomToken(32);
  const t = now();
  const accessId = newId('at');
  run(`INSERT INTO oauth_tokens (id, kind, token_hash, client_id, user_id, scope, expires_at, created_at)
       VALUES (?,?,?,?,?,?,?,?)`,
    accessId, 'access', tokenHash(accessToken), client.client_id, user.id, scope,
    t + config.oauth.accessTtlSeconds * 1000, t);

  const payload = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.oauth.accessTtlSeconds,
    scope,
  };

  if (scope.split(' ').includes('offline_access')) {
    const refreshToken = randomToken(32);
    run(`INSERT INTO oauth_tokens (id, kind, token_hash, client_id, user_id, scope, parent_id, expires_at, created_at)
         VALUES (?,?,?,?,?,?,?,?,?)`,
      newId('rt'), 'refresh', tokenHash(refreshToken), client.client_id, user.id, scope, accessId,
      t + config.oauth.refreshTtlDays * 86_400_000, t);
    payload.refresh_token = refreshToken;
  }

  if (scope.split(' ').includes('openid')) {
    payload.id_token = signJwt({
      iss: config.issuer,
      sub: user.id,
      aud: client.client_id,
      nonce: nonce || undefined,
      auth_time: Math.floor(t / 1000),
      at_hash: sha256b64u(accessToken).slice(0, 22),
      ...claimsFor(user, scope),
    }, { expiresIn: config.oauth.accessTtlSeconds });
  }

  return payload;
}

function claimsFor(user, scope) {
  const scopes = scope.split(' ');
  const claims = {};
  if (scopes.includes('profile')) {
    claims.name = user.name;
    claims.preferred_username = user.username || undefined;
    claims.picture = user.avatar_url || undefined;
    claims.updated_at = Math.floor(user.updated_at / 1000);
  }
  if (scopes.includes('email')) {
    claims.email = user.email;
    claims.email_verified = Boolean(user.email_verified);
  }
  return claims;
}

export async function token(req, res) {
  enforceRateLimit(req, 'token', { limit: 120, windowMs: 60_000 });
  const body = await readJson(req);
  const client = authenticateClient(req, body);

  if (body.grant_type === 'authorization_code') {
    const row = one('SELECT * FROM oauth_codes WHERE code_hash = ?', tokenHash(String(body.code || '')));
    if (!row) throw tokenError(400, 'invalid_grant', 'Код не найден');
    if (row.used_at) {
      // Повторное использование кода — отзываем всё, что по нему выдано.
      run('UPDATE oauth_tokens SET revoked_at = ? WHERE client_id = ? AND user_id = ? AND revoked_at IS NULL', now(), row.client_id, row.user_id);
      run('DELETE FROM oauth_codes WHERE code_hash = ?', row.code_hash);
      audit('oauth.code_replay', { userId: row.user_id, detail: { client_id: row.client_id } });
      throw tokenError(400, 'invalid_grant', 'Код уже использован — выданные токены отозваны');
    }
    if (row.expires_at < now()) throw tokenError(400, 'invalid_grant', 'Код истёк');
    if (row.client_id !== client.client_id) throw tokenError(400, 'invalid_grant', 'Код выдан другому клиенту');
    if (body.redirect_uri !== row.redirect_uri) throw tokenError(400, 'invalid_grant', 'redirect_uri не совпадает');
    if (row.code_challenge && !verifyPkce(body.code_verifier, row.code_challenge, row.code_challenge_method)) {
      throw tokenError(400, 'invalid_grant', 'code_verifier не проходит проверку PKCE');
    }

    run('UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?', now(), row.code_hash);
    const user = findUserById(row.user_id);
    if (!user || user.disabled) throw tokenError(400, 'invalid_grant', 'Аккаунт недоступен');

    audit('oauth.token_issued', { userId: user.id, detail: { client_id: client.client_id, grant: 'authorization_code' } });
    return json(res, 200, issueTokens(client, user, row.scope, { nonce: row.nonce }));
  }

  if (body.grant_type === 'refresh_token') {
    const row = one('SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = ?', tokenHash(String(body.refresh_token || '')), 'refresh');
    if (!row || row.revoked_at || row.expires_at < now()) throw tokenError(400, 'invalid_grant', 'Refresh-токен недействителен');
    if (row.client_id !== client.client_id) throw tokenError(400, 'invalid_grant', 'Токен выдан другому клиенту');

    let scope = row.scope;
    if (body.scope) {
      const requested = String(body.scope).split(/\s+/).filter(Boolean);
      if (requested.some((s) => !row.scope.split(' ').includes(s))) {
        throw tokenError(400, 'invalid_scope', 'Нельзя расширить разрешения при обновлении токена');
      }
      scope = requested.join(' ');
    }
    const user = findUserById(row.user_id);
    if (!user || user.disabled) throw tokenError(400, 'invalid_grant', 'Аккаунт недоступен');

    // Ротация: старый refresh отзывается вместе со своим access.
    run('UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? OR id = ?', now(), row.id, row.parent_id || '');
    audit('oauth.token_refreshed', { userId: user.id, detail: { client_id: client.client_id } });
    return json(res, 200, issueTokens(client, user, scope));
  }

  throw tokenError(400, 'unsupported_grant_type', 'Поддерживаются authorization_code и refresh_token');
}

// --- Bearer-эндпоинты -----------------------------------------------------

function bearerToken(req, url) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();
  return url?.searchParams.get('access_token') || '';
}

export function resolveAccessToken(token) {
  if (!token) return null;
  const row = one('SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = ?', tokenHash(token), 'access');
  if (!row || row.revoked_at || row.expires_at < now()) return null;
  const user = findUserById(row.user_id);
  if (!user || user.disabled) return null;
  return { token: row, user };
}

export function userinfo(req, res, url) {
  const found = resolveAccessToken(bearerToken(req, url));
  if (!found) {
    res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    throw unauthorized('invalid_token', 'Токен недействителен или истёк');
  }
  const { token: row, user } = found;
  json(res, 200, {
    sub: user.id,
    ...claimsFor(user, row.scope),
    identities: row.scope.includes('profile')
      ? listIdentities(user.id).map((i) => ({ provider: i.provider, id: i.provider_user_id }))
      : undefined,
  });
}

export async function revoke(req, res) {
  const body = await readJson(req);
  const client = authenticateClient(req, body);
  const hash = tokenHash(String(body.token || ''));
  run('UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL', now(), hash, client.client_id);
  json(res, 200, {}); // RFC 7009: всегда 200
}

export async function introspect(req, res) {
  const body = await readJson(req);
  const client = authenticateClient(req, body);
  const row = one('SELECT * FROM oauth_tokens WHERE token_hash = ?', tokenHash(String(body.token || '')));
  if (!row || row.revoked_at || row.expires_at < now() || row.client_id !== client.client_id) {
    return json(res, 200, { active: false });
  }
  json(res, 200, {
    active: true,
    scope: row.scope,
    client_id: row.client_id,
    sub: row.user_id,
    token_type: row.kind === 'access' ? 'Bearer' : 'refresh_token',
    exp: Math.floor(row.expires_at / 1000),
    iat: Math.floor(row.created_at / 1000),
    iss: config.issuer,
  });
}

export function errorPage(req, res) {
  sendPage(res, 'oauth-error');
}

export { publicClient };
