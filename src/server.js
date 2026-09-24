import { createServer } from 'node:http';
import { config } from './config.js';
import { sweepExpired } from './db.js';
import {
  json, redirect, serveStatic, sendPage, parseCookies, clearCookie,
  securityHeaders, HttpError, notFound, safeDecode,
} from './lib/http.js';
import { isSafeNext } from './lib/validate.js';
import { ensureCsrfToken } from './lib/csrf.js';
import { resolveSession, revokeSessionByToken } from './lib/users.js';
import * as auth from './routes/auth.js';
import * as oauth from './routes/oauth.js';
import * as vk from './routes/vk.js';
import * as account from './routes/account.js';

// --- Маршрутизатор --------------------------------------------------------

const routes = [];
const add = (method, pattern, handler) => {
  const keys = [];
  const regex = new RegExp(`^${pattern.replace(/:[a-z_]+/gi, (m) => {
    keys.push(m.slice(1));
    return '([^/]+)';
  })}$`);
  routes.push({ method, regex, keys, handler });
};
const get = (p, h) => add('GET', p, h);
const post = (p, h) => add('POST', p, h);
const page = (p, name) => get(p, (req, res) => sendPage(res, name));

// Страницы
page('/', 'index');
page('/login', 'login');
page('/register', 'register');
page('/forgot-password', 'forgot-password');
page('/reset-password', 'reset-password');
page('/verify-email', 'verify-email');
page('/consent', 'consent');
page('/account', 'account');
page('/docs', 'docs');
page('/oauth/error', 'oauth-error');

get('/logout', (req, res) => {
  const token = parseCookies(req)[config.session.cookie];
  if (token) revokeSessionByToken(token);
  clearCookie(res, config.session.cookie);
  const next = new URL(req.url, config.issuer).searchParams.get('next');
  redirect(res, isSafeNext(next) ? next : '/');
});

// Метаданные OpenID Connect
get('/.well-known/openid-configuration', oauth.discovery);
get('/oauth/jwks.json', oauth.jwks);

// OAuth
get('/oauth/authorize', oauth.authorize);
post('/oauth/token', oauth.token);
get('/oauth/userinfo', oauth.userinfo);
post('/oauth/userinfo', oauth.userinfo);
post('/oauth/revoke', oauth.revoke);
post('/oauth/introspect', oauth.introspect);
get('/api/oauth/consent', oauth.consentInfo);
post('/api/oauth/consent', oauth.consentDecision);

// Аутентификация
get('/api/config', (req, res) => json(res, 200, {
  issuer: config.issuer,
  vk_enabled: config.vk.enabled,
  scopes: config.oauth.scopes,
  authenticated: Boolean(req.auth),
}));
post('/api/auth/register', auth.register);
post('/api/auth/login', auth.login);
post('/api/auth/logout', auth.logout);
get('/api/auth/me', auth.me);
post('/api/auth/verify-email', auth.verifyEmail);
post('/api/auth/resend-verification', auth.resendVerification);
post('/api/auth/password/forgot', auth.forgotPassword);
post('/api/auth/password/reset', auth.resetPassword);

// VK ID
get('/auth/vk/start', vk.start);
get('/auth/vk/callback', vk.callback);

// Аккаунт
get('/api/account', account.overview);
post('/api/account/profile', account.updateProfile);
post('/api/account/password', account.changePassword);
post('/api/account/sessions/:id/revoke', account.endSession);
post('/api/account/sessions/revoke-others', account.endOtherSessions);
post('/api/account/identities/:id/unlink', account.removeIdentity);
post('/api/account/apps/:id/revoke', account.removeGrant);
post('/api/account/clients', account.addClient);
post('/api/account/clients/:id', account.updateClient);
post('/api/account/clients/:id/secret', account.rotateClientSecret);
post('/api/account/clients/:id/delete', account.deleteClient);

// --- Обработка запроса ----------------------------------------------------

function match(method, pathname) {
  for (const route of routes) {
    if (route.method !== method) continue;
    const found = route.regex.exec(pathname);
    if (!found) continue;
    const params = {};
    for (const [i, key] of route.keys.entries()) {
      const value = safeDecode(found[i + 1]);
      if (value === null) return null;
      params[key] = value;
    }
    return { handler: route.handler, params };
  }
  return null;
}

const isApiPath = (pathname) =>
  pathname.startsWith('/api/') || pathname.startsWith('/oauth/') || pathname.startsWith('/.well-known/');

function handleError(err, req, res, pathname) {
  if (res.headersSent) return res.end();
  const status = err instanceof HttpError ? err.status : 500;
  if (status === 500) console.error('Ошибка запроса', req.method, pathname, err);

  if (err?.extra?.retryAfter) res.setHeader('Retry-After', String(err.extra.retryAfter));

  if (isApiPath(pathname) || (req.headers.accept || '').includes('application/json')) {
    const body = err?.extra?.oauth
      ? { error: err.code, error_description: err.message }
      : { error: err instanceof HttpError ? err.code : 'server_error',
          message: err instanceof HttpError ? err.message : 'Что-то пошло не так на нашей стороне',
          ...(err?.extra?.field ? { field: err.extra.field } : {}) };
    return json(res, status, body);
  }
  if (status === 404) return sendPage(res, '404');
  redirect(res, `/oauth/error?message=${encodeURIComponent(err.message || 'Непредвиденная ошибка')}`);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, config.issuer);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  securityHeaders(res);

  try {
    // Сессия пользователя и CSRF-токен доступны всем обработчикам.
    const sessionToken = parseCookies(req)[config.session.cookie];
    req.auth = resolveSession(sessionToken);
    if (!isApiPath(pathname) || pathname.startsWith('/api/')) ensureCsrfToken(req, res);

    const route = match(req.method === 'HEAD' ? 'GET' : req.method, pathname);
    if (route) return await route.handler(req, res, url, route.params);

    if (req.method === 'GET' && serveStatic(res, pathname)) return;
    throw notFound();
  } catch (err) {
    handleError(err, req, res, pathname);
  }
});

setInterval(sweepExpired, 15 * 60_000).unref();
sweepExpired();

server.listen(config.port, () => {
  console.log(`\n  FlowID запущен  →  ${config.issuer}`);
  console.log(`  Вход:           ${config.issuer}/login`);
  console.log(`  Метаданные:     ${config.issuer}/.well-known/openid-configuration`);
  console.log(`  Вход через VK:  ${config.vk.enabled ? 'включён' : 'выключен (задайте VK_CLIENT_ID в .env)'}\n`);
});

export { server };
