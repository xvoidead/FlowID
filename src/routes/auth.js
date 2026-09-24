import { config } from '../config.js';
import { audit, now, run } from '../db.js';
import {
  createSession, createUser, findUserByEmail, findUserById, publicUser,
  resolveSession, revokeSessionByToken, issueEmailToken, consumeEmailToken,
  listIdentities,
} from '../lib/users.js';
import { verifyPassword, hashPassword } from '../lib/crypto.js';
import { sendMail } from '../lib/mailer.js';
import { requireCsrf } from '../lib/csrf.js';
import {
  requireEmail, requirePassword, requireName, optionalUsername, normalizeEmail, isSafeNext,
} from '../lib/validate.js';
import {
  json, readJson, setCookie, clearCookie, clientIp, enforceRateLimit,
  parseCookies, badRequest, unauthorized,
} from '../lib/http.js';

const VERIFY_TTL = 24 * 3600_000;
const RESET_TTL = 60 * 60_000;

function startSession(req, res, user, method) {
  const { token, expiresAt } = createSession(user.id, {
    ip: clientIp(req), userAgent: req.headers['user-agent'], method,
  });
  setCookie(res, config.session.cookie, token, {
    maxAge: Math.floor((expiresAt - now()) / 1000),
  });
  return token;
}

async function sendVerificationEmail(user) {
  const token = issueEmailToken(user.id, 'verify', VERIFY_TTL);
  const link = `${config.issuer}/verify-email?token=${token}`;
  await sendMail({
    to: user.email,
    subject: 'Подтвердите почту в FlowID',
    text: `${user.name}, подтвердите адрес — ссылка действует сутки:\n\n${link}\n`,
  });
  return token;
}

export async function register(req, res) {
  enforceRateLimit(req, 'register', { limit: 10, windowMs: 10 * 60_000 });
  const body = await readJson(req);
  requireCsrf(req, body);

  const email = requireEmail(body.email);
  const name = requireName(body.name);
  const username = optionalUsername(body.username);
  const password = requirePassword(body.password);
  if (body.password_confirm !== undefined && body.password_confirm !== password) {
    throw badRequest('password_mismatch', 'Пароли не совпадают', { field: 'password_confirm' });
  }
  if (body.accept_terms === false) {
    throw badRequest('terms_required', 'Примите условия, чтобы продолжить', { field: 'accept_terms' });
  }

  const user = await createUser({ email, password, name, username });
  audit('user.registered', { userId: user.id, ip: clientIp(req) });
  await sendVerificationEmail(user);
  startSession(req, res, user, 'password');

  const next = isSafeNext(body.next) ? body.next : '/account';
  json(res, 201, { user: publicUser(user), next, verification_sent: true });
}

export async function login(req, res) {
  enforceRateLimit(req, 'login', { limit: 20, windowMs: 10 * 60_000 });
  const body = await readJson(req);
  requireCsrf(req, body);

  const email = normalizeEmail(body.email);
  const password = String(body.password ?? '');
  const user = findUserByEmail(email);

  // Один и тот же ответ для «нет такого пользователя» и «неверный пароль».
  const ok = user && user.password_hash && await verifyPassword(password, user.password_hash);
  if (!ok) {
    audit('login.failed', { detail: { email }, ip: clientIp(req) });
    throw unauthorized('invalid_credentials', 'Неверная почта или пароль');
  }
  if (user.disabled) throw unauthorized('account_disabled', 'Аккаунт отключён. Напишите в поддержку');

  startSession(req, res, user, 'password');
  audit('login.success', { userId: user.id, ip: clientIp(req), detail: { method: 'password' } });

  const next = isSafeNext(body.next) ? body.next : '/account';
  json(res, 200, { user: publicUser(user), next });
}

export async function logout(req, res) {
  const body = await readJson(req).catch(() => ({}));
  requireCsrf(req, body);
  const token = parseCookies(req)[config.session.cookie];
  if (token) revokeSessionByToken(token);
  clearCookie(res, config.session.cookie);
  json(res, 200, { ok: true });
}

export function me(req, res) {
  if (!req.auth) return json(res, 200, { user: null });
  json(res, 200, {
    user: publicUser(req.auth.user),
    session: { id: req.auth.session.id, method: req.auth.session.method },
    identities: listIdentities(req.auth.user.id).map((i) => ({ id: i.id, provider: i.provider, display_name: i.display_name })),
  });
}

export async function verifyEmail(req, res) {
  const body = await readJson(req);
  const user = consumeEmailToken(body.token, 'verify');
  if (!user) throw badRequest('invalid_token', 'Ссылка устарела или уже использована. Запросите новую');
  run('UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?', now(), user.id);
  audit('email.verified', { userId: user.id, ip: clientIp(req) });
  json(res, 200, { ok: true, email: user.email });
}

export async function resendVerification(req, res) {
  enforceRateLimit(req, 'resend-verify', { limit: 3, windowMs: 10 * 60_000 });
  const body = await readJson(req);
  requireCsrf(req, body);
  if (!req.auth) throw unauthorized('unauthenticated', 'Сначала войдите в аккаунт');
  if (req.auth.user.email_verified) return json(res, 200, { ok: true, already: true });
  await sendVerificationEmail(req.auth.user);
  json(res, 200, { ok: true });
}

export async function forgotPassword(req, res) {
  enforceRateLimit(req, 'forgot', { limit: 5, windowMs: 15 * 60_000 });
  const body = await readJson(req);
  requireCsrf(req, body);
  const email = normalizeEmail(body.email);
  const user = findUserByEmail(email);
  if (user) {
    const token = issueEmailToken(user.id, 'reset', RESET_TTL);
    await sendMail({
      to: user.email,
      subject: 'Сброс пароля FlowID',
      text: `Чтобы задать новый пароль, перейдите по ссылке — она действует час:\n\n${config.issuer}/reset-password?token=${token}\n\nЕсли вы не запрашивали сброс, просто удалите письмо.`,
    });
    audit('password.reset_requested', { userId: user.id, ip: clientIp(req) });
  }
  // Ответ не зависит от того, есть ли такой адрес.
  json(res, 200, { ok: true });
}

export async function resetPassword(req, res) {
  enforceRateLimit(req, 'reset', { limit: 10, windowMs: 15 * 60_000 });
  const body = await readJson(req);
  requireCsrf(req, body);
  const password = requirePassword(body.password);
  const user = consumeEmailToken(body.token, 'reset');
  if (!user) throw badRequest('invalid_token', 'Ссылка устарела или уже использована. Запросите новую');

  // Ссылка пришла на почту — значит, владение адресом доказано.
  run('UPDATE users SET password_hash = ?, email_verified = 1, updated_at = ? WHERE id = ?', await hashPassword(password), now(), user.id);
  run('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL', now(), user.id);
  audit('password.reset', { userId: user.id, ip: clientIp(req) });

  const fresh = findUserById(user.id);
  startSession(req, res, fresh, 'password');
  json(res, 200, { ok: true, user: publicUser(fresh), next: '/account' });
}

export { resolveSession };
