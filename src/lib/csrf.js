import { config } from '../config.js';
import { randomToken, safeEqual } from './crypto.js';
import { parseCookies, setCookie, forbidden } from './http.js';

/** Двойная отправка токена: cookie (читаемая скриптом) + заголовок/поле формы. */
export function ensureCsrfToken(req, res) {
  const cookies = parseCookies(req);
  let token = cookies[config.session.csrfCookie];
  if (!token || token.length < 20) {
    token = randomToken(24);
    setCookie(res, config.session.csrfCookie, token, {
      httpOnly: false,
      maxAge: config.session.ttlDays * 86_400,
    });
  }
  return token;
}

export function requireCsrf(req, body = {}) {
  const cookies = parseCookies(req);
  const expected = cookies[config.session.csrfCookie];
  const provided = req.headers['x-csrf-token'] || body.csrf_token;
  if (!expected || !provided || !safeEqual(expected, provided)) {
    throw forbidden('csrf_failed', 'Сессия формы устарела. Обновите страницу и попробуйте снова');
  }
}
