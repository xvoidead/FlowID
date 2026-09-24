import { badRequest } from './http.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
const USERNAME_RE = /^[a-z0-9_]{3,24}$/;

export function normalizeEmail(value) {
  return String(value ?? '').trim().toLowerCase();
}

export function requireEmail(value) {
  const email = normalizeEmail(value);
  if (!EMAIL_RE.test(email) || email.length > 254) {
    throw badRequest('invalid_email', 'Введите адрес почты в формате name@example.com', { field: 'email' });
  }
  return email;
}

/** Требования к паролю: 8+ символов, буквы и цифры, не из списка частых. */
const COMMON = new Set(['password', '12345678', 'qwerty123', 'password1', '11111111', 'qwertyui', 'iloveyou']);

export function requirePassword(value, field = 'password') {
  const password = String(value ?? '');
  if (password.length < 8) throw badRequest('weak_password', 'Пароль должен быть не короче 8 символов', { field });
  if (password.length > 200) throw badRequest('weak_password', 'Пароль не длиннее 200 символов', { field });
  if (!/[a-zа-я]/i.test(password) || !/\d/.test(password)) {
    throw badRequest('weak_password', 'Добавьте в пароль хотя бы одну букву и одну цифру', { field });
  }
  if (COMMON.has(password.toLowerCase())) {
    throw badRequest('weak_password', 'Этот пароль слишком часто встречается — придумайте другой', { field });
  }
  return password;
}

export function requireName(value) {
  const name = String(value ?? '').trim().replace(/\s+/g, ' ');
  if (name.length < 2) throw badRequest('invalid_name', 'Имя должно быть не короче 2 символов', { field: 'name' });
  if (name.length > 80) throw badRequest('invalid_name', 'Имя не длиннее 80 символов', { field: 'name' });
  return name;
}

export function optionalUsername(value) {
  const username = String(value ?? '').trim().toLowerCase();
  if (!username) return null;
  if (!USERNAME_RE.test(username)) {
    throw badRequest('invalid_username', 'Ник: 3–24 символа, латиница, цифры и нижнее подчёркивание', { field: 'username' });
  }
  return username;
}

/** Оценка силы пароля 0–4 — используется и на клиенте, и на сервере. */
export function passwordStrength(password = '') {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) && /[^\w\s]/.test(password)) score += 1;
  return Math.min(score, 4);
}

/**
 * Адрес для возврата после входа — только путь на этом же сайте.
 * Браузер читает `/\evil.com` как `//evil.com`, поэтому обратная косая
 * и управляющие символы запрещены целиком, а итог сверяется через URL.
 */
export function isSafeNext(next) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.length > 2048) return false;
  if (/[\\\x00-\x1f\x7f]/.test(next) || /^\/[/\\]/.test(next)) return false;
  const base = 'http://flowid.invalid';
  try { return new URL(next, base).origin === base; } catch { return false; }
}
