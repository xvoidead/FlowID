import { createReadStream, statSync, existsSync } from 'node:fs';
import { join, normalize, extname } from 'node:path';
import { config } from '../config.js';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const badRequest = (code, message, extra) => new HttpError(400, code, message, extra);
export const unauthorized = (code, message) => new HttpError(401, code, message);
export const forbidden = (code, message) => new HttpError(403, code, message);
export const notFound = (message = 'Страница не найдена') => new HttpError(404, 'not_found', message);

/** decodeURIComponent, который не бросает на битом `%`. */
export function safeDecode(value) {
  try { return decodeURIComponent(value); } catch { return null; }
}

export function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  const out = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    // Битая чужая cookie не должна ронять каждый запрос — пропускаем её.
    const value = safeDecode(part.slice(eq + 1).trim());
    if (value !== null) out[part.slice(0, eq).trim()] = value;
  }
  return out;
}

export function setCookie(res, name, value, { maxAge, httpOnly = true, sameSite = 'Lax', path = '/' } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (httpOnly) parts.push('HttpOnly');
  if (config.isProd) parts.push('Secure');
  if (maxAge !== undefined) parts.push(`Max-Age=${Math.floor(maxAge)}`);
  const prev = res.getHeader('Set-Cookie');
  const list = prev ? (Array.isArray(prev) ? prev : [prev]) : [];
  res.setHeader('Set-Cookie', [...list, parts.join('; ')]);
}

export const clearCookie = (res, name) => setCookie(res, name, '', { maxAge: 0 });

export async function readBody(req, limit = 1024 * 256) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw badRequest('payload_too_large', 'Тело запроса слишком большое');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function readJson(req) {
  const type = req.headers['content-type'] || '';
  const raw = await readBody(req);
  if (!raw) return {};
  if (type.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw badRequest('invalid_json', 'Не удалось разобрать JSON');
  }
}

export function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

export function redirect(res, location, status = 302) {
  res.writeHead(status, { Location: location, 'Cache-Control': 'no-store' });
  res.end();
}

/**
 * Адрес клиента. X-Forwarded-For подделывается кем угодно, поэтому ему верим
 * только за своим прокси (TRUST_PROXY=1) и берём последнее звено — его
 * дописал сам прокси, а не клиент.
 */
export function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (config.trustProxy && typeof fwd === 'string' && fwd) {
    const hops = fwd.split(',').map((h) => h.trim()).filter(Boolean);
    if (hops.length) return hops[hops.length - 1];
  }
  return req.socket.remoteAddress || '';
}

export function serveStatic(res, urlPath) {
  const decoded = safeDecode(urlPath);
  if (decoded === null) return false;
  const rel = normalize(decoded).replace(/^(\.\.[/\\])+/, '');
  const file = join(config.publicDir, rel);
  if (!file.startsWith(config.publicDir) || !existsSync(file)) return false;
  const stat = statSync(file);
  if (!stat.isFile()) return false;
  const ext = extname(file);
  const immutable = ext === '.woff2' || rel.includes('/img/');
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': stat.size,
    'Cache-Control': immutable ? 'public, max-age=31536000, immutable'
      : (config.isProd ? 'public, max-age=300' : 'no-cache'),
  });
  createReadStream(file).pipe(res);
  return true;
}

export function sendPage(res, name) {
  if (!serveStatic(res, `/${name}.html`)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Страница не найдена');
  }
}

export function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

// --- Ограничение частоты запросов (в памяти процесса) ---------------------
const buckets = new Map();

export function rateLimit(key, { limit, windowMs }) {
  const t = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= t) {
    buckets.set(key, { count: 1, resetAt: t + windowMs });
    return { ok: true, remaining: limit - 1, retryAfter: 0 };
  }
  bucket.count += 1;
  if (bucket.count > limit) {
    return { ok: false, remaining: 0, retryAfter: Math.ceil((bucket.resetAt - t) / 1000) };
  }
  return { ok: true, remaining: limit - bucket.count, retryAfter: 0 };
}

export function enforceRateLimit(req, name, opts) {
  const result = rateLimit(`${name}:${clientIp(req)}`, opts);
  if (!result.ok) {
    throw new HttpError(429, 'too_many_requests',
      `Слишком много попыток. Повторите через ${result.retryAfter} с.`, { retryAfter: result.retryAfter });
  }
}

setInterval(() => {
  const t = Date.now();
  for (const [key, bucket] of buckets) if (bucket.resetAt <= t) buckets.delete(key);
}, 60_000).unref();
