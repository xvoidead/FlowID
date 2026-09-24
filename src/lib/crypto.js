import {
  randomBytes, scrypt, timingSafeEqual, createHash, createHmac,
  generateKeyPairSync, createSign, createPublicKey,
} from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { config } from '../config.js';

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

const scryptAsync = (password, salt, keylen, opts) =>
  new Promise((resolve, reject) =>
    scrypt(password, salt, keylen, opts, (err, key) => (err ? reject(err) : resolve(key))));

/** Хеш пароля в формате scrypt$N$r$p$salt$key (всё в base64url). */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scryptAsync(password.normalize('NFKC'), salt, SCRYPT.keylen, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('scrypt$')) return false;
  const [, N, r, p, salt, key] = stored.split('$');
  const expected = Buffer.from(key, 'base64url');
  const actual = await scryptAsync(
    password.normalize('NFKC'),
    Buffer.from(salt, 'base64url'),
    expected.length,
    { N: Number(N), r: Number(r), p: Number(p) },
  );
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const sha256 = (value) => createHash('sha256').update(value).digest();
export const sha256b64u = (value) => sha256(value).toString('base64url');
export const tokenHash = (token) => createHash('sha256').update(`${token}${config.appSecret}`).digest('hex');
export const newId = (prefix) => `${prefix}_${randomBytes(12).toString('hex')}`;

export function safeEqual(a = '', b = '') {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/** Подпись строки для stateless-состояний (VK state, ссылки из писем). */
export const sign = (value) => createHmac('sha256', config.appSecret).update(value).digest('base64url');

/** Проверка PKCE: code_verifier против сохранённого challenge. */
export function verifyPkce(verifier, challenge, method = 'S256') {
  if (!verifier || !challenge) return false;
  if (method === 'plain') return safeEqual(verifier, challenge);
  return safeEqual(sha256b64u(verifier), challenge);
}

// --- Ключи для подписи id_token ------------------------------------------
let keyCache = null;

export function getSigningKey() {
  if (keyCache) return keyCache;
  mkdirSync(config.dataDir, { recursive: true });
  const path = join(config.dataDir, 'signing-key.json');
  if (existsSync(path)) {
    keyCache = JSON.parse(readFileSync(path, 'utf8'));
    return keyCache;
  }
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  keyCache = {
    kid: randomBytes(8).toString('hex'),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
  writeFileSync(path, JSON.stringify(keyCache, null, 2), { mode: 0o600 });
  return keyCache;
}

export function publicJwk() {
  const { kid, publicPem } = getSigningKey();
  const jwk = createPublicKey(publicPem).export({ format: 'jwk' });
  return { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', use: 'sig', kid };
}

const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

/** Подписанный RS256 JWT (используется для id_token). */
export function signJwt(payload, { expiresIn = 3600 } = {}) {
  const { kid, privatePem } = getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + expiresIn, ...payload };
  const data = `${b64u({ alg: 'RS256', typ: 'JWT', kid })}.${b64u(body)}`;
  const signature = createSign('RSA-SHA256').update(data).sign(privatePem).toString('base64url');
  return `${data}.${signature}`;
}
