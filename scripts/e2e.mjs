import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Отдельный сервер и база: прогон не зависит от состояния разработки
// и не упирается в ограничение частоты запросов.
const PORT = 3200;
const BASE = `http://localhost:${PORT}`;
const dataDir = mkdtempSync(join(tmpdir(), 'flowid-e2e-'));
const server = spawn('node', ['src/server.js'], {
  env: { ...process.env, PORT: String(PORT), ISSUER: BASE, DATA_DIR: dataDir, VK_CLIENT_ID: '' },
  stdio: 'ignore',
});
await new Promise((resolve) => setTimeout(resolve, 1200));

const b64u = (b) => b.toString('base64url');
const jar = new Map();
let csrf = '';

function stash(res) {
  for (const c of res.headers.getSetCookie?.() || []) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  if (jar.has('flow_csrf')) csrf = decodeURIComponent(jar.get('flow_csrf'));
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

async function call(path, opts = {}) {
  const res = await fetch(BASE + path, {
    ...opts,
    redirect: 'manual',
    headers: { Cookie: cookieHeader(), 'X-CSRF-Token': csrf, ...(opts.headers || {}) },
  });
  stash(res);
  return res;
}

const check = (name, ok, extra = '') => console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${extra ? ' — ' + extra : ''}`);
let failures = 0;
const assert = (name, ok, extra) => { if (!ok) failures++; check(name, ok, extra); };

// 0. получить csrf
await call('/api/config');

// 1. регистрация
const email = `test${Date.now()}@example.com`;
let r = await call('/api/auth/register', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'Тест Тестов', email, password: 'parol12345' }),
});
assert('регистрация', r.status === 201, `${r.status} ${await r.clone().text().then(t=>t.slice(0,120))}`);

// 1a. слабый пароль отвергается
r = await call('/api/auth/register', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'X Y', email: 'weak@example.com', password: 'password' }),
});
assert('слабый пароль отклонён', r.status === 400 && (await r.json()).field === 'password');

// 1b. дубль почты
r = await call('/api/auth/register', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'X Y', email, password: 'parol12345' }),
});
assert('повторная почта отклонена', r.status === 400 && (await r.json()).error === 'email_taken');

// 1c. CSRF обязателен
r = await fetch(BASE + '/api/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookieHeader() },
  body: JSON.stringify({ email, password: 'parol12345' }),
});
assert('запрос без CSRF отклонён', r.status === 403);

// 2. me
r = await call('/api/auth/me');
const me = await r.json();
assert('сессия активна', me.user?.email === email);

// 2a. приложение для проверки OAuth
r = await call('/api/account/clients', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Демо-клиент',
    description: 'Пример подключения к FlowID',
    redirect_uris: ['http://localhost:4000/callback'],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
  }),
});
const registered = await r.json();
const creds = { client_id: registered.client?.client_id, client_secret: registered.client_secret };
assert('приложение создано', r.status === 201 && Boolean(creds.client_id), JSON.stringify(registered).slice(0, 150));

// 3. authorize + PKCE
const verifier = b64u(randomBytes(32));
const challenge = b64u(createHash('sha256').update(verifier).digest());
const authUrl = `/oauth/authorize?response_type=code&client_id=${creds.client_id}&redirect_uri=${encodeURIComponent('http://localhost:4000/callback')}&scope=${encodeURIComponent('openid profile email offline_access')}&state=xyz&code_challenge=${challenge}&code_challenge_method=S256`;
r = await call(authUrl);
const consentLoc = r.headers.get('location');
assert('authorize ведёт на согласие', r.status === 302 && consentLoc.startsWith('/consent?request='), consentLoc);

const requestId = new URLSearchParams(consentLoc.split('?')[1]).get('request');
r = await call(`/api/oauth/consent?request=${requestId}`);
const info = await r.json();
assert('экран согласия отдаёт данные', info.client?.name === 'Демо-клиент' && info.scopes.length === 4);

r = await call('/api/oauth/consent', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ request: requestId, allow: true, scopes: ['profile', 'email', 'offline_access'] }),
});
const decision = await r.json();
const redirectUrl = new URL(decision.redirect);
const code = redirectUrl.searchParams.get('code');
assert('код выдан', Boolean(code) && redirectUrl.searchParams.get('state') === 'xyz');

// 4. плохой verifier
r = await fetch(BASE + '/oauth/token', {
  method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: 'wrong', redirect_uri: 'http://localhost:4000/callback', client_id: creds.client_id, client_secret: creds.client_secret }),
});
assert('PKCE защищает код', r.status === 400 && (await r.json()).error === 'invalid_grant');

// 5. обмен кода
const form = (o) => ({ method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o) });
r = await fetch(BASE + '/oauth/token', form({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'http://localhost:4000/callback', client_id: creds.client_id, client_secret: creds.client_secret }));
const tokens = await r.json();
assert('токены выданы', r.ok && tokens.access_token && tokens.id_token && tokens.refresh_token, JSON.stringify(tokens).slice(0, 150));

// 5a. id_token
const header = JSON.parse(Buffer.from(tokens.id_token.split('.')[0], 'base64url'));
const claims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url'));
assert('id_token RS256 с kid', header.alg === 'RS256' && Boolean(header.kid));
assert('claims корректны', claims.iss === BASE && claims.aud === creds.client_id && claims.email === email);

// 5b. подпись проверяется ключом из JWKS
const { createPublicKey, createVerify } = await import('node:crypto');
const jwk = (await (await fetch(BASE + '/oauth/jwks.json')).json()).keys[0];
const key = createPublicKey({ key: { ...jwk, kty: 'RSA' }, format: 'jwk' });
const [h, p, s] = tokens.id_token.split('.');
assert('подпись id_token валидна', createVerify('RSA-SHA256').update(`${h}.${p}`).verify(key, Buffer.from(s, 'base64url')));

// 6. повтор кода отзывает токены
r = await fetch(BASE + '/oauth/token', form({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'http://localhost:4000/callback', client_id: creds.client_id, client_secret: creds.client_secret }));
assert('повтор кода отклонён', r.status === 400);
r = await fetch(BASE + '/oauth/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
assert('токены после повтора отозваны', r.status === 401);

// 7. свежий цикл через тихое согласие (grant уже сохранён)
const v2 = b64u(randomBytes(32));
const c2 = b64u(createHash('sha256').update(v2).digest());
r = await call(`/oauth/authorize?response_type=code&client_id=${creds.client_id}&redirect_uri=${encodeURIComponent('http://localhost:4000/callback')}&scope=${encodeURIComponent('openid profile email offline_access')}&state=s2&code_challenge=${c2}&code_challenge_method=S256`);
const loc2 = r.headers.get('location');
assert('повторный вход без экрана согласия', loc2.startsWith('http://localhost:4000/callback?'), loc2);
const code2 = new URL(loc2).searchParams.get('code');
r = await fetch(BASE + '/oauth/token', form({ grant_type: 'authorization_code', code: code2, code_verifier: v2, redirect_uri: 'http://localhost:4000/callback', client_id: creds.client_id, client_secret: creds.client_secret }));
const t2 = await r.json();
assert('вторые токены выданы', r.ok && t2.access_token);

// 8. userinfo
r = await fetch(BASE + '/oauth/userinfo', { headers: { Authorization: `Bearer ${t2.access_token}` } });
const profile = await r.json();
assert('userinfo отдаёт профиль', r.ok && profile.email === email && profile.name === 'Тест Тестов');

// 9. refresh с ротацией
r = await fetch(BASE + '/oauth/token', form({ grant_type: 'refresh_token', refresh_token: t2.refresh_token, client_id: creds.client_id, client_secret: creds.client_secret }));
const t3 = await r.json();
assert('refresh работает', r.ok && t3.access_token && t3.access_token !== t2.access_token);
r = await fetch(BASE + '/oauth/token', form({ grant_type: 'refresh_token', refresh_token: t2.refresh_token, client_id: creds.client_id, client_secret: creds.client_secret }));
assert('старый refresh отозван', r.status === 400);

// 10. introspect и revoke
r = await fetch(BASE + '/oauth/introspect', form({ token: t3.access_token, client_id: creds.client_id, client_secret: creds.client_secret }));
assert('introspect активен', (await r.json()).active === true);
r = await fetch(BASE + '/oauth/revoke', form({ token: t3.access_token, client_id: creds.client_id, client_secret: creds.client_secret }));
assert('revoke отвечает 200', r.ok);
r = await fetch(BASE + '/oauth/userinfo', { headers: { Authorization: `Bearer ${t3.access_token}` } });
assert('отозванный токен не работает', r.status === 401);

// 11. чужой redirect_uri / неверный секрет
r = await call(`/oauth/authorize?response_type=code&client_id=${creds.client_id}&redirect_uri=http://evil.example/cb&scope=openid`);
assert('чужой redirect_uri отклонён', r.headers.get('location')?.startsWith(`${BASE}/oauth/error`));
r = await fetch(BASE + '/oauth/token', form({ grant_type: 'authorization_code', code: 'x', client_id: creds.client_id, client_secret: 'wrong' }));
assert('неверный секрет отклонён', r.status === 401);

// 12. кабинет
r = await call('/api/account');
const account = await r.json();
assert('кабинет отдаёт данные', r.ok && account.apps.length === 1 && account.sessions.length >= 1 && account.clients.length === 1);

r = await call('/api/account/profile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Новое Имя', username: `tester_${Date.now().toString(36)}` }) });
assert('профиль сохраняется', r.ok && (await r.json()).user.username?.startsWith('tester_'));

assert('секрет выдан один раз при создании', creds.client_secret?.startsWith('fsec_'));

r = await call('/api/account/clients', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'Плохой', redirect_uris: ['http://example.com/cb'] }),
});
assert('http вне localhost отклонён', r.status === 400);

r = await call(`/api/account/apps/${creds.client_id}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
assert('доступ приложения отзывается', r.ok);

// 13. смена пароля и выход
r = await call('/api/account/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current_password: 'parol12345', password: 'novyparol99' }) });
assert('пароль меняется', r.ok);
r = await call('/api/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
assert('выход работает', r.ok);
r = await call('/api/auth/me');
assert('после выхода сессии нет', (await r.json()).user === null);

r = await call('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'novyparol99' }) });
assert('вход с новым паролем', r.ok);
r = await call('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'parol12345' }) });
assert('старый пароль не подходит', r.status === 401);

// 14. Защита по итогам ревью
const json = (body) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

for (const bad of ['javascript:alert(document.domain)//', 'JavaScript:alert(1)', 'data:text/html,x', 'file:///etc/passwd']) {
  r = await call('/api/account/clients', json({ name: 'Злое', redirect_uris: [bad] }));
  assert(`redirect URI ${bad.split(':')[0]}: отклонён`, r.status === 400);
}
r = await call('/api/account/clients', json({ name: 'Нативное', redirect_uris: ['com.example.app:/cb'], is_public: true }));
assert('схема нативного приложения разрешена', r.status === 201);

r = await call('/api/auth/login', json({ email, password: 'novyparol99', next: '/\\evil.example' }));
assert('next с обратной косой не уводит с сайта', (await r.json()).next === '/account');

// prompt=login: после свежего входа человек идёт дальше, а не по кругу
const prompted = await (await call('/api/account/clients', json({ name: 'Промпт', redirect_uris: ['http://localhost:9/cb'] }))).json();
const authz = `/oauth/authorize?response_type=code&client_id=${prompted.client.client_id}`
  + `&redirect_uri=${encodeURIComponent('http://localhost:9/cb')}&scope=openid&state=s1`;
r = await call(`${authz}&prompt=login`);
const loginNext = new URL(r.headers.get('location'), BASE).searchParams.get('next');
assert('prompt=login ведёт на вход', r.headers.get('location')?.startsWith('/login?') && loginNext?.includes('login_after='));
assert('в адресе возврата нет prompt=login', !new URL(loginNext, BASE).searchParams.has('prompt'));
r = await call(loginNext);
assert('старая сессия не проходит повторный вход', r.headers.get('location')?.startsWith('/login?'));
await new Promise((resolve) => setTimeout(resolve, 5));
r = await call('/api/auth/login', json({ email, password: 'novyparol99', next: loginNext }));
r = await call((await r.json()).next);
assert('после входа prompt=login не зацикливается', !r.headers.get('location')?.startsWith('/login'), r.headers.get('location'));

r = await fetch(`${BASE}${authz}&prompt=none`, { redirect: 'manual' });
const silent = new URL(r.headers.get('location'));
assert('prompt=none без сессии → login_required', silent.origin === 'http://localhost:9' && silent.searchParams.get('error') === 'login_required' && silent.searchParams.get('state') === 's1');

// Битые данные не роняют сервер
r = await fetch(BASE + '/api/config', { headers: { Cookie: 'junk=%; other=%E0%A4%A' } });
assert('битая cookie не даёт 500', r.status === 200);
r = await call('/api/account/sessions/%E0%A4%A/revoke', json({}));
assert('битый %-путь не даёт 500', r.status === 404);
r = await fetch(BASE + '/oauth/token', { method: 'POST', headers: { Authorization: `Basic ${Buffer.from('%E0:%').toString('base64')}` }, body: '' });
assert('битый Basic-заголовок → 401', r.status === 401);

r = await fetch(BASE + '/logout?next=%2F%5Cevil.example', { redirect: 'manual' });
assert('/logout не уводит на чужой сайт', r.headers.get('location') === '/');

// Последним: исчерпывает лимит входа
let limited = 0;
for (let i = 0; i < 25; i++) {
  r = await fetch(BASE + '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookieHeader(), 'X-CSRF-Token': csrf, 'X-Forwarded-For': `10.0.0.${i}` },
    body: JSON.stringify({ email, password: 'nevernyi1' }),
  });
  if (r.status === 429) limited++;
}
assert('X-Forwarded-For не обходит лимит входа', limited > 0, `заблокировано ${limited} из 25`);

console.log(failures ? `\n${failures} проверок не прошли` : '\nВсе проверки прошли');
server.kill();
rmSync(dataDir, { recursive: true, force: true });
process.exit(failures ? 1 : 0);
