// Проверка входа через VK: настоящий FlowID против локального макета VK ID.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Отдельная база, чтобы прогон не зависел от предыдущих запусков.
const dataDir = mkdtempSync(join(tmpdir(), 'flowid-vk-'));

const VK_PORT = 5555;
const FLOW = 'http://localhost:3100';
let failures = 0;
const assert = (name, ok, extra = '') => { if (!ok) failures++; console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${extra ? ' — ' + extra : ''}`); };

// Макет VK ID: отдаёт токен и профиль.
const vk = createServer(async (req, res) => {
  const body = await new Promise((r) => { let d = ''; req.on('data', (c) => d += c); req.on('end', () => r(d)); });
  const params = new URLSearchParams(body);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  if (req.url.startsWith('/oauth2/auth')) {
    if (!params.get('code_verifier')) return res.end(JSON.stringify({ error: 'no verifier' }));
    if (params.get('code') === 'squatted') return res.end(JSON.stringify({ access_token: 'vk_access_squatted', user_id: 888 }));
    return res.end(JSON.stringify({ access_token: 'vk_access', refresh_token: 'vk_refresh', expires_in: 3600, user_id: 777 }));
  }
  if (req.url.startsWith('/oauth2/user_info')) {
    // Отдельный профиль, чья почта уже занята неподтверждённым аккаунтом FlowID.
    if (params.get('access_token') === 'vk_access_squatted') {
      return res.end(JSON.stringify({ user: { user_id: 888, first_name: 'Жертва', email: 'squatted@example.com' } }));
    }
    if (params.get('access_token') !== 'vk_access') return res.end(JSON.stringify({ error: 'bad token' }));
    return res.end(JSON.stringify({ user: { user_id: 777, first_name: 'Иван', last_name: 'Петров', email: 'ivan.vk@example.com', avatar: 'https://vk.com/avatar.jpg' } }));
  }
  res.end('{}');
}).listen(VK_PORT);

const server = spawn('node', ['src/server.js'], {
  env: { ...process.env, PORT: '3100', ISSUER: FLOW, DATA_DIR: dataDir,
    VK_CLIENT_ID: '12345', VK_CLIENT_SECRET: 'vk_secret',
    VK_REDIRECT_URI: `${FLOW}/auth/vk/callback`,
    VK_TOKEN_URL: `http://localhost:${VK_PORT}/oauth2/auth`,
    VK_USERINFO_URL: `http://localhost:${VK_PORT}/oauth2/user_info`,
    VK_AUTHORIZE_URL: `http://localhost:${VK_PORT}/authorize` },
  stdio: 'ignore',
});
await new Promise((r) => setTimeout(r, 1200));

const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
async function call(path, opts = {}) {
  const res = await fetch(FLOW + path, { ...opts, redirect: 'manual', headers: { Cookie: cookieHeader(), ...(opts.headers || {}) } });
  for (const c of res.headers.getSetCookie?.() || []) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  return res;
}

// 1. старт: редирект на VK с PKCE
let r = await call('/auth/vk/start?next=/account');
const authorize = new URL(r.headers.get('location'));
assert('старт ведёт на VK ID', r.status === 302 && authorize.host === `localhost:${VK_PORT}`);
assert('PKCE и параметры на месте',
  authorize.searchParams.get('code_challenge_method') === 'S256'
  && authorize.searchParams.get('code_challenge')?.length > 20
  && authorize.searchParams.get('client_id') === '12345'
  && authorize.searchParams.get('scope') === 'vkid.personal_info email');

const state = authorize.searchParams.get('state');

// 2. подделанный state отклоняется
r = await call('/auth/vk/callback?code=abc&state=fake&device_id=1');
assert('чужой state отклонён', r.headers.get('location')?.startsWith('/login?error='));

// 3. успешный возврат
r = await call(`/auth/vk/callback?code=abc&state=${state}&device_id=dev1`);
assert('после VK возврат на /account', r.headers.get('location') === '/account', r.headers.get('location'));

r = await call('/api/auth/me');
const me = await r.json();
assert('создан пользователь из профиля VK', me.user?.name === 'Иван Петров' && me.user?.email === 'ivan.vk@example.com');
assert('почта VK считается подтверждённой', me.user?.email_verified === true);
assert('профиль VK привязан', me.identities?.some((i) => i.provider === 'vk'));

// 4. повторный вход тем же профилем VK не плодит аккаунтов
const firstId = me.user.id;
jar.clear();
r = await call('/auth/vk/start');
const state2 = new URL(r.headers.get('location')).searchParams.get('state');
await call(`/auth/vk/callback?code=abc&state=${state2}&device_id=dev1`);
const me2 = await (await call('/api/auth/me')).json();
assert('повторный вход — тот же аккаунт', me2.user?.id === firstId);

// 5. state одноразовый
r = await call(`/auth/vk/callback?code=abc&state=${state2}&device_id=dev1`);
assert('state одноразовый', r.headers.get('location')?.startsWith('/login?error='));

// 6. нельзя отвязать единственный способ входа
const csrf = decodeURIComponent(jar.get('flow_csrf') || '');
const account = await (await call('/api/account')).json();
const identityId = account.identities[0].id;
r = await call(`/api/account/identities/${identityId}/unlink`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: '{}',
});
assert('последний способ входа не отвязывается', r.status === 400 && (await r.json()).error === 'last_login_method');

// 7. задаём пароль — теперь отвязка разрешена
r = await call('/api/account/password', {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
  body: JSON.stringify({ password: 'novyparol1' }),
});
assert('пароль задаётся без текущего, если его не было', r.ok, String(r.status));
r = await call(`/api/account/identities/${identityId}/unlink`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: '{}',
});
assert('после пароля VK отвязывается', r.ok);

// 8. привязка VK к аккаунту с паролем
r = await call('/auth/vk/start?mode=link');
const state3 = new URL(r.headers.get('location')).searchParams.get('state');
r = await call(`/auth/vk/callback?code=abc&state=${state3}&device_id=dev1`);
assert('привязка возвращает в кабинет', r.headers.get('location') === '/account?tab=security&linked=vk', r.headers.get('location'));
const me3 = await (await call('/api/auth/me')).json();
assert('профиль VK снова привязан', me3.identities?.some((i) => i.provider === 'vk'));

// 9. ссылка возврата из чужого браузера не срабатывает
r = await call('/auth/vk/start');
const foreignState = new URL(r.headers.get('location')).searchParams.get('state');
r = await fetch(`${FLOW}/auth/vk/callback?code=abc&state=${foreignState}&device_id=dev1`, { redirect: 'manual' });
assert('state из другого браузера отклонён', r.headers.get('location')?.startsWith('/login?error=')
  && !r.headers.getSetCookie().some((c) => c.startsWith('flow_session=') && !c.includes('Max-Age=0')));

// 10. почта занята неподтверждённым аккаунтом — VK к нему не привязывается
const other = new Map();
const otherCall = async (path, opts = {}) => {
  const res = await fetch(FLOW + path, { ...opts, redirect: 'manual', headers: { Cookie: [...other].map(([k, v]) => `${k}=${v}`).join('; '), ...(opts.headers || {}) } });
  for (const c of res.headers.getSetCookie()) { const [pair] = c.split(';'); const i = pair.indexOf('='); other.set(pair.slice(0, i), pair.slice(i + 1)); }
  return res;
};
await otherCall('/api/config');
r = await otherCall('/api/auth/register', {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(other.get('flow_csrf')) },
  body: JSON.stringify({ name: 'Захватчик', email: 'squatted@example.com', password: 'zahvat1234' }),
});
assert('захватчик регистрирует чужую почту без подтверждения', r.status === 201);
jar.clear();
r = await call('/auth/vk/start');
const squatState = new URL(r.headers.get('location')).searchParams.get('state');
r = await call(`/auth/vk/callback?code=squatted&state=${squatState}&device_id=dev1`);
assert('VK не входит в аккаунт с неподтверждённой почтой', r.headers.get('location')?.startsWith('/login?error='), r.headers.get('location'));
const squatter = await (await otherCall('/api/auth/me')).json();
assert('профиль VK жертвы не привязан к захватчику', !squatter.identities?.some((i) => i.provider === 'vk'));

console.log(failures ? `\n${failures} проверок не прошли` : '\nВсе проверки VK прошли');
server.kill();
vk.close();
rmSync(dataDir, { recursive: true, force: true });
process.exit(failures ? 1 : 0);
