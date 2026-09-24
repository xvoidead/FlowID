// Демонстрационное приложение, которое входит через FlowID.
// Запуск:  npm run seed  &&  npm run demo   →  http://localhost:4000
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
let creds;
try {
  creds = JSON.parse(readFileSync(join(root, 'data', 'demo-client.json'), 'utf8'));
} catch {
  console.error('Сначала выполните: npm run seed');
  process.exit(1);
}

const ISSUER = process.env.ISSUER || creds.issuer || 'http://localhost:3000';
const REDIRECT_URI = 'http://localhost:4000/callback';
const PORT = 4000;
const pending = new Map();

const b64u = (buffer) => buffer.toString('base64url');
const page = (title, body) => `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{margin:0;font:16px/1.6 system-ui,sans-serif;background:#f1f5fa;color:#0b1320;display:grid;place-items:center;min-height:100vh;padding:24px}
main{background:#fff;border:1px solid #dde5f0;border-radius:18px;padding:32px;width:min(100%,640px)}
h1{margin:0 0 12px;font-size:24px}a.btn{display:inline-block;background:#1e92ff;color:#fff;text-decoration:none;padding:12px 20px;border-radius:12px;margin-top:16px}
pre{background:#0b1320;color:#dbe7f7;padding:16px;border-radius:12px;overflow:auto;font-size:13px}</style></head><body><main>${body}</main></body></html>`;

createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/') {
    return send(res, 200, page('Демо-клиент FlowID', `<h1>Демо-клиент</h1>
      <p>Приложение <code>${creds.client_id}</code> запросит у FlowID имя и почту.</p>
      <a class="btn" href="/login">Войти через FlowID</a>`));
  }

  if (url.pathname === '/login') {
    const verifier = b64u(randomBytes(32));
    const state = b64u(randomBytes(16));
    pending.set(state, verifier);
    const target = new URL(`${ISSUER}/oauth/authorize`);
    target.search = new URLSearchParams({
      response_type: 'code',
      client_id: creds.client_id,
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile email',
      state,
      code_challenge: b64u(createHash('sha256').update(verifier).digest()),
      code_challenge_method: 'S256',
    }).toString();
    res.writeHead(302, { Location: target.toString() });
    return res.end();
  }

  if (url.pathname === '/callback') {
    const error = url.searchParams.get('error');
    if (error) return send(res, 400, page('Отказ', `<h1>Вход не завершён</h1><p>${error}: ${url.searchParams.get('error_description') || ''}</p><a class="btn" href="/">Ещё раз</a>`));

    const state = url.searchParams.get('state');
    const verifier = pending.get(state);
    if (!verifier) return send(res, 400, page('Ошибка', '<h1>Неизвестный state</h1>'));
    pending.delete(state);

    const tokenResponse = await fetch(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: url.searchParams.get('code'),
        code_verifier: verifier,
        redirect_uri: REDIRECT_URI,
        client_id: creds.client_id,
        client_secret: creds.client_secret,
      }),
    });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok) return send(res, 400, page('Ошибка', `<h1>Токен не выдан</h1><pre>${JSON.stringify(tokens, null, 2)}</pre>`));

    const profile = await (await fetch(`${ISSUER}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })).json();
    const claims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());

    return send(res, 200, page('Вход выполнен', `<h1>Здравствуйте, ${profile.name || profile.sub}</h1>
      <p>Токены получены. Ниже — профиль из <code>/oauth/userinfo</code> и разобранный <code>id_token</code>.</p>
      <pre>${JSON.stringify({ userinfo: profile, id_token: claims }, null, 2)}</pre>
      <a class="btn" href="/">На главную</a>`));
  }

  send(res, 404, page('Не найдено', '<h1>Не найдено</h1>'));
}).listen(PORT, () => console.log(`\n  Демо-клиент → http://localhost:${PORT}  (провайдер: ${ISSUER})\n`));

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(body);
}
