import { config } from '../config.js';
import { run, one, now, audit } from '../db.js';
import { randomToken, sha256b64u, safeEqual } from '../lib/crypto.js';
import {
  createSession, createUser, findUserByEmail, findIdentity, findUserById,
  linkIdentity,
} from '../lib/users.js';
import { isSafeNext } from '../lib/validate.js';
import {
  redirect, setCookie, parseCookies, clientIp, enforceRateLimit, HttpError,
} from '../lib/http.js';

const STATE_TTL = 10 * 60_000;

// state дублируется в cookie того браузера, который начал вход. Без этого
// чужую ссылку возврата от VK можно подсунуть жертве и войти или привязать
// профиль за неё.
const STATE_COOKIE = 'flow_vk_state';
const STATE_COOKIE_PATH = '/auth/vk';

function vkUnavailable() {
  return new HttpError(503, 'vk_not_configured',
    'Вход через VK не настроен: добавьте VK_CLIENT_ID и VK_CLIENT_SECRET в .env');
}

/** Шаг 1: уводим пользователя на VK ID с PKCE. */
export function start(req, res, url) {
  if (!config.vk.enabled) throw vkUnavailable();
  enforceRateLimit(req, 'vk-start', { limit: 30, windowMs: 10 * 60_000 });

  const verifier = randomToken(32);
  const state = randomToken(24);
  const next = url.searchParams.get('next');
  const linkMode = url.searchParams.get('mode') === 'link';

  run(`INSERT INTO ext_states (state, provider, verifier, next_url, link_user_id, expires_at, created_at)
       VALUES (?,?,?,?,?,?,?)`,
    state, 'vk', verifier,
    isSafeNext(next) ? next : null,
    linkMode && req.auth ? req.auth.user.id : null,
    now() + STATE_TTL, now());
  setCookie(res, STATE_COOKIE, state, { maxAge: STATE_TTL / 1000, path: STATE_COOKIE_PATH });

  const target = new URL(config.vk.authorizeUrl);
  target.searchParams.set('response_type', 'code');
  target.searchParams.set('client_id', config.vk.clientId);
  target.searchParams.set('redirect_uri', config.vk.redirectUri);
  target.searchParams.set('scope', config.vk.scope);
  target.searchParams.set('state', state);
  target.searchParams.set('code_challenge', sha256b64u(verifier));
  target.searchParams.set('code_challenge_method', 'S256');
  redirect(res, target.toString());
}

async function postForm(url, params) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { error: 'bad_response', raw: text.slice(0, 300) }; }
  return { ok: response.ok, status: response.status, data };
}

function failure(res, message) {
  redirect(res, `/login?error=${encodeURIComponent(message)}`);
}

/** Шаг 2: обмениваем код на токены, забираем профиль, входим или связываем аккаунт. */
export async function callback(req, res, url) {
  if (!config.vk.enabled) throw vkUnavailable();

  const q = url.searchParams;
  if (q.get('error')) {
    return failure(res, q.get('error_description') || 'VK отклонил вход');
  }

  const state = q.get('state') || '';
  const browserState = parseCookies(req)[STATE_COOKIE] || '';
  const stored = one('SELECT * FROM ext_states WHERE state = ? AND provider = ?', state, 'vk');
  if (stored) run('DELETE FROM ext_states WHERE state = ?', state);
  if (!stored || stored.expires_at < now()) {
    return failure(res, 'Запрос входа через VK устарел. Попробуйте ещё раз');
  }
  if (!browserState || !safeEqual(browserState, state)) {
    audit('vk.state_mismatch', { ip: clientIp(req) });
    return failure(res, 'Вход через VK начат в другом браузере. Начните его заново здесь');
  }
  // Стираем cookie только при совпадении: подсунутая ссылка с чужим state
  // не должна сбивать вход, который человек начал сам.
  setCookie(res, STATE_COOKIE, '', { maxAge: 0, path: STATE_COOKIE_PATH });
  // Привязка завершается только в сессии того же человека, который её начал.
  if (stored.link_user_id && req.auth?.user.id !== stored.link_user_id) {
    return failure(res, 'Сессия сменилась во время привязки VK. Войдите и привяжите профиль заново');
  }

  const code = q.get('code');
  const deviceId = q.get('device_id') || '';
  if (!code) return failure(res, 'VK не передал код авторизации');

  const tokenResponse = await postForm(config.vk.tokenUrl, {
    grant_type: 'authorization_code',
    code,
    code_verifier: stored.verifier,
    client_id: config.vk.clientId,
    ...(config.vk.clientSecret ? { client_secret: config.vk.clientSecret } : {}),
    device_id: deviceId,
    redirect_uri: config.vk.redirectUri,
    state,
  });
  if (!tokenResponse.ok || !tokenResponse.data.access_token) {
    audit('vk.token_failed', { ip: clientIp(req), detail: tokenResponse.data });
    return failure(res, 'VK не выдал токен доступа. Проверьте настройки приложения');
  }

  const profileResponse = await postForm(config.vk.userInfoUrl, {
    client_id: config.vk.clientId,
    access_token: tokenResponse.data.access_token,
  });
  const vkUser = profileResponse.data?.user;
  if (!vkUser?.user_id) {
    audit('vk.profile_failed', { ip: clientIp(req), detail: profileResponse.data });
    return failure(res, 'Не удалось получить профиль VK');
  }

  const profile = {
    provider: 'vk',
    providerUserId: String(vkUser.user_id),
    email: (vkUser.email || '').toLowerCase() || null,
    displayName: [vkUser.first_name, vkUser.last_name].filter(Boolean).join(' ') || `VK ${vkUser.user_id}`,
    avatarUrl: vkUser.avatar || null,
    profileUrl: `https://vk.com/id${vkUser.user_id}`,
  };

  let user;
  let method = 'vk';

  const identity = findIdentity('vk', profile.providerUserId);
  const linkUser = stored.link_user_id ? findUserById(stored.link_user_id) : null;

  if (linkUser) {
    if (identity && identity.user_id !== linkUser.id) {
      return redirect(res, '/account?tab=security&error=' + encodeURIComponent('Этот профиль VK уже привязан к другому аккаунту'));
    }
    linkIdentity(linkUser.id, profile);
    return redirect(res, '/account?tab=security&linked=vk');
  }

  if (identity) {
    user = findUserById(identity.user_id);
    if (!user || user.disabled) return failure(res, 'Аккаунт отключён');
  } else if (profile.email && findUserByEmail(profile.email)) {
    // Связываем автоматически, только если владение почтой доказано и в FlowID.
    // Иначе кто-то мог заранее зарегистрировать чужую почту со своим паролем
    // и получить доступ к аккаунту, как только настоящий владелец войдёт через VK.
    user = findUserByEmail(profile.email);
    if (!user.email_verified) {
      audit('vk.link_refused_unverified', { userId: user.id, ip: clientIp(req) });
      return failure(res, 'Аккаунт с этой почтой уже есть, но почта в нём не подтверждена. '
        + 'Войдите по паролю или восстановите его, затем привяжите VK в настройках безопасности');
    }
    if (user.disabled) return failure(res, 'Аккаунт отключён');
    linkIdentity(user.id, profile);
    method = 'vk-linked';
  } else {
    user = await createUser({
      email: profile.email,
      password: null,
      name: profile.displayName,
      avatarUrl: profile.avatarUrl,
      emailVerified: Boolean(profile.email),
    });
    linkIdentity(user.id, profile);
    audit('user.registered', { userId: user.id, ip: clientIp(req), detail: { via: 'vk' } });
    method = 'vk-signup';
  }

  const { token, expiresAt } = createSession(user.id, {
    ip: clientIp(req), userAgent: req.headers['user-agent'], method: 'vk',
  });
  setCookie(res, config.session.cookie, token, { maxAge: Math.floor((expiresAt - now()) / 1000) });
  audit('login.success', { userId: user.id, ip: clientIp(req), detail: { method } });

  redirect(res, stored.next_url || '/account');
}

export const vkStatus = () => ({ enabled: config.vk.enabled });
