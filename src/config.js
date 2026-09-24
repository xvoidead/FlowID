import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Мини-загрузчик .env, чтобы не тянуть зависимости.
function loadEnvFile(path) {
  if (!existsSync(path)) return;
  for (const raw of readFileSync(path, 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}
loadEnvFile(join(ROOT, '.env'));

const env = process.env;

export const config = {
  port: Number(env.PORT || 3000),
  issuer: (env.ISSUER || `http://localhost:${env.PORT || 3000}`).replace(/\/$/, ''),
  isProd: env.NODE_ENV === 'production',
  // Включайте только за своим обратным прокси, иначе X-Forwarded-For подделывается.
  trustProxy: env.TRUST_PROXY === '1' || env.TRUST_PROXY === 'true',
  appSecret: env.APP_SECRET || 'flowid-development-secret-do-not-use-in-production',
  dataDir: env.DATA_DIR ? (env.DATA_DIR.startsWith('/') ? env.DATA_DIR : join(ROOT, env.DATA_DIR)) : join(ROOT, 'data'),
  publicDir: join(ROOT, 'public'),

  session: {
    cookie: 'flow_session',
    csrfCookie: 'flow_csrf',
    ttlDays: 30,
  },

  oauth: {
    codeTtlSeconds: 600,
    accessTtlSeconds: 3600,
    refreshTtlDays: 60,
    scopes: {
      openid: 'Подтвердить, что это вы',
      profile: 'Имя, ник и аватар',
      email: 'Адрес почты и статус подтверждения',
      offline_access: 'Оставаться в аккаунте, когда вы не в сети',
    },
  },

  vk: {
    clientId: env.VK_CLIENT_ID || '',
    clientSecret: env.VK_CLIENT_SECRET || '',
    redirectUri: env.VK_REDIRECT_URI || `${(env.ISSUER || 'http://localhost:3000').replace(/\/$/, '')}/auth/vk/callback`,
    scope: 'vkid.personal_info email',
    // Адреса вынесены в переменные, чтобы их можно было подменить на стенде.
    authorizeUrl: env.VK_AUTHORIZE_URL || 'https://id.vk.com/authorize',
    tokenUrl: env.VK_TOKEN_URL || 'https://id.vk.com/oauth2/auth',
    userInfoUrl: env.VK_USERINFO_URL || 'https://id.vk.com/oauth2/user_info',
    get enabled() { return Boolean(this.clientId); },
  },

  mail: {
    from: env.MAIL_FROM || 'FlowID <no-reply@flowid.local>',
  },
};

if (config.isProd && config.appSecret.startsWith('flowid-development')) {
  throw new Error('APP_SECRET обязателен в production. Задайте его в .env');
}
