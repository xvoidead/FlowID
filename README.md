# FlowID

Провайдер входа на Node.js без внешних зависимостей: регистрация и вход по почте и паролю,
вход через **VK ID**, и полноценный **OAuth 2.1 / OpenID Connect** для сторонних приложений.
Фронтенд — десктоп и мобильный, со светлой и тёмной темой, акцент `#1e92ff`.

## Запуск

```bash
cp .env.example .env        # минимум — задать APP_SECRET
npm start                   # http://localhost:3000
```

Ни `npm install`, ни базы данных не нужно: используются встроенные `node:sqlite`, `node:crypto`
и `node:http`. Требуется Node.js 22.5+ (проверено на 26).

Демо-прогон полного цикла входа:

```bash
npm run seed   # демо-пользователь demo@flowid.local / flowid12345 и демо-приложение
npm run demo   # клиентское приложение на http://localhost:4000
```

## Что внутри

| Возможность | Детали |
| --- | --- |
| Регистрация и вход | scrypt-хеш пароля, проверка слабых паролей, подтверждение почты, сброс по ссылке |
| Сессии | cookie `HttpOnly` + `SameSite=Lax`, список устройств, завершение любой сессии |
| VK ID | authorization code с PKCE, привязка и отвязка профиля, вход по уже подтверждённой почте |
| OAuth 2.1 / OIDC | код с PKCE (S256), ротация refresh-токенов, отзыв при повторе кода, `id_token` на RS256 |
| Экран согласия | разрешения на человеческом языке, необязательные можно снять, согласие запоминается |
| Кабинет разработчика | свои приложения, `client_id`, перевыпуск секрета, посимвольная сверка redirect URI |
| Защита | CSRF двойной отправкой токена, ограничение частоты запросов, журнал событий аккаунта |

## Эндпоинты

```
GET  /.well-known/openid-configuration   метаданные для библиотек
GET  /oauth/jwks.json                    открытый ключ для проверки id_token
GET  /oauth/authorize                    начало входа, выдаёт код
POST /oauth/token                        authorization_code и refresh_token
GET  /oauth/userinfo                     профиль по Bearer-токену
POST /oauth/revoke, /oauth/introspect    отзыв и проверка токена
GET  /auth/vk/start, /auth/vk/callback   вход через VK ID
```

Разрешения: `openid`, `profile`, `email`, `offline_access`.

## Настройка VK ID

1. Создайте приложение на [id.vk.com](https://id.vk.com/about/business/go).
2. В доверенные redirect URL добавьте `http://localhost:3000/auth/vk/callback`.
3. Заполните `VK_CLIENT_ID` и `VK_CLIENT_SECRET` в `.env` и перезапустите сервер.

Пока переменные пусты, кнопка VK не показывается, а `/auth/vk/start` отвечает понятной ошибкой.

## Письма

Без SMTP письма печатаются в консоль — ссылки подтверждения и сброса можно скопировать оттуда.
Свой транспорт подключается в одном месте: `src/lib/mailer.js`.

## Проверки

```bash
npm test
```

Обе сюиты поднимают собственный сервер во временной базе, так что прогон не трогает данные
разработки и повторяется сколько угодно раз. `scripts/vk.mjs` (14 проверок) работает против
макета VK ID, `scripts/e2e.mjs` (35 проверок) проходит регистрацию, экран согласия, обмен кода,
ротацию refresh-токенов, отзыв и кабинет.

## Структура

```
src/
  server.js          маршрутизатор и обработка ошибок
  config.js          настройки из .env
  db.js              схема SQLite
  lib/               crypto, http, csrf, users, clients, validate, mailer
  routes/            auth, oauth, vk, account
public/              страницы и дизайн-система (assets/css/flowid.css)
examples/demo-client приложение-пример на 120 строк
```

## Перед продакшеном

- Задайте `APP_SECRET` и `ISSUER` с `https://` — cookie тогда выставляются с флагом `Secure`.
- Поставьте сервер за обратный прокси с TLS и пробросом `X-Forwarded-For`.
- Подключите реальную отправку писем.
- Файл `data/signing-key.json` — приватный ключ подписи `id_token`: храните его как секрет
  и не теряйте при переносе, иначе все выданные `id_token` перестанут проверяться.
