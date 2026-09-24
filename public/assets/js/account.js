// Личный кабинет: профиль, безопасность, выданные доступы, свои приложения.
import {
  api, $, $$, toast, onSubmit, wirePeek, wireStrength, initials,
  formatDate, formatWhen, describeDevice, copyText, busy, plural,
} from '/assets/js/core.js';

let state = null;
let config = {};

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

function emptyState(container, message, action) {
  const box = el('div', 'empty');
  box.append(el('p', null, message));
  if (action) box.append(action);
  container.append(box);
}

// --- Вкладки --------------------------------------------------------------

function wireTabs() {
  const tabs = $$('.tab');
  const ink = $('.tabs__ink');

  const moveInk = (tab) => {
    if (!ink || !tab) return;
    ink.style.width = `${tab.offsetWidth}px`;
    ink.style.transform = `translateX(${tab.offsetLeft}px)`;
  };

  const show = (name) => {
    const active = tabs.find((tab) => tab.dataset.tab === name);
    tabs.forEach((tab) => tab.setAttribute('aria-selected', String(tab === active)));
    $$('.tabpanel').forEach((panel) => { panel.hidden = panel.dataset.panel !== name; });
    moveInk(active);
    const url = new URL(location.href);
    url.searchParams.set('tab', name);
    history.replaceState(null, '', url);
  };

  tabs.forEach((tab) => tab.addEventListener('click', () => show(tab.dataset.tab)));
  const requested = new URLSearchParams(location.search).get('tab');
  show(tabs.some((t) => t.dataset.tab === requested) ? requested : 'profile');

  // Подчёркивание держится за вкладкой при смене ширины окна и после загрузки шрифтов.
  addEventListener('resize', () => moveInk(tabs.find((tab) => tab.getAttribute('aria-selected') === 'true')));
  document.fonts?.ready.then(() => moveInk(tabs.find((tab) => tab.getAttribute('aria-selected') === 'true')));
}

// --- Отрисовка ------------------------------------------------------------

function renderHeader() {
  const { user } = state;
  const avatar = $('#heroAvatar');
  avatar.textContent = '';
  if (user.avatar_url) {
    const img = el('img');
    img.src = user.avatar_url;
    img.alt = '';
    avatar.append(img);
  } else {
    avatar.textContent = initials(user.name);
  }
  $('#heroName').textContent = user.name;
  $('#heroMeta').textContent = [user.email, user.username ? `@${user.username}` : null]
    .filter(Boolean).join(' · ');

  const tags = $('#heroTags');
  tags.textContent = '';
  tags.append(el('span', `tag ${user.email_verified ? 'tag--ok' : 'tag--warn'}`,
    user.email_verified ? 'Почта подтверждена' : 'Почта не подтверждена'));
  tags.append(el('span', 'tag', `${plural(state.sessions.length, 'активная сессия', 'активные сессии', 'активных сессий')}`));

  $('#verifyNote').hidden = user.email_verified || !user.email;

  $('#emailValue').textContent = user.email || 'Почта не указана';
  $('#emailMeta').textContent = user.email_verified ? 'Используется для входа и восстановления' : 'Подтвердите, чтобы приложения получили её';
  $('#emailTag').className = `tag ${user.email_verified ? 'tag--ok' : 'tag--warn'}`;
  $('#emailTag').textContent = user.email_verified ? 'подтверждена' : 'ждёт подтверждения';
  $('#subValue').textContent = user.id;
  $('#createdValue').textContent = formatDate(user.created_at);

  $('#name').value = user.name;
  $('#username').value = user.username || '';
  $('#avatar_url').value = user.avatar_url || '';

  // Пользователь, вошедший только через VK, задаёт первый пароль без текущего.
  $('#currentWrap').hidden = !user.has_password;
  $('#passwordTitle').textContent = user.has_password ? 'Смена пароля' : 'Задать пароль';
}

const PROVIDERS = {
  vk: { title: 'VK ID', hint: 'вход по профилю VK' },
};

function renderIdentities() {
  const box = $('#identities');
  box.textContent = '';
  const linkedVk = state.identities.some((i) => i.provider === 'vk');
  $('#linkVk').hidden = linkedVk || !config.vk_enabled;

  const password = el('div', 'list__item');
  password.append(el('div', 'avatar', '••'));
  const passwordText = el('div');
  passwordText.append(el('div', 'list__title', 'Почта и пароль'));
  passwordText.append(el('div', 'list__meta', state.user.has_password ? 'настроен' : 'пароль ещё не задан'));
  password.append(passwordText, el('span', `tag ${state.user.has_password ? 'tag--ok' : ''}`, state.user.has_password ? 'активно' : 'нет'));
  box.append(password);

  for (const identity of state.identities) {
    const meta = PROVIDERS[identity.provider] || { title: identity.provider, hint: '' };
    const row = el('div', 'list__item');
    row.append(el('div', 'avatar', meta.title.slice(0, 2).toUpperCase()));
    const text = el('div');
    text.append(el('div', 'list__title', meta.title));
    text.append(el('div', 'list__meta', `${identity.display_name || meta.hint} · привязан ${formatWhen(identity.created_at)}`));
    const unlink = el('button', 'btn btn--quiet', 'Отвязать');
    unlink.type = 'button';
    unlink.addEventListener('click', async () => {
      if (!confirm(`Отвязать ${meta.title}? Входить через него больше не получится.`)) return;
      try {
        await api(`/api/account/identities/${identity.id}/unlink`, { method: 'POST', body: {} });
        toast(`${meta.title} отвязан`, 'ok');
        await load();
      } catch (error) { toast(error.message, 'error'); }
    });
    row.append(text, unlink);
    box.append(row);
  }
}

function renderSessions() {
  const box = $('#sessions');
  box.textContent = '';
  for (const session of state.sessions) {
    const current = session.id === state.current_session_id;
    const row = el('div', 'list__item');
    row.append(el('div', 'avatar', current ? '•' : '·'));
    const text = el('div');
    const title = el('div', 'list__title', describeDevice(session.user_agent || ''));
    if (current) title.append(' ', el('span', 'tag tag--accent', 'текущая'));
    text.append(title);
    text.append(el('div', 'list__meta',
      `${session.ip || 'адрес неизвестен'} · вход ${formatWhen(session.created_at)} · активность ${formatWhen(session.last_seen_at)}${session.method === 'vk' ? ' · через VK ID' : ''}`));
    row.append(text);
    if (!current) {
      const end = el('button', 'btn btn--quiet', 'Завершить');
      end.type = 'button';
      end.addEventListener('click', async () => {
        try {
          await api(`/api/account/sessions/${session.id}/revoke`, { method: 'POST', body: {} });
          toast('Сессия завершена', 'ok');
          await load();
        } catch (error) { toast(error.message, 'error'); }
      });
      row.append(end);
    } else {
      row.append(el('span', 'tag', 'это устройство'));
    }
    box.append(row);
  }
}

const EVENT_TITLES = {
  'login.success': 'Вход выполнен',
  'login.failed': 'Неудачная попытка входа',
  'user.registered': 'Аккаунт создан',
  'session.created': 'Начата сессия',
  'session.revoked': 'Сессия завершена',
  'session.revoked_all': 'Завершены другие сессии',
  'password.changed': 'Пароль изменён',
  'password.reset': 'Пароль сброшен',
  'password.reset_requested': 'Запрошен сброс пароля',
  'email.verified': 'Почта подтверждена',
  'profile.updated': 'Профиль обновлён',
  'identity.linked': 'Привязан внешний профиль',
  'identity.unlinked': 'Отвязан внешний профиль',
  'oauth.code_issued': 'Выдан код приложению',
  'oauth.token_issued': 'Выданы токены приложению',
  'oauth.token_refreshed': 'Токены обновлены',
  'oauth.consent_denied': 'Доступ приложению отклонён',
  'oauth.code_replay': 'Повтор кода — токены отозваны',
  'grant.revoked': 'Отозван доступ приложения',
  'client.created': 'Создано приложение',
  'client.updated': 'Изменено приложение',
  'client.deleted': 'Удалено приложение',
  'client.secret_rotated': 'Перевыпущен секрет',
};

function renderActivity() {
  const box = $('#activity');
  box.textContent = '';
  if (!state.activity.length) return emptyState(box, 'Событий пока нет.');
  for (const entry of state.activity) {
    const row = el('div', 'list__item');
    row.append(el('div', 'avatar', '›'));
    const text = el('div');
    text.append(el('div', 'list__title', EVENT_TITLES[entry.event] || entry.event));
    text.append(el('div', 'list__meta', `${formatWhen(entry.created_at)}${entry.ip ? ` · ${entry.ip}` : ''}`));
    row.append(text, el('span', 'tag mono', entry.event.split('.')[0]));
    box.append(row);
  }
}

function renderApps() {
  const box = $('#apps');
  box.textContent = '';
  if (!state.apps.length) {
    const link = el('a', 'btn btn--ghost', 'Как подключить приложение');
    link.href = '/docs';
    return emptyState(box, 'Ни одно приложение пока не получало доступ к вашему аккаунту.', link);
  }
  for (const app of state.apps) {
    const row = el('div', 'list__item');
    const logo = el('div', 'avatar');
    if (app.logo_url) {
      const img = el('img');
      img.src = app.logo_url;
      img.alt = '';
      logo.append(img);
    } else logo.textContent = initials(app.name);
    const text = el('div');
    text.append(el('div', 'list__title', app.name));
    text.append(el('div', 'list__meta',
      `${app.scope.map((s) => config.scopes?.[s] || s).join(', ')} · доступ выдан ${formatWhen(app.granted_at)}`));
    const revoke = el('button', 'btn btn--danger', 'Отозвать');
    revoke.type = 'button';
    revoke.addEventListener('click', async () => {
      if (!confirm(`Отозвать доступ «${app.name}»? Приложение придётся авторизовать заново.`)) return;
      try {
        await api(`/api/account/apps/${app.client_id}/revoke`, { method: 'POST', body: {} });
        toast('Доступ отозван', 'ok');
        await load();
      } catch (error) { toast(error.message, 'error'); }
    });
    row.append(logo, text, revoke);
    box.append(row);
  }
}

function secretPanel(container, secret) {
  const note = el('div', 'note note--warn');
  note.innerHTML = '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M10 7v4m0 3h.01"/><circle cx="10" cy="10" r="8"/></svg><span class="grow"></span>';
  const span = note.querySelector('span');
  span.append(el('div', null, 'Секрет показывается один раз. Сохраните его сейчас.'));
  const field = el('div', 'copyfield');
  const input = el('input', 'input');
  input.readOnly = true;
  input.value = secret;
  const copy = el('button', 'btn btn--ghost', 'Скопировать');
  copy.type = 'button';
  copy.addEventListener('click', () => copyText(secret, 'Секрет скопирован'));
  field.append(input, copy);
  span.append(field);
  container.prepend(note);
}

function renderClients() {
  const box = $('#clients');
  box.textContent = '';
  if (!state.clients.length) {
    return emptyState(box, 'Приложений пока нет. Создайте первое — client_id появится сразу.');
  }
  for (const client of state.clients) {
    const row = el('div', 'list__item');
    row.append(el('div', 'avatar', initials(client.name)));
    const text = el('div');
    text.append(el('div', 'list__title', client.name));
    const meta = el('div', 'list__meta');
    meta.append(el('span', 'mono', client.client_id));
    meta.append(` · ${plural(client.redirect_uris.length, 'адрес возврата', 'адреса возврата', 'адресов возврата')} · ${client.scopes.join(' ')}`);
    if (client.is_public) meta.append(' · публичный');
    text.append(meta);
    const actions = el('div', 'row');

    const copyId = el('button', 'btn btn--quiet', 'Копировать client_id');
    copyId.type = 'button';
    copyId.addEventListener('click', () => copyText(client.client_id, 'client_id скопирован'));

    const rotate = el('button', 'btn btn--ghost', 'Новый секрет');
    rotate.type = 'button';
    rotate.addEventListener('click', async () => {
      if (!confirm('Перевыпустить секрет? Старый перестанет работать сразу.')) return;
      busy(rotate, true, 'Выпускаем…');
      try {
        const result = await api(`/api/account/clients/${client.client_id}/secret`, { method: 'POST', body: {} });
        secretPanel($('[data-panel=dev]'), result.client_secret);
        toast('Секрет перевыпущен', 'ok');
        await load();
      } catch (error) {
        toast(error.message, 'error');
      } finally { busy(rotate, false); }
    });

    const remove = el('button', 'btn btn--danger', 'Удалить');
    remove.type = 'button';
    remove.addEventListener('click', async () => {
      if (!confirm(`Удалить «${client.name}»? Все его токены перестанут работать.`)) return;
      try {
        await api(`/api/account/clients/${client.client_id}/delete`, { method: 'POST', body: {} });
        toast('Приложение удалено', 'ok');
        await load();
      } catch (error) { toast(error.message, 'error'); }
    });

    actions.append(copyId, rotate, remove);
    row.append(text, actions);
    box.append(row);
  }
}

function renderScopeChoices() {
  const box = $('#scopeChoices');
  if (box.children.length) return;
  for (const [key, title] of Object.entries(config.scopes || {})) {
    const label = el('label', 'scopechoice');
    const input = el('input');
    input.type = 'checkbox';
    input.value = key;
    input.checked = ['openid', 'profile', 'email'].includes(key);
    input.disabled = key === 'openid';
    const text = el('span');
    text.append(el('span', null, title));
    text.append(el('span', 'key', key));
    label.append(input, text);
    box.append(label);
  }
}

// --- Загрузка и формы -----------------------------------------------------

async function load() {
  state = await api('/api/account');
  renderHeader();
  renderIdentities();
  renderSessions();
  renderActivity();
  renderApps();
  renderClients();
}

wireTabs();
wirePeek();
wireStrength($('#newPassword'), $('#strength'));

try {
  config = await api('/api/config');
  renderScopeChoices();
  await load();
} catch (error) {
  if (error.status === 401) location.href = '/login?next=/account';
  else toast(error.message || 'Не удалось загрузить аккаунт', 'error');
}

const params = new URLSearchParams(location.search);
if (params.get('linked') === 'vk') toast('VK ID привязан', 'ok');
if (params.get('welcome')) toast('Аккаунт создан. Проверьте почту — там письмо для подтверждения', 'ok');
if (params.get('error')) toast(params.get('error'), 'error');

onSubmit($('#profileForm'), async (values) => {
  await api('/api/account/profile', {
    method: 'POST',
    body: { name: values.name, username: values.username, avatar_url: values.avatar_url },
  });
  toast('Профиль сохранён', 'ok');
  await load();
}, { busyLabel: 'Сохраняем…' });

onSubmit($('#passwordForm'), async (values) => {
  await api('/api/account/password', {
    method: 'POST',
    body: {
      current_password: values.current_password,
      password: values.password,
      revoke_others: values.revoke_others === 'on',
    },
  });
  $('#passwordForm').reset();
  toast('Пароль обновлён', 'ok');
  await load();
}, { busyLabel: 'Сохраняем…' });

onSubmit($('#clientForm'), async (values) => {
  const scopes = $$('#scopeChoices input:checked').map((input) => input.value);
  const result = await api('/api/account/clients', {
    method: 'POST',
    body: {
      name: values.name,
      website: values.website,
      redirect_uris: values.redirect_uris.split('\n').map((s) => s.trim()).filter(Boolean),
      scopes,
      is_public: values.is_public === 'on',
    },
  });
  $('#clientForm').reset();
  await load();
  if (result.client_secret) secretPanel($('[data-panel=dev]'), result.client_secret);
  toast(`Приложение «${result.client.name}» создано`, 'ok');
}, { busyLabel: 'Создаём…' });

$('#revokeOthers').addEventListener('click', async () => {
  if (!confirm('Завершить все сессии, кроме текущей?')) return;
  try {
    await api('/api/account/sessions/revoke-others', { method: 'POST', body: {} });
    toast('Другие сессии завершены', 'ok');
    await load();
  } catch (error) { toast(error.message, 'error'); }
});

$('#resendVerify').addEventListener('click', async (event) => {
  busy(event.currentTarget, true, 'Отправляем…');
  try {
    await api('/api/auth/resend-verification', { method: 'POST', body: {} });
    toast('Письмо отправлено', 'ok');
  } catch (error) {
    toast(error.message, 'error');
  } finally { busy(event.currentTarget, false); }
});

$('#copySub').addEventListener('click', () => copyText(state.user.id, 'Идентификатор скопирован'));
