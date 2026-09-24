// Общие утилиты интерфейса FlowID: запросы, уведомления, тема, формы.

export const $ = (selector, scope = document) => scope.querySelector(selector);
export const $$ = (selector, scope = document) => [...scope.querySelectorAll(selector)];

export const readCookie = (name) => document.cookie
  .split('; ')
  .find((part) => part.startsWith(`${name}=`))
  ?.split('=').slice(1).join('=');

export const csrfToken = () => decodeURIComponent(readCookie('flow_csrf') || '');

export class ApiError extends Error {
  constructor(status, payload) {
    super(payload?.message || payload?.error_description || 'Запрос не удался');
    this.status = status;
    this.code = payload?.error || 'error';
    this.field = payload?.field;
  }
}

export async function api(path, { method = 'GET', body } = {}) {
  const response = await fetch(path, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      'X-CSRF-Token': csrfToken(),
    },
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(response.status, payload);
  return payload;
}

// --- Уведомления ----------------------------------------------------------

const ICONS = {
  ok: '<path d="M4 10.5 8 14.5l8-9"/>',
  error: '<path d="M10 5v7m0 3h.01"/><circle cx="10" cy="10" r="8"/>',
  info: '<circle cx="10" cy="10" r="8"/><path d="M10 9v5m0-8h.01"/>',
};

function toastLayer() {
  let layer = $('.toasts');
  if (!layer) {
    layer = document.createElement('div');
    layer.className = 'toasts';
    layer.setAttribute('role', 'status');
    layer.setAttribute('aria-live', 'polite');
    document.body.append(layer);
  }
  return layer;
}

export function toast(message, kind = 'info') {
  const node = document.createElement('div');
  node.className = `toast toast--${kind}`;
  node.innerHTML = `<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"
    stroke-linecap="round" stroke-linejoin="round">${ICONS[kind] || ICONS.info}</svg><span></span>`;
  node.lastElementChild.textContent = message;
  toastLayer().append(node);
  setTimeout(() => {
    node.classList.add('toast--leaving');
    node.addEventListener('animationend', () => node.remove(), { once: true });
    setTimeout(() => node.remove(), 400);
  }, kind === 'error' ? 6000 : 3800);
}

// --- Формы ----------------------------------------------------------------

export function setFieldError(form, field, message) {
  const wrap = form.querySelector(`[data-field='${field}']`);
  if (!wrap) return false;
  wrap.dataset.invalid = 'true';
  const slot = wrap.querySelector('.field__error');
  if (slot) slot.textContent = message;
  wrap.querySelector('.input')?.setAttribute('aria-invalid', 'true');
  return true;
}

export function clearFieldErrors(form) {
  $$('[data-field]', form).forEach((wrap) => {
    delete wrap.dataset.invalid;
    wrap.querySelector('.input')?.removeAttribute('aria-invalid');
  });
}

export function showNote(node, message, kind = 'error') {
  if (!node) return;
  node.className = `note note--${kind}`;
  node.querySelector('span').textContent = message;
  node.hidden = false;
}

export function busy(button, isBusy, labelWhenBusy) {
  if (!button) return;
  if (isBusy) {
    button.dataset.label = button.textContent;
    button.setAttribute('aria-busy', 'true');
    button.innerHTML = `<span class="spinner" aria-hidden="true"></span>${labelWhenBusy || button.dataset.label}`;
  } else {
    button.removeAttribute('aria-busy');
    button.textContent = button.dataset.label || button.textContent;
  }
}

/** Обёртка сабмита: блокирует кнопку, разбирает ошибки полей, показывает сообщение. */
export function onSubmit(form, handler, { note, button, busyLabel } = {}) {
  const submitButton = button || form.querySelector('[type=submit]');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearFieldErrors(form);
    if (note) note.hidden = true;
    busy(submitButton, true, busyLabel);
    try {
      await handler(Object.fromEntries(new FormData(form)));
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Нет связи с сервером. Проверьте подключение';
      if (!(error instanceof ApiError) || !error.field || !setFieldError(form, error.field, message)) {
        if (note) showNote(note, message, 'error');
        else toast(message, 'error');
      }
    } finally {
      busy(submitButton, false);
    }
  });
}

export function passwordStrength(password = '') {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-zа-я]/.test(password) && /[A-ZА-Я]/.test(password)) score += 1;
  if (/\d/.test(password) && /[^\w\s]/.test(password)) score += 1;
  return Math.min(score, 4);
}

const STRENGTH_LABELS = [
  'Слишком короткий',
  'Слабый — добавьте символов',
  'Средний — смешайте регистр',
  'Хороший',
  'Отличный',
];

export function wireStrength(input, meter) {
  if (!input || !meter) return;
  const update = () => {
    const score = input.value ? passwordStrength(input.value) : 0;
    meter.dataset.score = String(score);
    meter.querySelector('.strength__label').textContent = input.value ? STRENGTH_LABELS[score] : 'Минимум 8 символов, буква и цифра';
  };
  input.addEventListener('input', update);
  update();
}

export function wirePeek(root = document) {
  $$('.peek', root).forEach((button) => {
    button.addEventListener('click', () => {
      const input = button.parentElement.querySelector('input');
      const shown = input.type === 'text';
      input.type = shown ? 'password' : 'text';
      button.setAttribute('aria-label', shown ? 'Показать пароль' : 'Скрыть пароль');
      button.dataset.shown = String(!shown);
    });
  });
}

// --- Тема -----------------------------------------------------------------

export function wireTheme() {
  const apply = (theme) => {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  };
  apply(localStorage.getItem('flowid-theme'));
  $$('.theme-toggle').forEach((button) => {
    button.addEventListener('click', () => {
      const dark = getComputedStyle(document.documentElement).colorScheme === 'dark';
      const next = dark ? 'light' : 'dark';
      localStorage.setItem('flowid-theme', next);
      apply(next);
    });
  });
}

// --- Разное ---------------------------------------------------------------

/** Русская форма множественного числа: plural(2, 'сессия', 'сессии', 'сессий'). */
export function plural(count, one, few, many) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} ${one}`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} ${few}`;
  return `${count} ${many}`;
}

export const initials = (name = '') => name.trim().split(/\s+/).slice(0, 2).map((w) => w[0] || '').join('').toUpperCase() || '?';

export function formatDate(ms) {
  return new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' }).format(new Date(ms));
}

export function formatWhen(ms) {
  const diff = Date.now() - ms;
  if (diff < 60_000) return 'только что';
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)} мин назад`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3600_000)} ч назад`;
  if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)} дн назад`;
  return formatDate(ms);
}

export function describeDevice(userAgent = '') {
  const browser = /YaBrowser/.test(userAgent) ? 'Яндекс Браузер'
    : /Edg\//.test(userAgent) ? 'Edge'
    : /Firefox/.test(userAgent) ? 'Firefox'
    : /Chrome/.test(userAgent) ? 'Chrome'
    : /Safari/.test(userAgent) ? 'Safari'
    : 'Неизвестный браузер';
  const os = /Android/.test(userAgent) ? 'Android'
    : /iPhone|iPad/.test(userAgent) ? 'iOS'
    : /Mac OS X/.test(userAgent) ? 'macOS'
    : /Windows/.test(userAgent) ? 'Windows'
    : /Linux/.test(userAgent) ? 'Linux'
    : 'другая система';
  return `${browser}, ${os}`;
}

export async function copyText(text, message = 'Скопировано', highlight) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message, 'ok');
    if (highlight) {
      highlight.classList.remove('copied');
      void highlight.offsetWidth;
      highlight.classList.add('copied');
    }
  } catch {
    toast('Браузер не дал доступ к буферу обмена', 'error');
  }
}

export function nextParam() {
  const next = new URLSearchParams(location.search).get('next');
  return next && next.startsWith('/') && !next.startsWith('//') ? next : null;
}

wireTheme();
