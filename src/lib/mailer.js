import { config } from '../config.js';

/**
 * Отправка писем. Без настроенного SMTP письмо печатается в консоль —
 * этого достаточно для разработки и для подключения своего провайдера позже.
 */
export async function sendMail({ to, subject, text }) {
  const line = '─'.repeat(64);
  console.log(`\n${line}\n📮 ${config.mail.from} → ${to}\n${subject}\n${line}\n${text}\n${line}\n`);
  return { delivered: true, transport: 'console' };
}
