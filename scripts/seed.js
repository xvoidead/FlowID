// Создаёт демо-пользователя и демо-приложение для проверки полного цикла входа.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { config } from '../src/config.js';
import { db } from '../src/db.js';
import { createUser, findUserByEmail } from '../src/lib/users.js';
import { createClient, listClientsByOwner } from '../src/lib/clients.js';

const EMAIL = 'demo@flowid.local';
const PASSWORD = 'flowid12345';

let user = findUserByEmail(EMAIL);
if (!user) {
  user = await createUser({ email: EMAIL, password: PASSWORD, name: 'Демо Пользователь', username: 'demo', emailVerified: true });
  console.log(`Создан пользователь ${EMAIL} с паролем ${PASSWORD}`);
} else {
  console.log(`Пользователь ${EMAIL} уже есть`);
}

const existing = listClientsByOwner(user.id).find((c) => c.name === 'Демо-клиент');
if (existing) {
  console.log(`Демо-клиент уже есть: ${existing.client_id}. Удалите его в кабинете, если нужен новый секрет.`);
} else {
  const { client, secret } = createClient({
    ownerUserId: user.id,
    name: 'Демо-клиент',
    description: 'Пример подключения к FlowID',
    website: 'http://localhost:4000',
    redirectUris: ['http://localhost:4000/callback'],
    scopes: 'openid profile email offline_access',
  });
  const path = join(config.dataDir, 'demo-client.json');
  writeFileSync(path, JSON.stringify({ client_id: client.client_id, client_secret: secret, issuer: config.issuer }, null, 2));
  console.log(`Создано приложение ${client.client_id}, секрет записан в ${path}`);
}

db.close();
