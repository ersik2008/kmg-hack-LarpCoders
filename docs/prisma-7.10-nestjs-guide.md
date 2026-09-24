━━━━━━━━━━━━━━━━━━━━
📘 PRISMA ORM 7.10 + POSTGRESQL + NESTJS
━━━━━━━━━━━━━━━━━━━━

Цель документа:

Настроить Prisma 7.10.0 в NestJS-проекте с PostgreSQL:

```
PostgreSQL
   ↓
Prisma
   ↓
Prisma Client
   ↓
PrismaService
   ↓
NestJS Service
   ↓
Controller / API
```

В документе:

• установка Prisma 7.10.0
• подключение PostgreSQL
• `schema.prisma`
• модели и связи
• migration
• generate
• PrismaService
• PrismaModule
• `@Global()`
• использование Prisma через DI

⚠️ Документ рассчитан именно на Prisma 7.10.0 + PostgreSQL + NestJS.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 1/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
📦 1. УСТАНОВКА PRISMA
━━━━━━━━━━━━━━━━━━━━

В корне NestJS-проекта устанавливаем Prisma 7.10.0:

```bash
npm install prisma@7.10.0 --save-dev
```

Затем Prisma Client и PostgreSQL adapter:

```bash
npm install @prisma/client@7.10.0 @prisma/adapter-pg pg
```

И **обязательно** dotenv — без него `prisma.config.ts`/`prisma7.config.ts` не сможет прочитать `.env`:

```bash
npm install dotenv
```

Что устанавливается:

`prisma`
→ Prisma CLI.

Используется для:

```bash
npx prisma init
npx prisma migrate dev
npx prisma generate
```

`@prisma/client`
→ Prisma Client, через который NestJS работает с БД.

`@prisma/adapter-pg`
→ PostgreSQL adapter для Prisma 7.

`pg`
→ PostgreSQL driver.

`dotenv`
→ загружает переменные из `.env` в `process.env`. В Prisma 7 CLI больше не подхватывает `.env` автоматически — нужен явный `import 'dotenv/config'` в конфиге.

⚠️ В Prisma 7 driver adapter для прямого подключения к БД обязателен.

Проверить установленную версию:

```bash
npx prisma -v
```

Нас интересует:

```text
prisma        : 7.10.0
@prisma/client: 7.10.0
```

Версии `prisma` и `@prisma/client` должны всегда совпадать.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 2/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
⚙️ 2. ИНИЦИАЛИЗАЦИЯ PRISMA
━━━━━━━━━━━━━━━━━━━━

Выполняем:

```bash
npx prisma init --output ../src/generated/prisma
```

`--output` указывает, куда Prisma будет генерировать Prisma Client. Это официальный флаг CLI, не самодельный.

В нашем случае:

```text
src/generated/prisma
```

После `init` получаем примерно такую структуру:

```text
project/
│
├── prisma/
│   └── schema.prisma
│
├── src/
│   └── generated/
│       └── prisma/
│
├── .env
├── prisma7.config.ts   (или prisma.config.ts — см. ниже)
└── package.json
```

⚠️ **Про имя конфиг-файла.** Начиная с Prisma 7.10.0, CLI поддерживает версионированные конфиг-файлы — это официальное поведение, а не случайность конкретной установки. Оно введено, чтобы Prisma 7 и будущий Prisma 8 могли сосуществовать в одном проекте без конфликта имён. Поэтому у тебя может сгенерироваться:

```text
prisma7.config.ts
```

Это нормально. **Не нужно** переименовывать его в `prisma.config.ts` — CLI и так находит `prisma7.config.*` автоматически, без флага `--config`.

**Содержимое файла** (что бы он ни назывался — `prisma.config.ts` или `prisma7.config.ts`):

```typescript
import 'dotenv/config';
import { defineConfig, env } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: env('DATABASE_URL'),
  },
});
```

Обрати внимание: импорт обычный — `from 'prisma/config'`. Специальный путь `from '@prisma/prisma7/config'` нужен только если ты отдельно ставишь compat-пакет `@prisma/prisma7` для запуска Prisma 7 рядом с Prisma 8 в одном проекте — для обычной установки `prisma@7.10.0` он не нужен.

📌 Главное:

`schema.prisma`
→ описывает структуру базы.

`prisma7.config.ts` / `prisma.config.ts`
→ конфигурация Prisma CLI (путь к схеме, к миграциям, DATABASE_URL).

`.env`
→ переменные окружения.

`src/generated/prisma`
→ сгенерированный Prisma Client.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 3/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
🔐 3. DATABASE_URL
━━━━━━━━━━━━━━━━━━━━

В `.env` указываем подключение к PostgreSQL:

```env
DATABASE_URL="postgresql://postgres:ПАРОЛЬ@localhost:5432/ИМЯ_БД"
```

Например:

```env
DATABASE_URL="postgresql://postgres:1234@localhost:5432/mydb"
```

Где:

```text
postgres   → пользователь PostgreSQL
1234       → пароль PostgreSQL
mydb       → имя базы данных
```

Если PostgreSQL использует другой пароль или имя БД — указываем свои значения.

⚠️ Не записывай настоящий пароль непосредственно в исходный код. Используй `.env` и не публикуй его в Git (добавь в `.gitignore`).

📌 В Prisma 7 переменные окружения для CLI не подхватываются автоматически — их нужно явно загрузить через `dotenv` (см. содержимое конфига в разделе 2).

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 4/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
🗃️ 4. SCHEMA.PRISMA
━━━━━━━━━━━━━━━━━━━━

Основной файл: `prisma/schema.prisma`

⚠️ Пример ниже — **учебный** (`User`/`Post`), не путай его с реальной схемой твоего проекта (`Camera`/`Detection`). Он нужен только чтобы понять синтаксис.

```prisma
generator client {
  provider = "prisma-client"
  output   = "../src/generated/prisma"
}

datasource db {
  provider = "postgresql"
}

model User {
  id    Int    @id @default(autoincrement())
  email String @unique
  name  String?
  posts Post[]
}

model Post {
  id        Int      @id @default(autoincrement())
  title     String
  content   String?
  published Boolean  @default(false)

  author   User? @relation(fields: [authorId], references: [id])
  authorId Int?
}
```

━━━━━━━━━━━━━━━━━━━━
📌 РАЗБОР USER
━━━━━━━━━━━━━━━━━━━━

`id Int @id @default(autoincrement())`
→ `id` — имя поля, `Int` — тип, `@id` — Primary Key, `@default(autoincrement())` — PostgreSQL сам увеличивает значение.

`email String @unique`
→ `@unique` значит, что значение не может повторяться у двух записей.

`name String?`
→ `?` значит, что поле необязательное (может быть `null`).

`posts Post[]`
→ связь один-ко-многим: один `User` может иметь много `Post`.

━━━━━━━━━━━━━━━━━━━━
📌 РАЗБОР POST
━━━━━━━━━━━━━━━━━━━━

`title String` — обязательное строковое поле.
`content String?` — необязательное.
`published Boolean @default(false)` — по умолчанию `false`. `?` здесь не нужен, обычного `true/false` достаточно.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 5/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
🔗 5. RELATION USER ↔ POST
━━━━━━━━━━━━━━━━━━━━

В `Post`:

```prisma
author   User? @relation(fields: [authorId], references: [id])
authorId Int?
```

```text
Post.authorId
       ↓
   User.id
```

`authorId` — внешний ключ. `references: [id]` говорит, что он ссылается на `User.id`. `User?` и `Int?` означают, что автор у поста может отсутствовать (связь необязательная) — если у тебя в проекте связь обязательная (как `Detection.camera` в твоей схеме), пиши без `?`.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 6/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
🛠️ 6. MIGRATION
━━━━━━━━━━━━━━━━━━━━

После создания или изменения моделей выполняем:

```bash
npx prisma migrate dev --name init
```

Prisma: 1) смотрит на `schema.prisma`, 2) сравнивает со схемой в БД, 3) создаёт SQL-миграцию, 4) применяет к PostgreSQL, 5) сохраняет историю в `prisma/migrations/`.

📌 **Название миграции** должно объяснять, что изменилось — не переиспользуй `--name init` для каждого изменения:

```bash
npx prisma migrate dev --name add-username
npx prisma migrate dev --name add-role
npx prisma migrate dev --name add-orders
```

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 7/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
⚙️ 7. PRISMA GENERATE
━━━━━━━━━━━━━━━━━━━━

```bash
npx prisma generate
```

создаёт Prisma Client на основе `schema.prisma` и указанного `output = "../src/generated/prisma"`.

В NestJS импортируем **не так**:

```ts
import { PrismaClient } from "@prisma/client"; // ❌ неправильно для нашего setup
```

а так:

```ts
import { PrismaClient } from "../generated/prisma/client"; // ✅
```

потому что мы сами задали кастомный `output`.

📌 **`migrate` vs `generate`:**

```text
schema.prisma
      │
      ├──── migrate ────→ меняет структуру PostgreSQL
      │
      └──── generate ───→ создаёт/обновляет Prisma Client (TypeScript)
```

`migrate dev` уже сам вызывает `generate` внутри себя — отдельный `generate` нужен, если менял схему, но не хочешь трогать БД.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 8/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
🧩 8. PRISMASERVICE
━━━━━━━━━━━━━━━━━━━━

`src/prisma/prisma.service.ts`:

```ts
import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
} from "@nestjs/common";

import { PrismaClient } from "../generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    const adapter = new PrismaPg({
      connectionString: process.env.DATABASE_URL,
    });

    super({ adapter });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
```

📌 Разбор:

- `@Injectable()` — класс доступен через Dependency Injection NestJS.
- `extends PrismaClient` — сервис сам становится Prisma Client, поэтому `this.camera.findMany()` работает напрямую.
- `PrismaPg({ connectionString: ... })` — адаптер, обязателен в Prisma 7 для прямого подключения.
- `super({ adapter })` — передаёт адаптер в конструктор `PrismaClient`.
- `onModuleInit` / `onModuleDestroy` — Nest сам вызывает их при старте/остановке приложения, подключая и отключая БД.

━━━━━━━━━━━━━━━━━━━━
МАРКЕР: 9/9
━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━
🌐 9. PRISMA MODULE
━━━━━━━━━━━━━━━━━━━━

`src/prisma/prisma.module.ts`:

```ts
import { Global, Module } from "@nestjs/common";
import { PrismaService } from "./prisma.service";

@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
```

📌 Разбор:

- `providers: [PrismaService]` — регистрирует сервис в DI.
- `exports: [PrismaService]` — без этого другие модули не смогут получить сервис через импорт.
- `@Global()` — делает модуль глобальным: после подключения в `AppModule` не нужно импортировать `PrismaModule` в каждый отдельный модуль (Cameras, Detections и т.д.).

**В `AppModule`:**

```ts
import { Module } from "@nestjs/common";
import { PrismaModule } from "./prisma/prisma.module";

@Module({
  imports: [PrismaModule],
})
export class AppModule {}
```

Теперь в любом сервисе:

```ts
constructor(private readonly prisma: PrismaService) {}
```

```ts
const items = await this.prisma.camera.findMany();

const item = await this.prisma.camera.create({
  data: { name: "Camera 1", streamUrl: "video.mp4", sourceType: "FILE" },
});
```

━━━━━━━━━━━━━━━━━━━━
🚀 ИТОГОВАЯ СХЕМА
━━━━━━━━━━━━━━━━━━━━

```text
1. npm install prisma@7.10.0 --save-dev
2. npm install @prisma/client@7.10.0 @prisma/adapter-pg pg dotenv
3. npx prisma init --output ../src/generated/prisma
4. .env → DATABASE_URL
5. schema.prisma → Models + Relations
6. npx prisma migrate dev --name <осмысленное_имя>
7. npx prisma generate
8. PrismaService → PrismaClient + PrismaPg
9. PrismaModule → providers + exports + @Global()
10. NestJS Service → this.prisma.<model>.findMany()
11. Controller → HTTP API
```

━━━━━━━━━━━━━━━━━━━━
🧠 ЧТО НУЖНО ЗАПОМНИТЬ
━━━━━━━━━━━━━━━━━━━━

- `schema.prisma` → описывает модели БД
- `DATABASE_URL` → адрес подключения к PostgreSQL
- `migrate` → изменяет структуру БД
- `generate` → генерирует Prisma Client
- `PrismaPg` → PostgreSQL adapter (обязателен в Prisma 7)
- `PrismaService` → Prisma Client внутри NestJS
- `PrismaModule` → подключает PrismaService к NestJS DI
- `@Global()` → делает модуль глобальным
- `prisma7.config.ts` — легитимное имя конфига в Prisma 7.10.0+, не переименовывать
- `dotenv` — обязателен, .env больше не грузится автоматически

⚠️ Документ рассчитан на конкретный setup: **Prisma 7.10.0 + PostgreSQL + @prisma/adapter-pg + NestJS**. Не смешивай без необходимости с инструкциями для Prisma 6 или Prisma 8 — там другой синтаксис (`url` в schema.prisma, `prisma-client-js`, без обязательного адаптера).


Main.ts надо добавить import 'dotenv/config';
патомучта тогда env не пометь и не будеть работать с PostgreSQL 
