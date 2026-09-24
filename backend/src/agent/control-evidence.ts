/**
 * Deterministic evidence collection for the security-control assessment.
 *
 * The model is never asked "does this project have authentication?" in the
 * abstract — that invites guessing. Instead each control is defined by concrete
 * signals, this module greps the workspace for them, and the model only judges
 * the code that was actually found. If a control has no evidence at all, that
 * absence is itself the finding.
 */

export interface ControlSignal {
  /** Human-readable name of what this pattern indicates. */
  label: string;
  pattern: RegExp;
  /** A hit here argues the control is present and done properly. */
  positive: boolean;
}

/**
 * Some controls are proven by a file simply EXISTING (a lock file, a
 * dependabot config, a .env.example). Those files are often far too large to
 * read — NodeGoat's package-lock.json alone is megabytes — so they are matched
 * by path instead of content.
 */
export interface ControlFileSignal {
  label: string;
  match: RegExp;
  positive: boolean;
}

export interface ControlDefinition {
  key: string;
  title: string;
  /** What the control is supposed to guarantee — shown to the model and the user. */
  question: string;
  /** Why its absence matters. */
  risk: string;
  signals: ControlSignal[];
  /** Signals proven by the presence of a file, without reading it. */
  fileSignals?: ControlFileSignal[];
  /** Manifest dependencies that imply the control exists. */
  packages?: string[];
  /** Skip the control when the project clearly has no such surface. */
  requiresWebSurface?: boolean;
}

export const CONTROL_DEFINITIONS: ControlDefinition[] = [
  {
    key: 'AUTHENTICATION',
    title: 'Аутентификация',
    question:
      'Реализована ли проверка подлинности пользователей и безопасно ли хранятся учётные данные ' +
      '(стойкий KDF вместо быстрого хеша или открытого текста)?',
    risk: 'Без корректной аутентификации возможен неавторизованный доступ и компрометация учётных записей.',
    requiresWebSurface: true,
    packages: ['passport', 'bcrypt', 'bcryptjs', 'argon2', 'jsonwebtoken', 'next-auth', 'lucia', '@nestjs/jwt'],
    signals: [
      { label: 'Стойкое хеширование пароля (bcrypt/argon2/scrypt/pbkdf2)', positive: true,
        pattern: /\b(bcrypt|argon2|scryptSync|scrypt\(|pbkdf2(Sync)?)\b/i },
      { label: 'Проверка пароля', positive: true,
        pattern: /\b(compare|verify)(Sync)?\s*\(\s*[^)]*password/i },
      { label: 'Стратегия/guard аутентификации', positive: true,
        pattern: /\b(passport\.authenticate|PassportStrategy|AuthGuard|requireAuth|isAuthenticated|withAuth)\b/ },
      { label: 'Верификация JWT', positive: true,
        pattern: /\bjwt\.verify\s*\(|\bverifyToken\s*\(/ },
      { label: 'Пароль хранится/сравнивается без хеширования', positive: false,
        pattern: /password\s*===\s*|\bpassword\s*==\s*[^=]|storePassword\s*\(\s*password\s*\)/i },
      { label: 'Быстрый хеш для пароля (md5/sha1)', positive: false,
        pattern: /createHash\(\s*['"`](md5|sha1)['"`]\s*\)[\s\S]{0,80}password|password[\s\S]{0,80}createHash\(\s*['"`](md5|sha1)/i },
    ],
  },
  {
    key: 'AUTHORIZATION',
    title: 'Авторизация и контроль доступа',
    question:
      'Проверяются ли права на чувствительных операциях (удаление, изменение чужих данных, ' +
      'административные действия), или доступ определяется только фактом входа?',
    risk: 'Отсутствие проверки прав открывает IDOR и эскалацию привилегий: любой вошедший может действовать за других.',
    requiresWebSurface: true,
    packages: ['casl', '@casl/ability', 'accesscontrol', 'casbin'],
    signals: [
      { label: 'Проверка ролей/прав', positive: true,
        pattern: /\b(hasRole|checkPermission|can\s*\(|ability\.|@Roles?\(|RolesGuard|authorize\s*\(|requirePermission)\b/ },
      { label: 'Сравнение владельца ресурса', positive: true,
        pattern: /\b(ownerId|userId)\s*(===|!==|==|!=)\s*(req\.user|currentUser|session\.user)/ },
      { label: 'Чувствительная операция по id из запроса', positive: false,
        pattern: /\b(delete|remove|update|destroy)\w*\s*\([^)]*req\.(params|body|query)\.(id|userId)/i },
    ],
  },
  {
    key: 'SECRETS_MANAGEMENT',
    title: 'Управление секретами',
    question:
      'Берутся ли секреты и ключи из окружения/секрет-хранилища, а не из исходного кода?',
    risk: 'Секрет в репозитории считается скомпрометированным: он попадает в историю git и ко всем, у кого есть доступ.',
    fileSignals: [
      { label: 'Шаблон конфигурации без секретов', positive: true,
        match: /(^|\/)\.env\.(example|sample|template|dist)$/ },
      { label: 'Файл .env закоммичен в репозиторий', positive: false,
        match: /(^|\/)\.env(\.local|\.production)?$/ },
      { label: 'Приватный ключ в репозитории', positive: false,
        match: /\.(pem|key|p12|pfx|jks)$/ },
    ],
    signals: [
      { label: 'Секреты из переменных окружения', positive: true,
        pattern: /process\.env\.[A-Z0-9_]{3,}|configService\.get|os\.environ|System\.getenv/ },
      { label: 'Пример конфигурации без значений (.env.example)', positive: true,
        pattern: /\.env\.example|\.env\.sample|\.env\.template/ },
      { label: 'Секрет-менеджер', positive: true,
        pattern: /\b(SecretsManager|vault|KeyVault|SecretManagerService|doppler)\b/i },
      { label: 'Жёстко зашитый ключ/токен в коде', positive: false,
        pattern: /(api[_-]?key|secret|token|password)\s*[:=]\s*['"`][A-Za-z0-9_\-/+]{12,}['"`]/i },
    ],
  },
  {
    key: 'INPUT_VALIDATION',
    title: 'Валидация входных данных',
    question:
      'Валидируются ли данные из запросов по схеме и используются ли параметризованные запросы к БД?',
    risk: 'Без валидации и параметризации открыты инъекции (SQL, команды, XSS) и порча данных.',
    requiresWebSurface: true,
    packages: ['zod', 'joi', 'yup', 'class-validator', 'express-validator', 'ajv', 'valibot'],
    signals: [
      { label: 'Схемная валидация', positive: true,
        pattern: /\b(z\.object|Joi\.object|yup\.object|ValidationPipe|@IsString|@IsInt|@IsEmail|body\(\s*['"`]|checkSchema|ajv\.compile)\b/ },
      { label: 'Параметризованный SQL', positive: true,
        pattern: /\.(query|execute)\s*\(\s*['"`][^'"`]*\$\d|\.(query|execute)\s*\([^)]*,\s*\[/ },
      { label: 'Экранирование вывода', positive: true,
        pattern: /\b(escapeHtml|sanitizeHtml|DOMPurify|encodeURIComponent)\b/ },
      { label: 'SQL собирается конкатенацией', positive: false,
        pattern: /(SELECT|INSERT|UPDATE|DELETE)[^'"`;]*['"`]\s*\+|`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{/i },
    ],
  },
  {
    key: 'CRYPTOGRAPHY',
    title: 'Криптография',
    question:
      'Используются ли стойкие алгоритмы и криптографически безопасная генерация случайных значений?',
    risk: 'Слабая криптография и предсказуемые токены позволяют подделать сессии и расшифровать данные.',
    signals: [
      { label: 'Криптостойкий генератор случайных значений', positive: true,
        pattern: /crypto\.(randomBytes|randomUUID|getRandomValues)|secrets\.token_/ },
      { label: 'Современный алгоритм шифрования', positive: true,
        pattern: /aes-256-(gcm|cbc)|createCipheriv|createDecipheriv/ },
      { label: 'Math.random() для секретов/токенов', positive: false,
        pattern: /Math\.random\(\)[\s\S]{0,60}(token|secret|key|salt|nonce|password|session)/i },
      { label: 'Устаревший алгоритм (md5/sha1/des/rc4)', positive: false,
        pattern: /createHash\(\s*['"`](md5|sha1)['"`]|\b(des-ecb|rc4)\b/i },
      { label: 'Шифрование без вектора инициализации', positive: false,
        pattern: /createCipher\s*\(/ },
    ],
  },
  {
    key: 'SESSION_MANAGEMENT',
    title: 'Управление сессиями',
    question:
      'Ограничен ли срок жизни сессий/токенов, есть ли выход из аккаунта и защищены ли cookie?',
    risk: 'Бессрочные токены и незащищённые cookie позволяют переиспользовать украденную сессию неограниченно долго.',
    requiresWebSurface: true,
    packages: ['express-session', 'cookie-session', 'iron-session'],
    signals: [
      { label: 'Ограничение срока жизни токена', positive: true,
        pattern: /expiresIn|maxAge|exp\s*:|TokenExpire|ttl\s*:/i },
      { label: 'Защищённые флаги cookie', positive: true,
        pattern: /httpOnly\s*:\s*true|sameSite\s*:|secure\s*:\s*true/ },
      { label: 'Выход из аккаунта / отзыв сессии', positive: true,
        pattern: /\b(logout|signOut|revoke|destroySession|invalidateToken)\b/i },
      { label: 'Токен без срока жизни', positive: false,
        pattern: /jwt\.sign\((?:(?!expiresIn)[\s\S]){0,160}\)\s*;/ },
    ],
  },
  {
    key: 'AUDIT_LOGGING',
    title: 'Аудит и журналирование',
    question:
      'Журналируются ли события безопасности (вход, отказ в доступе, изменение прав) и не утекают ли секреты в логи?',
    risk: 'Без журнала событий ИБ инцидент невозможно обнаружить и расследовать.',
    packages: ['winston', 'pino', 'bunyan', 'morgan', '@nestjs/common'],
    fileSignals: [
      { label: 'Выделенная конфигурация логирования', positive: true,
        match: /(^|\/)(logger|logging)\.(ts|js|py|go|java)$/i },
    ],
    signals: [
      { label: 'Структурное логирование', positive: true,
        pattern: /\b(winston|pino|bunyan|morgan|createLogger|new Logger\()/ },
      { label: 'Журналирование событий безопасности', positive: true,
        pattern: /log(ger)?\.(info|warn|error)\s*\([^)]*(login|auth|denied|forbidden|unauthorized|permission)/i },
      { label: 'Редактирование секретов в логах', positive: true,
        pattern: /\b(redact|REDACTED|maskSecret|sanitizeLog)\b/i },
      { label: 'Вывод секрета в лог', positive: false,
        pattern: /console\.(log|info)\s*\([^)]*(password|token|secret|apiKey)/i },
    ],
  },
  {
    key: 'TRANSPORT_SECURITY',
    title: 'Защита канала передачи',
    question:
      'Используется ли HTTPS/TLS и не отключена ли проверка сертификатов?',
    risk: 'Трафик без TLS или с отключённой проверкой сертификата читается и подменяется посредником.',
    requiresWebSurface: true,
    signals: [
      { label: 'HTTPS в конфигурации', positive: true,
        pattern: /https:\/\/|createServer\s*\(\s*\{[\s\S]{0,120}(key|cert)\s*:|forceSSL|hsts/i },
      { label: 'Проверка сертификата отключена', positive: false,
        pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0|verify\s*=\s*False/ },
      { label: 'Открытый http:// к внешнему сервису', positive: false,
        pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/ },
    ],
  },
  {
    key: 'SECURITY_CONFIGURATION',
    title: 'Конфигурация безопасности',
    question:
      'Настроены ли защитные заголовки и CORS, выключен ли отладочный режим в проде?',
    risk: 'Слабая конфигурация (CORS «*», debug в проде, отсутствие заголовков) расширяет поверхность атаки.',
    requiresWebSurface: true,
    packages: ['helmet', 'cors', '@nestjs/throttler', 'express-rate-limit'],
    fileSignals: [
      { label: 'Проверка безопасности в CI', positive: true,
        match: /(^|\/)\.github\/workflows\/.*(security|codeql|scan|sast).*\.ya?ml$/i },
    ],
    signals: [
      { label: 'Защитные HTTP-заголовки', positive: true,
        pattern: /\bhelmet\s*\(|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security/i },
      { label: 'Ограничение частоты запросов', positive: true,
        pattern: /rateLimit|Throttler|express-rate-limit|slowDown/i },
      { label: 'Ограниченный список origin для CORS', positive: true,
        pattern: /origin\s*:\s*(\[|process\.env|allowedOrigins|function|\()/ },
      { label: 'CORS разрешает любой origin', positive: false,
        pattern: /origin\s*:\s*['"`]\*['"`]|Access-Control-Allow-Origin['"`]?\s*[,:]\s*['"`]\*/ },
      { label: 'Отладочный режим включён', positive: false,
        pattern: /debug\s*:\s*true|DEBUG\s*=\s*['"`]?true|app\.set\(\s*['"`]env['"`]\s*,\s*['"`]development/i },
    ],
  },
  {
    key: 'DEPENDENCY_SECURITY',
    title: 'Безопасность зависимостей',
    question:
      'Зафиксированы ли версии зависимостей (lock-файл) и настроена ли проверка уязвимостей пакетов?',
    risk: 'Уязвимые и неприкреплённые зависимости — самый частый путь компрометации цепочки поставки.',
    fileSignals: [
      { label: 'Lock-файл зависимостей', positive: true,
        match: /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Gemfile\.lock|composer\.lock|go\.sum|Cargo\.lock)$/ },
      { label: 'Конфигурация автообновления зависимостей', positive: true,
        match: /(^|\/)(\.github\/dependabot\.ya?ml|renovate\.json|\.renovaterc(\.json)?)$/ },
      { label: 'Манифест зависимостей без lock-файла', positive: false,
        match: /(^|\/)(package\.json)$/ },
    ],
    signals: [
      { label: 'Lock-файл зависимостей', positive: true,
        pattern: /"lockfileVersion"|# This file is automatically @generated by Cargo|poetry\.lock|Pipfile\.lock/ },
      { label: 'Автоматическая проверка зависимостей', positive: true,
        pattern: /dependabot|renovate|npm audit|snyk|trivy|safety check|osv-scanner/i },
      { label: 'Версии зависимостей не зафиксированы', positive: false,
        pattern: /"[^"]+"\s*:\s*"\*"/ },
    ],
  },
];

/** Files worth searching for control signals. */
export const EVIDENCE_EXTENSIONS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx',
  '.py', '.go', '.java', '.rb', '.php', '.cs', '.kt',
  '.json', '.yml', '.yaml', '.toml', '.env', '.example',
]);

export const EVIDENCE_IGNORED_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', '.next', 'coverage',
  '.cache', 'vendor', '__pycache__', '.venv', 'venv', '.idea', '.vscode',
]);
