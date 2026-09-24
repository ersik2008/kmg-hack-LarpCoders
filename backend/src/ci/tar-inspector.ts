import { gunzipSync } from 'zlib';

/**
 * Проверка содержимого tar-архива ДО распаковки.
 *
 * Полагаться на сам tar нельзя: busybox tar молча срезает ведущие «../» и в
 * листинге отдаёт уже нормализованный путь, поэтому проверка вывода `tar -tzf`
 * traversal не обнаруживает. Реализация tar в образе — деталь окружения, и
 * менять её может обновление базового образа, поэтому заголовки разбираются
 * здесь, а небезопасный архив отклоняется до того, как tar что-либо запишет.
 *
 * Формат tar: записи по 512 байт — заголовок, затем данные, выровненные до
 * границы блока. https://www.gnu.org/software/tar/manual/html_node/Standard.html
 */

const BLOCK = 512;

export interface TarInspection {
  entries: number;
  totalBytes: number;
  /** Причина отказа; пусто — архив безопасен. */
  rejection: string | null;
}

export interface TarLimits {
  /** Максимальный суммарный размер после распаковки (защита от zip-бомбы). */
  maxTotalBytes: number;
  maxEntries: number;
}

const DEFAULT_LIMITS: TarLimits = {
  maxTotalBytes: 2 * 1024 * 1024 * 1024, // 2 ГБ
  maxEntries: 200_000,
};

function readString(buffer: Buffer, offset: number, length: number): string {
  const slice = buffer.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8');
}

function readOctal(buffer: Buffer, offset: number, length: number): number {
  const raw = readString(buffer, offset, length).trim();
  if (!raw) return 0;
  const value = parseInt(raw, 8);
  return Number.isFinite(value) && value >= 0 ? value : 0;
}

/** Путь вне распаковываемого каталога или абсолютный — недопустим. */
function isUnsafePath(name: string): boolean {
  if (!name) return false;
  const normalized = name.replace(/\\/g, '/');
  if (normalized.startsWith('/')) return true;
  if (/^[a-zA-Z]:/.test(normalized)) return true;
  return normalized.split('/').some(part => part === '..');
}

export function inspectTarGz(archive: Buffer, limits: Partial<TarLimits> = {}): TarInspection {
  const { maxTotalBytes, maxEntries } = { ...DEFAULT_LIMITS, ...limits };

  let data: Buffer;
  try {
    data = gunzipSync(archive);
  } catch (err: any) {
    return { entries: 0, totalBytes: 0, rejection: `не удалось распаковать gzip: ${err.message}` };
  }

  let offset = 0;
  let entries = 0;
  let totalBytes = 0;
  // GNU-расширение: длинное имя приходит отдельной записью перед файлом.
  let pendingLongName: string | null = null;

  while (offset + BLOCK <= data.length) {
    const header = data.subarray(offset, offset + BLOCK);

    // Два нулевых блока подряд — конец архива.
    if (header.every(byte => byte === 0)) break;

    const size = readOctal(header, 124, 12);
    const typeFlag = String.fromCharCode(header[156] || 0);
    const prefix = readString(header, 345, 155);
    const rawName = readString(header, 0, 100);

    let name = pendingLongName ?? (prefix ? `${prefix}/${rawName}` : rawName);
    pendingLongName = null;

    // 'L' — имя следующей записи лежит в данных этого блока.
    if (typeFlag === 'L') {
      const dataStart = offset + BLOCK;
      pendingLongName = data.subarray(dataStart, dataStart + size).toString('utf8').replace(/\0+$/, '');
      if (isUnsafePath(pendingLongName)) {
        return { entries, totalBytes, rejection: `небезопасный путь: ${pendingLongName.slice(0, 120)}` };
      }
      offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
      continue;
    }

    if (isUnsafePath(name)) {
      return { entries, totalBytes, rejection: `небезопасный путь: ${name.slice(0, 120)}` };
    }

    // Симлинки и жёсткие ссылки наружу позволяют записать файл вне каталога
    // даже при безопасном имени самой записи.
    if (typeFlag === '1' || typeFlag === '2') {
      const linkName = readString(header, 157, 100);
      if (isUnsafePath(linkName)) {
        return {
          entries,
          totalBytes,
          rejection: `ссылка за пределы архива: ${name.slice(0, 60)} -> ${linkName.slice(0, 60)}`,
        };
      }
    }

    entries++;
    totalBytes += size;

    if (entries > maxEntries) {
      return { entries, totalBytes, rejection: `в архиве больше ${maxEntries} записей` };
    }
    if (totalBytes > maxTotalBytes) {
      return {
        entries,
        totalBytes,
        rejection: `распакованный размер превышает ${Math.round(maxTotalBytes / 1024 / 1024)} МБ`,
      };
    }

    offset += BLOCK + Math.ceil(size / BLOCK) * BLOCK;
  }

  if (entries === 0) {
    return { entries: 0, totalBytes: 0, rejection: 'архив пуст или не является tar' };
  }

  return { entries, totalBytes, rejection: null };
}
