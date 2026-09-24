import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  IsArray,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';

export class PrePushFileDto {
  /** Repository-relative path of the file that is about to be pushed. */
  @IsString()
  @MaxLength(1000)
  path!: string;

  /** File content, base64 encoded (exact blob content of the commit being pushed). */
  @IsString()
  @MaxLength(4_000_000)
  contentBase64!: string;
}

export class PrePushCheckDto {
  /** "owner/name" — used to attach the result to a known repository. */
  @IsOptional()
  @IsString()
  @MaxLength(255)
  repository?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  branch?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  commitSha?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  remote?: string;

  /**
   * Which stage invoked the check.
   *
   * `ci` был отсутствующим значением: kmg-guard в режиме ci отправляет
   * stage='ci', а глобальный ValidationPipe с forbidNonWhitelisted отвечал на
   * такой запрос HTTP 400 — проверка из composite action не доходила до анализа.
   */
  @IsOptional()
  @IsIn(['pre-push', 'pre-commit', 'ci'])
  stage?: 'pre-push' | 'pre-commit' | 'ci';

  /**
   * Объём проверки. Требования ИБ-01…ИБ-08 сквозные (ТЗ п. 1.19, 4.4.2) и по
   * диффу не устанавливаются, поэтому сервер оценивает их только при scope=all.
   */
  @IsOptional()
  @IsIn(['all', 'changed'])
  scope?: 'all' | 'changed';

  /** Время начала проверки на стороне CI (ISO 8601) — для сводной части отчёта. */
  @IsOptional()
  @IsString()
  @MaxLength(40)
  startedAt?: string;

  @IsArray()
  @ArrayMaxSize(10000)
  @ValidateNested({ each: true })
  @Type(() => PrePushFileDto)
  files!: PrePushFileDto[];
}
