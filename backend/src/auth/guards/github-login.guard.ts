import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Старт входа через GitHub.
 *
 * С `?switch=1` к запросу авторизации добавляется prompt=select_account, и
 * GitHub показывает выбор аккаунта. Без этого браузер, где уже выполнен вход
 * на github.com, всегда возвращает того же пользователя — сменить аккаунт
 * после выхода было нельзя.
 */
@Injectable()
export class GithubLoginGuard extends AuthGuard('github') {
  getAuthenticateOptions(context: ExecutionContext): Record<string, unknown> {
    const request = context.switchToHttp().getRequest();
    const wantsSwitch = request?.query?.switch === '1';
    return wantsSwitch ? { prompt: 'select_account' } : {};
  }
}
