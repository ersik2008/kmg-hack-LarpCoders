import { Controller, Query, Sse, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable, interval, map, merge } from 'rxjs';

import { PrismaService } from '../prisma/index.js';
import { AuthService } from '../auth/auth.service.js';
import { EventsService, ScanEvent } from './events.service.js';

@Controller('events')
export class EventsController {
  constructor(
    private readonly events: EventsService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * SSE-канал обновлений. EventSource не умеет отправлять заголовок
   * Authorization, поэтому токен принимается query-параметром и проверяется
   * здесь вручную — теми же правилами, что и JwtStrategy.
   */
  @Sse('stream')
  async stream(@Query('token') token?: string): Promise<Observable<{ data: ScanEvent | { type: string } }>> {
    const userId = await this.authenticate(token);

    // Прокси и браузеры рвут «молчащий» SSE-канал, поэтому раз в 25 секунд
    // отправляется heartbeat — он же держит соединение живым.
    const heartbeat$ = interval(25_000).pipe(
      map(() => ({ data: { type: 'ping' as const } })),
    );

    return merge(this.events.subscribe(userId), heartbeat$);
  }

  private async authenticate(token?: string): Promise<string> {
    if (!token) {
      throw new UnauthorizedException('Token is required to open the event stream');
    }

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(token);
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: { githubAccount: true },
    });

    if (!user?.githubAccount?.accessTokenHash) {
      throw new UnauthorizedException('Session revoked. Please sign in with GitHub again.');
    }

    // Тот же контроль отзыва сессии, что и в JwtStrategy: токен, выпущенный
    // до перелогина, не должен открывать поток событий.
    if (payload.sid !== AuthService.sessionFingerprint(user.githubAccount.accessTokenHash)) {
      throw new UnauthorizedException('Session is no longer valid. Please sign in with GitHub again.');
    }

    return user.id;
  }
}
