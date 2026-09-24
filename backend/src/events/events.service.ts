import { Injectable, Logger } from '@nestjs/common';
import { Observable, Subject, filter, map } from 'rxjs';

/**
 * Событие «состояние репозитория изменилось»: новый скан, обновлённый список.
 * Фронтенд обновляет карточку по факту события, а не по таймеру.
 */
export interface ScanEvent {
  type: 'scan.completed' | 'scan.progress' | 'repositories.synced';
  userId: string;
  repositoryId?: string;
  scanId?: string;
  payload?: Record<string, unknown>;
}

@Injectable()
export class EventsService {
  private readonly logger = new Logger(EventsService.name);
  private readonly stream$ = new Subject<ScanEvent>();

  /** Публикует событие всем открытым вкладкам этого пользователя. */
  emit(event: ScanEvent): void {
    this.logger.debug(`event ${event.type} → user ${event.userId}`);
    this.stream$.next(event);
  }

  /**
   * Поток событий конкретного пользователя. Чужие события не отдаются:
   * SSE-канал открыт на сессию, и подмешивать в него данные других
   * пользователей нельзя.
   */
  subscribe(userId: string): Observable<{ data: ScanEvent }> {
    return this.stream$.pipe(
      filter(event => event.userId === userId),
      map(event => ({ data: event })),
    );
  }
}
