import { Injectable, NestMiddleware, ForbiddenException, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

/**
 * Middleware to detect and block prompt injection attacks in request bodies.
 * Scans all string fields for known prompt injection patterns.
 */
@Injectable()
export class PromptInjectionGuard implements NestMiddleware {
  private readonly logger = new Logger('PromptInjectionGuard');

  // Patterns that indicate prompt injection attempts
  private readonly suspiciousPatterns = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /forget\s+(all\s+)?previous/i,
    /you\s+are\s+now\s+/i,
    /new\s+instructions?\s*:/i,
    /system\s*prompt\s*:/i,
    /\[SYSTEM\]/i,
    /\[INST\]/i,
    /<<SYS>>/i,
    /act\s+as\s+(a\s+)?different/i,
    /override\s+(your\s+)?instructions/i,
    /disregard\s+(all\s+)?prior/i,
    /reveal\s+(your\s+)?system\s+prompt/i,
    /what\s+is\s+your\s+system\s+prompt/i,
    /output\s+your\s+instructions/i,
    /repeat\s+everything\s+above/i,
  ];

  use(req: Request, _res: Response, next: NextFunction) {
    if (req.body) {
      const bodyStr = JSON.stringify(req.body);
      
      for (const pattern of this.suspiciousPatterns) {
        if (pattern.test(bodyStr)) {
          this.logger.warn(
            `Potential prompt injection detected from ${req.ip}: matched pattern "${pattern.source}" on ${req.method} ${req.url}`,
          );
          throw new ForbiddenException('Request blocked: potentially malicious input detected.');
        }
      }
    }

    next();
  }
}
