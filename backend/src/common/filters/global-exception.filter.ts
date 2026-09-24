import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status: number;
    let message: string;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const responseBody = exception.getResponse();
      message = typeof responseBody === 'string' ? responseBody : (responseBody as any).message || 'An error occurred';
    } else if (exception instanceof Error) {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = 'Internal server error';
      // Log the actual error but don't expose it to the client
      this.logger.error(`Unhandled exception: ${exception.message}`, exception.stack);
    } else {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = 'Internal server error';
    }

    // Redact sensitive information from error messages
    message = this.redactSecrets(typeof message === 'string' ? message : JSON.stringify(message));

    response.status(status).json({
      statusCode: status,
      message,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }

  private redactSecrets(text: string): string {
    // Redact anything that looks like a token, key, or password
    return text
      .replace(/(?:token|key|password|secret|authorization|bearer)\s*[:=]\s*\S+/gi, '[REDACTED]')
      .replace(/ghp_[a-zA-Z0-9]{36}/g, '[GITHUB_TOKEN_REDACTED]')
      .replace(/gsk_[a-zA-Z0-9]+/g, '[GROQ_KEY_REDACTED]')
      .replace(/postgresql:\/\/[^@]+@/g, 'postgresql://[REDACTED]@');
  }
}
