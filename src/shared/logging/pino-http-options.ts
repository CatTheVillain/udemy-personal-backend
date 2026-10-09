import { IncomingMessage, ServerResponse } from 'node:http';

import { Options } from 'pino-http';

interface SafeHttpLogEvent {
  readonly req: SafeRequestLog;
  readonly res: SafeResponseLog;
}

interface SafeRequestLog {
  readonly method: string;
  readonly id: string;
}

interface SafeResponseLog {
  readonly statusCode: number;
}

export function createPinoHttpOptions(): Options<IncomingMessage, ServerResponse> {
  return {
    base: { service: 'udemy-personal-backend' },
    customAttributeKeys: { reqId: 'requestId' },
    quietReqLogger: true,
    quietResLogger: true,
    wrapSerializers: false,
    genReqId: (request: IncomingMessage, response: ServerResponse): string => {
      const requestId = response.getHeader('x-request-id');
      if (typeof requestId === 'string') {
        return requestId;
      }

      return typeof request.id === 'string' ? request.id : 'missing-request-id';
    },
    customSuccessMessage: (): string => 'http_request_completed',
    customErrorMessage: (): string => 'http_request_failed',
    customSuccessObject: createSafeHttpLogEvent,
    customErrorObject: createSafeHttpLogEvent,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'res.headers.set-cookie',
        'password',
        'token',
        'apiKey',
      ],
      censor: '[REDACTED]',
    },
  };
}

function createSafeHttpLogEvent(
  request: IncomingMessage,
  response: ServerResponse,
): SafeHttpLogEvent {
  return {
    req: {
      method: request.method ?? 'UNKNOWN',
      id: typeof request.id === 'string' ? request.id : 'missing-request-id',
    },
    res: { statusCode: response.statusCode },
  };
}
