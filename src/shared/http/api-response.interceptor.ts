import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
  StreamableFile,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { ApiResponse } from './api-response';
import { SKIP_RESPONSE_ENVELOPE } from './skip-response-envelope.decorator';

interface HttpResponseState {
  readonly headersSent?: boolean;
  readonly statusCode?: number;
}

interface HttpRequestState {
  readonly method?: string;
}

@Injectable()
export class ApiResponseInterceptor implements NestInterceptor {
  public intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (shouldBypassEnvelope(context)) {
      return next.handle();
    }

    return next.handle().pipe(
      map((body: unknown): unknown => {
        if (
          body instanceof ApiResponse ||
          body instanceof StreamableFile ||
          isResponseBypassed(context)
        ) {
          return body;
        }

        return new ApiResponse(body);
      }),
    );
  }
}

function shouldBypassEnvelope(context: ExecutionContext): boolean {
  if (context.getType() !== 'http') {
    return true;
  }

  return Reflect.getMetadata(SKIP_RESPONSE_ENVELOPE, context.getHandler()) === true;
}

function isResponseBypassed(context: ExecutionContext): boolean {
  const request = context.switchToHttp().getRequest<HttpRequestState>();
  const response = context.switchToHttp().getResponse<HttpResponseState>();

  return (
    request.method === 'HEAD' ||
    response.headersSent === true ||
    response.statusCode === 204 ||
    response.statusCode === 304
  );
}
