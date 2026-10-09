import { STATUS_CODES } from 'node:http';

import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import { Response } from 'express';
import createHttpError from 'http-errors';

import { ProblemDetailsDto } from './problem-details';
import { getRequestId } from './request-correlation';

interface KnownHttpProblem {
  readonly title: string;
  readonly detail: string;
  readonly code: string;
}

const KNOWN_HTTP_PROBLEMS = new Map<number, KnownHttpProblem>([
  [
    HttpStatus.BAD_REQUEST,
    {
      title: 'Bad Request',
      detail: 'The request is invalid.',
      code: 'REQUEST_INVALID',
    },
  ],
  [
    HttpStatus.UNAUTHORIZED,
    {
      title: 'Unauthorized',
      detail: 'Authentication is required.',
      code: 'AUTHENTICATION_REQUIRED',
    },
  ],
  [
    HttpStatus.FORBIDDEN,
    {
      title: 'Forbidden',
      detail: 'Access is denied.',
      code: 'ACCESS_DENIED',
    },
  ],
  [
    HttpStatus.NOT_FOUND,
    {
      title: 'Not Found',
      detail: 'The requested resource was not found.',
      code: 'RESOURCE_NOT_FOUND',
    },
  ],
  [
    HttpStatus.CONFLICT,
    {
      title: 'Conflict',
      detail: 'The request conflicts with the current resource state.',
      code: 'RESOURCE_CONFLICT',
    },
  ],
  [
    HttpStatus.PAYLOAD_TOO_LARGE,
    {
      title: 'Payload Too Large',
      detail: 'The request payload is too large.',
      code: 'PAYLOAD_TOO_LARGE',
    },
  ],
  [
    HttpStatus.UNPROCESSABLE_ENTITY,
    {
      title: 'Unprocessable Entity',
      detail: 'The request cannot be processed.',
      code: 'REQUEST_UNPROCESSABLE',
    },
  ],
  [
    HttpStatus.TOO_MANY_REQUESTS,
    {
      title: 'Too Many Requests',
      detail: 'Too many requests were received.',
      code: 'RATE_LIMITED',
    },
  ],
]);

@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  public catch(exception: unknown, host: ArgumentsHost): void {
    if (host.getType() !== 'http') {
      return;
    }

    const response = host.switchToHttp().getResponse<Response>();
    if (response.headersSent) {
      return;
    }

    const problem = createProblemDetails(exception, getRequestId(response));
    response.status(problem.status).type('application/problem+json').send(problem);
  }
}

function createProblemDetails(exception: unknown, requestId: string): ProblemDetailsDto {
  const status = getSafeStatus(exception);
  const knownProblem = KNOWN_HTTP_PROBLEMS.get(status);

  if (knownProblem === undefined) {
    if (
      exception instanceof HttpException &&
      status !== HttpStatus.INTERNAL_SERVER_ERROR &&
      Number.isInteger(status) &&
      status >= HttpStatus.BAD_REQUEST &&
      status <= 599
    ) {
      return new ProblemDetailsDto(
        'about:blank',
        STATUS_CODES[status] ?? 'HTTP Error',
        status,
        'The request could not be completed.',
        'HTTP_ERROR',
        requestId,
      );
    }

    return new ProblemDetailsDto(
      'about:blank',
      'Internal Server Error',
      HttpStatus.INTERNAL_SERVER_ERROR,
      'An unexpected error occurred.',
      'INTERNAL_ERROR',
      requestId,
    );
  }

  return new ProblemDetailsDto(
    'about:blank',
    knownProblem.title,
    status,
    knownProblem.detail,
    knownProblem.code,
    requestId,
  );
}

function getSafeStatus(exception: unknown): number {
  if (exception instanceof HttpException) {
    return exception.getStatus();
  }

  if (
    createHttpError.isHttpError(exception) &&
    exception.type === 'entity.too.large' &&
    exception.status === HttpStatus.PAYLOAD_TOO_LARGE &&
    exception.statusCode === HttpStatus.PAYLOAD_TOO_LARGE
  ) {
    return HttpStatus.PAYLOAD_TOO_LARGE;
  }

  return HttpStatus.INTERNAL_SERVER_ERROR;
}
