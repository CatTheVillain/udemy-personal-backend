import { randomUUID } from 'node:crypto';

import { NextFunction, Request, Response } from 'express';

const REQUEST_ID_HEADER = 'x-request-id';
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

declare global {
  namespace Express {
    interface Locals {
      requestId?: string;
    }
  }
}

export function requestCorrelationMiddleware(
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  const requestId = selectRequestId(request.headers[REQUEST_ID_HEADER]);

  request.id = requestId;
  response.locals.requestId = requestId;
  response.setHeader(REQUEST_ID_HEADER, requestId);
  next();
}

export function getRequestId(response: Response): string {
  const requestId = response.locals.requestId;
  if (requestId !== undefined) {
    return requestId;
  }

  const generatedRequestId = randomUUID();
  response.locals.requestId = generatedRequestId;
  response.setHeader(REQUEST_ID_HEADER, generatedRequestId);
  return generatedRequestId;
}

function selectRequestId(value: string | string[] | undefined): string {
  if (typeof value === 'string' && REQUEST_ID_PATTERN.test(value)) {
    return value;
  }

  return randomUUID();
}
