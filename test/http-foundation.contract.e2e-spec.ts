import {
  Body,
  CallHandler,
  Controller,
  Get,
  Head,
  HttpCode,
  HttpException,
  HttpStatus,
  INestApplication,
  MessageEvent,
  Module,
  Post,
  Redirect,
  Sse,
  StreamableFile,
} from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host';
import { IsString, MinLength } from 'class-validator';
import type { DestinationStream } from 'pino';
import { lastValueFrom, Observable, of } from 'rxjs';
import request from 'supertest';

import { AppModule } from '../src/app.module';
import { AppConfig } from '../src/shared/config/app-config';
import {
  ApiResponse,
  PaginatedApiResponse,
  PaginationLinks,
  PaginationMeta,
} from '../src/shared/http/api-response';
import { ApiResponseInterceptor } from '../src/shared/http/api-response.interceptor';
import { SkipResponseEnvelope } from '../src/shared/http/skip-response-envelope.decorator';
import { ApplicationOptions, configureApplication } from '../src/main';

const LOCAL_ORIGIN = 'http://localhost:4200';
const VALID_REQUEST_ID = 'f5b75d70-7eaa-4a1a-b93e-29c566eb0e44';
const INVALID_REQUEST_ID = 'invalid request id';
const OVERLONG_REQUEST_ID = 'a'.repeat(1025);
const SYNTHETIC_SECRET_MARKERS = [
  'secret-authorization-3cd04e92',
  'secret-cookie-24a2d1c6',
  'secret-url-e1a10c44',
  'secret-header-798d597c',
  'secret-body-e7fa236a',
  'secret-nested-cause-7d59e0a2',
  'secret-provider-body-e91aec9b',
] as const;

class ProbeRequestDto {
  @IsString()
  @MinLength(1)
  public value!: string;
}

class FailureRequestDto {
  @IsString()
  @MinLength(1)
  public marker!: string;
}

interface ProbeResponse {
  readonly value: string;
}

interface RawBusinessResponse {
  readonly data: string;
  readonly kind: string;
}

interface ProbeItem {
  readonly id: string;
}

class CapturedPinoDestination implements DestinationStream {
  public readonly messages: string[] = [];

  public write(message: string): void {
    this.messages.push(message);
  }
}

@Controller('http-foundation-probe')
class HttpFoundationProbeController {
  @Post('echo')
  public echo(@Body() body: ProbeRequestDto): ProbeResponse {
    return { value: body.value };
  }

  @Get('already-wrapped')
  public alreadyWrapped(): ApiResponse<ProbeResponse> {
    return new ApiResponse({ value: 'wrapped' });
  }

  @Get('raw-data-property')
  public rawDataProperty(): RawBusinessResponse {
    return { data: 'business-value', kind: 'raw-business-object' };
  }

  @Get('paginated')
  public paginated(): PaginatedApiResponse<ProbeItem> {
    return new PaginatedApiResponse(
      [{ id: 'first' }],
      new PaginationMeta(1, 10, 1, 1),
      new PaginationLinks(
        '/api/v1/http-foundation-probe/paginated',
        '/api/v1/http-foundation-probe/paginated',
        '/api/v1/http-foundation-probe/paginated',
      ),
    );
  }

  @Get('empty')
  @HttpCode(HttpStatus.NO_CONTENT)
  public empty(): void {}

  @Get('not-modified')
  @HttpCode(HttpStatus.NOT_MODIFIED)
  public notModified(): void {}

  @Head('head')
  public head(): void {}

  @Get('redirect')
  @Redirect('/api/v1/http-foundation-probe/already-wrapped', HttpStatus.FOUND)
  @SkipResponseEnvelope()
  public redirect(): void {}

  @Get('file')
  @SkipResponseEnvelope()
  public file(): StreamableFile {
    return new StreamableFile(Buffer.from('fixture-file'));
  }

  @Sse('events')
  @SkipResponseEnvelope()
  public events(): Observable<MessageEvent> {
    return of({ data: { event: 'ready' } });
  }

  @Get('known-error')
  public knownError(): void {
    throw new HttpException(SYNTHETIC_SECRET_MARKERS[0], HttpStatus.CONFLICT);
  }

  @Get('untrusted-status-error')
  public untrustedStatusError(): void {
    const error = Object.assign(new Error(SYNTHETIC_SECRET_MARKERS[0]), {
      status: HttpStatus.PAYLOAD_TOO_LARGE,
      statusCode: HttpStatus.PAYLOAD_TOO_LARGE,
    });
    throw error;
  }

  @Post('unexpected-error')
  public unexpectedError(@Body() body: FailureRequestDto): void {
    const error = new Error(
      `${body.marker} ${SYNTHETIC_SECRET_MARKERS[2]} ${SYNTHETIC_SECRET_MARKERS[3]}`,
      {
        cause: new Error(SYNTHETIC_SECRET_MARKERS[5]),
      },
    );
    Object.assign(error, { providerBody: SYNTHETIC_SECRET_MARKERS[6] });
    throw error;
  }
}

@Module({
  imports: [AppModule],
  controllers: [HttpFoundationProbeController],
})
class HttpFoundationProbeModule {}

describe('Global HTTP foundation (e2e)', () => {
  let app: INestApplication;
  let destination: CapturedPinoDestination;

  beforeAll(async () => {
    destination = new CapturedPinoDestination();
    app = await NestFactory.create(HttpFoundationProbeModule, { logger: false });
    configureApplication(app, {
      config: AppConfig.from({
        NODE_ENV: 'test',
        CORS_ALLOWED_ORIGINS: LOCAL_ORIGIN,
      }),
      logDestination: destination,
    });
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('AC01 wraps ordinary JSON once without mistaking a raw data-bearing object for an envelope', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/http-foundation-probe/echo')
      .send({ value: 'ordinary' })
      .expect(201)
      .expect({ data: { value: 'ordinary' } });

    await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/already-wrapped')
      .expect(200)
      .expect({ data: { value: 'wrapped' } });

    await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/raw-data-property')
      .expect(200)
      .expect({ data: { data: 'business-value', kind: 'raw-business-object' } });
  });

  it('AC01 bypasses the envelope for a non-HTTP execution context', async () => {
    const rawPayload = { transport: 'rpc' };
    const context = new ExecutionContextHost([]);
    context.setType('rpc');
    const handler: CallHandler = {
      handle: (): Observable<unknown> => of(rawPayload),
    };

    const result = await lastValueFrom(new ApiResponseInterceptor().intercept(context, handler));

    expect(result).toBe(rawPayload);
  });

  it('AC01 preserves the pagination shape and protocol bypasses', async () => {
    await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/paginated')
      .expect(200)
      .expect({
        data: [{ id: 'first' }],
        meta: {
          currentPage: 1,
          itemsPerPage: 10,
          totalItems: 1,
          totalPages: 1,
        },
        links: {
          current: '/api/v1/http-foundation-probe/paginated',
          first: '/api/v1/http-foundation-probe/paginated',
          last: '/api/v1/http-foundation-probe/paginated',
        },
      });

    await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/empty')
      .expect(204)
      .expect('');
    await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/not-modified')
      .expect(304)
      .expect('');
    const headResponse = await request(app.getHttpServer())
      .head('/api/v1/http-foundation-probe/head')
      .expect(200);
    expect(headResponse.text).toBeUndefined();
    await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/redirect')
      .expect('Location', '/api/v1/http-foundation-probe/already-wrapped')
      .expect(302)
      .expect('Found. Redirecting to /api/v1/http-foundation-probe/already-wrapped');
    const fileResponse = await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/file')
      .expect('Content-Type', /octet-stream/)
      .expect(200);
    expect(fileResponse.body).toBeInstanceOf(Buffer);
    expect(fileResponse.body.toString()).toBe('fixture-file');

    const sseResponse = await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/events')
      .expect('Content-Type', /text\/event-stream/)
      .expect(200);
    expect(sseResponse.text).toContain('"event":"ready"');
  });

  it('AC02 translates parser, known, and unexpected failures into safe problem details', async () => {
    const parserResponse = await request(app.getHttpServer())
      .post('/api/v1/http-foundation-probe/echo')
      .set('Content-Type', 'application/json')
      .send('{"value":')
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);
    const knownResponse = await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/known-error')
      .set('Authorization', `Bearer ${SYNTHETIC_SECRET_MARKERS[0]}`)
      .set('Cookie', `session=${SYNTHETIC_SECRET_MARKERS[1]}`)
      .expect('Content-Type', /application\/problem\+json/)
      .expect(409);
    const unexpectedResponse = await request(app.getHttpServer())
      .post(`/api/v1/http-foundation-probe/unexpected-error?token=${SYNTHETIC_SECRET_MARKERS[2]}`)
      .set('Authorization', `Bearer ${SYNTHETIC_SECRET_MARKERS[0]}`)
      .set('Cookie', `session=${SYNTHETIC_SECRET_MARKERS[1]}`)
      .set('X-Untrusted-Secret', SYNTHETIC_SECRET_MARKERS[3])
      .send({ marker: SYNTHETIC_SECRET_MARKERS[4] })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(500);

    for (const response of [parserResponse, knownResponse, unexpectedResponse]) {
      expect(response.body).toMatchObject({
        type: expect.any(String),
        title: expect.any(String),
        status: response.status,
        detail: expect.any(String),
        code: expect.any(String),
        requestId: expect.stringMatching(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        ),
      });
      expect(JSON.stringify(response.body)).not.toMatch(/secret-|SyntaxError|at .*\(/);
    }
    expect(knownResponse.body.code).toBe('RESOURCE_CONFLICT');
    expect(unexpectedResponse.body.code).toBe('INTERNAL_ERROR');
  });

  it('AC02 maps only a trusted Express oversized-body parser error to the safe 413 problem', async () => {
    const oversizedResponse = await request(app.getHttpServer())
      .post('/api/v1/hello')
      .send({ payload: 'a'.repeat(120_000) })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(413);
    expect(oversizedResponse.body).toMatchObject({
      status: 413,
      code: 'PAYLOAD_TOO_LARGE',
      requestId: expect.stringMatching(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      ),
    });

    const untrustedStatusResponse = await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/untrusted-status-error')
      .expect('Content-Type', /application\/problem\+json/)
      .expect(500);
    expect(untrustedStatusResponse.body.code).toBe('INTERNAL_ERROR');

    for (const response of [oversizedResponse, untrustedStatusResponse]) {
      const bodyText = JSON.stringify(response.body);
      for (const marker of SYNTHETIC_SECRET_MARKERS) {
        expect(bodyText).not.toContain(marker);
      }
    }
  });

  it('AC03 rejects unknown and invalid input at the global pipe', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/http-foundation-probe/echo')
      .send({ value: 'valid', unexpected: 'reject-me' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);
    await request(app.getHttpServer())
      .post('/api/v1/http-foundation-probe/echo')
      .send({ value: null })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);
    await request(app.getHttpServer())
      .post('/api/v1/http-foundation-probe/echo')
      .send({ value: 7 })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);
  });

  it('AC04 permits only configured local CORS origins and replaces unsafe correlation IDs', async () => {
    const acceptedOrigin = await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/already-wrapped')
      .set('Origin', LOCAL_ORIGIN)
      .set('X-Request-Id', VALID_REQUEST_ID)
      .expect('Access-Control-Allow-Origin', LOCAL_ORIGIN)
      .expect('X-Request-Id', VALID_REQUEST_ID)
      .expect(200);
    expect(acceptedOrigin.body).toEqual({ data: { value: 'wrapped' } });

    const rejectedOrigin = await request(app.getHttpServer())
      .get('/api/v1/http-foundation-probe/already-wrapped')
      .set('Origin', 'https://attacker.example')
      .set('X-Request-Id', OVERLONG_REQUEST_ID)
      .expect(200);
    expect(rejectedOrigin.headers['access-control-allow-origin']).toBeUndefined();
    expect(rejectedOrigin.headers['x-request-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(rejectedOrigin.headers['x-request-id']).not.toBe(OVERLONG_REQUEST_ID);
  });

  it('AC04 rejects malformed configuration and remote development origins', () => {
    expect(() => AppConfig.from({ NODE_ENV: 'production' })).toThrow();
    expect(() =>
      AppConfig.from({
        NODE_ENV: 'test',
        CORS_ALLOWED_ORIGINS: 'https://remote.example',
      }),
    ).toThrow();
    expect(() => AppConfig.from({ PORT: '0' })).toThrow();
    expect(() => AppConfig.from({ PORT: 'not-a-port' })).toThrow();
  });

  it('AC04 permits an explicit production HTTPS origin and denies an unknown one', async () => {
    const productionApp = await NestFactory.create(HttpFoundationProbeModule, {
      logger: false,
    });
    configureApplication(
      productionApp,
      new ApplicationOptions(
        AppConfig.from({
          NODE_ENV: 'production',
          CORS_ALLOWED_ORIGINS: 'https://app.example',
        }),
        new CapturedPinoDestination(),
      ),
    );
    await productionApp.init();

    try {
      await request(productionApp.getHttpServer())
        .get('/api/v1/http-foundation-probe/already-wrapped')
        .set('Origin', 'https://app.example')
        .expect('Access-Control-Allow-Origin', 'https://app.example')
        .expect(200);
      const deniedResponse = await request(productionApp.getHttpServer())
        .get('/api/v1/http-foundation-probe/already-wrapped')
        .set('Origin', 'https://attacker.example')
        .expect(200);
      expect(deniedResponse.headers['access-control-allow-origin']).toBeUndefined();
    } finally {
      await productionApp.close();
    }
  });

  it('AC05 retains a legitimate structured request event while excluding synthetic secrets', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/http-foundation-probe/echo')
      .set('X-Request-Id', VALID_REQUEST_ID)
      .send({ value: 'legitimate' })
      .expect(201);
    expect(response.headers['x-request-id']).toBe(VALID_REQUEST_ID);

    await request(app.getHttpServer())
      .post(`/api/v1/http-foundation-probe/unexpected-error?token=${SYNTHETIC_SECRET_MARKERS[2]}`)
      .set('Authorization', `Bearer ${SYNTHETIC_SECRET_MARKERS[0]}`)
      .set('Cookie', `session=${SYNTHETIC_SECRET_MARKERS[1]}`)
      .set('X-Untrusted-Secret', SYNTHETIC_SECRET_MARKERS[3])
      .send({ marker: SYNTHETIC_SECRET_MARKERS[4] })
      .expect(500);

    const logText = destination.messages.join('');
    const logEntries = destination.messages.map((message) => JSON.parse(message) as unknown);
    expect(logEntries).toContainEqual(
      expect.objectContaining({
        req: expect.objectContaining({
          method: 'POST',
          id: VALID_REQUEST_ID,
        }),
        res: expect.objectContaining({ statusCode: 201 }),
      }),
    );
    for (const marker of SYNTHETIC_SECRET_MARKERS) {
      expect(logText).not.toContain(marker);
    }
  });
});
