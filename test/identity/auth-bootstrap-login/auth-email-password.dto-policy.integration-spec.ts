import { Body, Controller, INestApplication, Module, Post } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request from 'supertest';

import { AuthEmailPasswordRequestDto } from '../../../src/modules/identity/presentation/dto/auth-email-password.request.dto';
import { configureApplication } from '../../../src/main';

class AcceptedAuthDtoResponse {
  public readonly accepted = true;
}

@Controller('identity-auth-dto-probe')
class IdentityAuthDtoProbeController {
  @Post()
  public accept(@Body() body: AuthEmailPasswordRequestDto): AcceptedAuthDtoResponse {
    void body;
    return new AcceptedAuthDtoResponse();
  }
}

@Module({ controllers: [IdentityAuthDtoProbeController] })
class IdentityAuthDtoProbeModule {}

describe('Auth email/password request DTO policy', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await NestFactory.create(IdentityAuthDtoProbeModule, { logger: false });
    configureApplication(app);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects policy-invalid raw email and password values at the real HTTP validation boundary', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: 'student@exämple.test', password: 'valid-password' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);

    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: `${'a'.repeat(245)}@test.test`, password: 'valid-password' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);

    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: 'student@example.test', password: 'too-short' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);

    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: '   ', password: 'valid-password' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);

    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: 'student\u0000@example.test', password: 'valid-password' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);

    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: 'student@example.test', password: 'valid-password\uD800' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);

    await request(app.getHttpServer())
      .post('/api/v1/identity-auth-dto-probe')
      .send({ email: 'student@example.test', password: 'valid-password\uDC00' })
      .expect('Content-Type', /application\/problem\+json/)
      .expect(400);
  });

  it('accepts exact ASCII and Unicode password bounds without changing the raw value', async () => {
    const accepted = [
      { email: 'a', password: 'a'.repeat(12) },
      { email: 'a'.repeat(254), password: 'a'.repeat(128) },
      { email: 'punycode.xn--p1ai', password: '😀'.repeat(64) },
    ];

    for (const body of accepted) {
      await request(app.getHttpServer())
        .post('/api/v1/identity-auth-dto-probe')
        .send(body)
        .expect(201)
        .expect({ data: { accepted: true } });
    }

    for (const password of ['a'.repeat(11), 'a'.repeat(129), '😀'.repeat(65)]) {
      await request(app.getHttpServer())
        .post('/api/v1/identity-auth-dto-probe')
        .send({ email: 'student@example.test', password })
        .expect(400);
    }
  });
});
