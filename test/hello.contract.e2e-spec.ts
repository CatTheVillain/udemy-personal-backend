import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import request from 'supertest';

import { AppModule } from '../src/app.module';
import { configureApplication } from '../src/main';

const EXPECTED_HELLO_RESPONSE = { data: { message: 'Hello World!' } };

describe('Hello public contract (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await NestFactory.create(AppModule, { logger: false });
    configureApplication(app);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('C1 serves the exact once-wrapped named HelloResponseDto JSON through GET /api/v1/hello', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/hello')
      .expect('Content-Type', /json/)
      .expect(200);

    expect(response.body).toStrictEqual(EXPECTED_HELLO_RESPONSE);
  });

  it('C2 does not expose an unversioned GET /hello route', async () => {
    await request(app.getHttpServer()).get('/hello').expect(404);
  });

  it('C3 publishes the versioned HelloApiResponseDto envelope with the named HelloResponseDto payload', () => {
    const document: OpenAPIObject = SwaggerModule.createDocument(
      app,
      new DocumentBuilder().setTitle('Udemy Personal Backend').build(),
    );

    const helloOperation = document.paths['/api/v1/hello']?.get;

    expect(helloOperation).toBeDefined();
    expect(helloOperation?.responses).toMatchObject({
      '200': {
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/HelloApiResponseDto' },
          },
        },
      },
    });
    expect(document.components?.schemas).toHaveProperty('HelloApiResponseDto');
    expect(document.components?.schemas).toHaveProperty('HelloResponseDto');
  });
});
