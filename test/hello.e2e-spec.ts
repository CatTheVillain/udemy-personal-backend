import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import request from 'supertest';

import { AppModule } from '../src/app.module';
import { configureApplication } from '../src/main';

describe('Hello bootstrap (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await NestFactory.create(AppModule, { logger: false });
    configureApplication(app);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('serves the frozen greeting only through the versioned route and publishes its named schema', async () => {
    await request(app.getHttpServer())
      .get('/api/v1/hello')
      .expect(200)
      .expect({ message: 'Hello World!' });
    await request(app.getHttpServer()).get('/hello').expect(404);

    const document: OpenAPIObject = SwaggerModule.createDocument(
      app,
      new DocumentBuilder().setTitle('Udemy Personal Backend').build(),
    );
    const helloOperation = document.paths['/api/v1/hello']?.get;

    expect(helloOperation).toBeDefined();
    expect(document.components?.schemas).toHaveProperty('HelloResponseDto');
  });
});
