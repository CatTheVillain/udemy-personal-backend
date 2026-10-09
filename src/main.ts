import 'reflect-metadata';

import { INestApplication, ValidationPipe } from '@nestjs/common';
import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import pino from 'pino';
import { pinoHttp } from 'pino-http';

import { AppModule } from './app.module';
import { AppConfig } from './shared/config/app-config';
import { ApiResponseInterceptor } from './shared/http/api-response.interceptor';
import { ProblemDetailsFilter } from './shared/http/problem-details.filter';
import { requestCorrelationMiddleware } from './shared/http/request-correlation';
import { createPinoHttpOptions } from './shared/logging/pino-http-options';

export const API_PREFIX = 'api/v1';

export class ApplicationOptions {
  public readonly config?: AppConfig;
  public readonly logDestination?: pino.DestinationStream;

  public constructor(config?: AppConfig, logDestination?: pino.DestinationStream) {
    if (config !== undefined) {
      this.config = config;
    }
    if (logDestination !== undefined) {
      this.logDestination = logDestination;
    }
  }
}

export function configureApplication(
  app: INestApplication,
  options = new ApplicationOptions(),
): void {
  const config = options.config ?? AppConfig.from(process.env);

  app.use(requestCorrelationMiddleware);
  app.use(pinoHttp(createPinoHttpOptions(), options.logDestination));
  app.setGlobalPrefix(API_PREFIX);
  const corsOptions: CorsOptions = {
    credentials: true,
    origin: (origin, callback) => {
      callback(null, origin === undefined || config.corsAllowedOrigins.includes(origin));
    },
  };
  app.enableCors(corsOptions);
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
      forbidUnknownValues: true,
      transformOptions: { enableImplicitConversion: false },
      validationError: { target: false, value: false },
    }),
  );
  app.useGlobalInterceptors(new ApiResponseInterceptor());
  app.useGlobalFilters(new ProblemDetailsFilter());

  const document = SwaggerModule.createDocument(
    app,
    new DocumentBuilder().setTitle('Udemy Personal Backend').setVersion('1.0').build(),
  );
  SwaggerModule.setup(`${API_PREFIX}/docs`, app, document);
}

export async function bootstrap(): Promise<void> {
  const config = AppConfig.from(process.env);
  const app = await NestFactory.create(AppModule, { logger: false });

  configureApplication(app, new ApplicationOptions(config));
  await app.listen(config.port);
}

if (require.main === module) {
  void bootstrap().catch(() => {
    process.stderr.write('Application startup failed.\n');
    process.exitCode = 1;
  });
}
