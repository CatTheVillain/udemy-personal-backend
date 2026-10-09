import 'reflect-metadata';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { AppModule } from './app.module';

export const API_PREFIX = 'api/v1';

export function configureApplication(app: INestApplication): void {
  app.setGlobalPrefix(API_PREFIX);
}

export async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);

  configureApplication(app);
  await app.listen(3000);
}

if (require.main === module) {
  void bootstrap();
}
