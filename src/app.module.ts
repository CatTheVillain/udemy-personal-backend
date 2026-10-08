import { Module } from '@nestjs/common';

import { HelloController } from './modules/system/hello/hello.controller';

@Module({
  controllers: [HelloController],
})
export class AppModule {}
