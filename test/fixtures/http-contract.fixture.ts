import { Module } from '@nestjs/common';

import { HelloController } from '../../src/modules/system/hello/hello.controller';

@Module({ controllers: [HelloController] })
export class HttpContractFixtureModule {}
