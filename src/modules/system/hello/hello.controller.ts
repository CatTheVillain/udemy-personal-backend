import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';

import { HelloResponseDto } from './hello-response.dto';

@ApiTags('system')
@Controller('hello')
export class HelloController {
  @Get()
  @ApiOperation({ summary: 'Return the bootstrap greeting' })
  @ApiOkResponse({ type: HelloResponseDto })
  public getHello(): HelloResponseDto {
    return new HelloResponseDto('Hello World!');
  }
}
