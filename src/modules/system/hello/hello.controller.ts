import { Controller, Get } from '@nestjs/common';
import {
  ApiExtraModels,
  ApiOkResponse,
  ApiOperation,
  ApiResponse as SwaggerApiResponse,
  ApiTags,
  getSchemaPath,
} from '@nestjs/swagger';

import { ProblemDetailsDto } from '../../../shared/http/problem-details';
import { HelloApiResponseDto, HelloResponseDto } from './hello-response.dto';

@ApiTags('system')
@ApiExtraModels(HelloApiResponseDto, ProblemDetailsDto)
@Controller('hello')
export class HelloController {
  @Get()
  @ApiOperation({ summary: 'Return the bootstrap greeting' })
  @ApiOkResponse({ type: HelloApiResponseDto })
  @SwaggerApiResponse({
    status: 400,
    description: 'Invalid request',
    content: {
      'application/problem+json': {
        schema: { $ref: getSchemaPath(ProblemDetailsDto) },
      },
    },
  })
  public getHello(): HelloResponseDto {
    return new HelloResponseDto('Hello World!');
  }
}
