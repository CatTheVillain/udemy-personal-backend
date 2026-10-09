import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ProblemDetailsDto {
  @ApiProperty({ example: 'about:blank' })
  public readonly type: string;

  @ApiProperty({ example: 'Bad Request' })
  public readonly title: string;

  @ApiProperty({ example: 400 })
  public readonly status: number;

  @ApiProperty({ example: 'The request is invalid.' })
  public readonly detail: string;

  @ApiProperty({ example: 'REQUEST_INVALID' })
  public readonly code: string;

  @ApiProperty({ example: 'fdc5f4d6-8f47-4cfb-8f54-0b5bb90c8d0f' })
  public readonly requestId: string;

  @ApiPropertyOptional({ example: 'urn:problem:fdc5f4d6-8f47-4cfb-8f54-0b5bb90c8d0f' })
  public readonly instance?: string;

  public constructor(
    type: string,
    title: string,
    status: number,
    detail: string,
    code: string,
    requestId: string,
    instance?: string,
  ) {
    this.type = type;
    this.title = title;
    this.status = status;
    this.detail = detail;
    this.code = code;
    this.requestId = requestId;
    if (instance !== undefined) {
      this.instance = instance;
    }
  }
}
