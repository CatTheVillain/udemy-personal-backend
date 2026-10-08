import { ApiProperty } from '@nestjs/swagger';

export class HelloResponseDto {
  @ApiProperty({ example: 'Hello World!' })
  public readonly message: string;

  public constructor(message: string) {
    this.message = message;
  }
}
