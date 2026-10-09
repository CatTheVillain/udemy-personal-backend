import { HelloController } from './hello.controller';
import { HelloResponseDto } from './hello-response.dto';

describe('HelloController', () => {
  it('returns the frozen bootstrap greeting DTO', () => {
    const controller = new HelloController();

    expect(controller.getHello()).toEqual(new HelloResponseDto('Hello World!'));
  });
});
