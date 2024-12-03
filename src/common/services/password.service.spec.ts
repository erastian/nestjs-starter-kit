import { PasswordService } from './password.service';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';

describe('PasswordService', () => {
  let service: PasswordService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PasswordService, ConfigService],
    }).compile();

    service = module.get<PasswordService>(PasswordService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});