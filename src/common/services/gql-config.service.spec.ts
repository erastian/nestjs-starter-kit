import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { GqlConfigService } from './gql-config.service';

describe('GqlConfigService', () => {
  let service: GqlConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [GqlConfigService, ConfigService],
    }).compile();

    service = module.get<GqlConfigService>(GqlConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});