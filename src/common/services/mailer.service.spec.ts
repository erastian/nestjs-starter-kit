import { MailerService } from '@nestjs-modules/mailer';
import { Test, TestingModule } from '@nestjs/testing';
import { MailerTransportService } from './mailer.service';
import { ConfigService } from '@nestjs/config';

describe('MailerTransportService', () => {
  let mailerService: MailerService;
  let mailerTransportService: MailerTransportService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [MailerService, MailerTransportService, ConfigService],
    }).overrideProvider(MailerService)
      .useValue({ sendMail: jest.fn() })
      .compile();

    mailerService = module.get(MailerService);
    mailerTransportService = module.get(MailerTransportService);
  })

  it('should be defined', () => {
    expect(mailerTransportService).toBeDefined();
  });
});