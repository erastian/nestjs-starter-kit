import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../../../src/app.module';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from 'nestjs-prisma';
import { MailerService } from '@nestjs-modules/mailer';
import { prismaService } from '../../config/setupTests.e2e';
import { MailerTransportService } from '../../../src/common/services/mailer.service';
import * as cookieParser from 'cookie-parser';

export interface E2EApp {
  app: INestApplication;
  cleanup: () => void;
}

export async function initializeApp() {
  const moduleRef: TestingModule = await Test.createTestingModule({
    imports: [ AppModule ],
  }).overrideProvider(PrismaService)
    .useValue(prismaService)
    .overrideProvider(MailerService)
    .useValue({ sendMail: jest.fn() })
    .overrideProvider(MailerTransportService)
    .useValue({ sendEmail: jest.fn(), sendRegistrationEmail: jest.fn(), SendPasswordRestorationEmail: jest.fn() })
    .compile();

  const app = moduleRef.createNestApplication();
  app.useGlobalPipes(new ValidationPipe());
  app.enableCors({
    origin: [ process.env.FRONTEND_URL || 'http://localhost:3000' ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  app.use(cookieParser());
  await app.init();

  const cleanup = async () => {
    await app.close();
  };

  return { app, cleanup };
}