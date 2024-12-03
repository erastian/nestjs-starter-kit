import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';
import {
  CorsConfig,
  NestConfig,
  SwaggerConfig,
} from './common/configs/config.interface';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as process from 'process';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(new ValidationPipe());

  const configService: ConfigService = app.get(ConfigService);
  const nestConfig = configService.get<NestConfig>('nest');
  const corsConfig = configService.get<CorsConfig>('cors');
  const swaggerConfig = configService.get<SwaggerConfig>('swagger');

  // Swagger API
  if (swaggerConfig.enabled) {
    const options = new DocumentBuilder()
      .setTitle(swaggerConfig.title || 'NestJS API')
      .setDescription(swaggerConfig.description || 'NestJS API description')
      .setVersion(swaggerConfig.version || '1.0')
      .build();
    const document = SwaggerModule.createDocument(app, options);
    SwaggerModule.setup(swaggerConfig.path || 'api', app, document);
  }

  app.use(cookieParser());

  // CORS
  if (corsConfig.enabled) {
    app.enableCors({
      origin: [ corsConfig.frontendUrl ],
      methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
      credentials: true,
    });
  }

  await app.listen(process.env.PORT || nestConfig.port || 3000, '0.0.0.0');
  Logger.log(
    `\x1b[33m[Server]\x1b[32m Running on\x1b[0m ${ await app.getUrl() }`,
  );
}

bootstrap();
