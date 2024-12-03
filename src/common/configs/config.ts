import type { Config } from './config.interface';
import * as process from 'process';
import { validateSchemeEnv } from '../../helpers/validation-schema-env';

const config: Config = {
  envFilePath: [ '.env', '.env.dev', '.env.prod', '.env.local', '.env.example' ],
  validate: validateSchemeEnv,
  nest: {
    port: +process.env.PORT || 3000,
  },
  cors: {
    enabled: true,
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  },
  swagger: {
    enabled: process.env.SWAGGER_ENABLED === 'true' || false,
    title: process.env.SERVER_NAME || 'My awesome API',
    description: process.env.SERVER_DESC || 'My awesome API description',
    version: process.env.SERVER_VERSION || '1.0',
    path: process.env.SWAGGER_URL || 'api/swagger',
  },
  graphql: {
    playgroundEnabled: true,
    debug: true,
    schemaDestination:
      process.env.GRAPHQL_SCHEMA_DESTINATION || './src/schema.graphql',
    sortSchema: true,
  },
  security: {
    jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'JWT_ACCESS_SECRET',
    jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRATION || '15m',
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'JWT_REFRESH_SECRET',
    jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '30d',
    saltOrRounds: +process.env.SALT_ROUNDS || 10,
    jwtResetSecret: process.env.JWT_RESET_SECRET || 'JWT_RESET_SECRET',
    jwtResetExpiresIn: process.env.JWT_RESET_EXPIRATION || '2h',
    jwtActivationTokenSecret: process.env.JWT_ACTIVATION_SECRET || 'JWT_ACTIVATION_SECRET',
    jwtActivationTokenExpiresIn: process.env.JWT_ACTIVATION_EXPIRATION || '2d',
  },
  mailer: {
    host: process.env.MAILER_HOST || 'smtp.mailtrap.io',
    port: +process.env.MAILER_PORT || 2525,
    user: process.env.MAILER_USER || 'MAILER_USER',
    pass: process.env.MAILER_PASS || 'MAILER_PASSWORD',
    debug: process.env.MAILER_DEBUG === 'true' || false,
    logger: process.env.MAILER_LOGGER === 'true' || false,
  }
};

export default (): Config => config;
