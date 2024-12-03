import { GraphQLModule } from '@nestjs/graphql';
import { Logger, Module } from '@nestjs/common';
import { loggingMiddleware, PrismaModule } from 'nestjs-prisma';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import config from './common/configs/config';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { GqlConfigService } from './common/services/gql-config.service';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import * as process from 'process';


@Module({
  controllers: [],
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [ config ],
    }),
    PrismaModule.forRoot({
      isGlobal: true,
      prismaServiceOptions: {
        prismaOptions: {
          log: ['warn', 'error'],
          errorFormat: 'pretty',
        },
        middlewares: [
          loggingMiddleware({
            logger: new Logger('PrismaMiddleware'),
            logLevel: 'log',
          }),
        ],
      },
    }),
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      useClass: GqlConfigService,
    }),
    MailerModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        transport: {
          service: 'gmail',
          auth: {
            user: configService.get('MAILER_USER'),
            pass: configService.get('MAILER_PASS'),
          },
        },
        defaults: {
          from: `${ configService.get('SERVER_NAME') } Happy Admin <${ configService.get('MAILER_USER') }>`,
        },
        template: {
          dir: process.cwd() + '/src/shared/mailer-templates/pages',
          adapter: new HandlebarsAdapter({
          }, {
            inlineCssEnabled: false,
          }),
          options: {
            strict: true
          },
        },
        options: {
          partials: {
            dir: process.cwd() + '/src/shared/mailer-templates/partials',
            options: {
              strict: true
            }
          },
        },
        preview: false,
      }),
      inject: [ ConfigService ]
    }),
    AuthModule,
    UsersModule,
  ],
  providers: [],
})
export class AppModule {}
