import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SecurityConfig } from '../common/configs/config.interface';
import { GqlAuthGuard } from '../common/guards/gql-auth.guard';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PasswordService } from '../common/services/password.service';
import { UsersService } from '../users/users.service';
import { LocalStrategy } from './strategies/local.strategy';
import { RolesGuard } from '../common/guards/roles.guard';
import { MailerTransportService } from '../common/services/mailer.service';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: undefined,
      useFactory: async (configService: ConfigService) => {
        const securityConfig = configService.get<SecurityConfig>('security');
        return {
          secret:
            securityConfig.jwtAccessSecret ||
            configService.get<string>('JWT_ACCESS_SECRET'),
          signOptions: {
            expiresIn: securityConfig.jwtAccessExpiresIn || '60m',
          },
        };
      },
      inject: [ConfigService]
    }),
  ],
  providers: [
    AuthResolver,
    AuthService,
    JwtStrategy,
    LocalStrategy,
    GqlAuthGuard,
    PasswordService,
    UsersService,
    RolesGuard,
    MailerTransportService
  ],
  exports: [GqlAuthGuard],
})
export class AuthModule {}
