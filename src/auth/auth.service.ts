import {
  BadRequestException, ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { UsersService } from '../users/users.service';
import { PasswordService } from '../common/services/password.service';
import { TokensDto } from './dto/tokens.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SecurityConfig } from '../common/configs/config.interface';
import { LoginInput } from './dto/login.input';
import { google } from 'googleapis';
import { ResetDto } from './dto/reset.dto';
import { ActivateDto } from './dto/activate.dto';
import { RegisterDto } from './dto/register.dto';
import { MailerTransportService } from '../common/services/mailer.service';
import { SocialDto } from './dto/social.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly passwordService: PasswordService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailerTransportService: MailerTransportService,
  ) {
  }

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.usersService.findOneByEmail(email);
    const valid =
      user &&
      (await this.passwordService.validatePassword(password, user.password));
    if (user && valid) {
      return user;
    }
    return null;
  }

  async createUser(
    payload: RegisterDto,
  ): Promise<{ user: User; tokens: TokensDto }> {
    const alreadyExisted = await this.usersService.findOneByEmail(payload.email);

    if (alreadyExisted) {
      throw new ConflictException(`Email ${ payload.email } is already in use.`);
    }

    const hashedPassword = await this.passwordService.hashPassword(
      payload.password,
    );
    const activationToken = await this.generateActivationToken(payload.email);

    const user = await this.usersService.createUser({
      ...payload,
      password: hashedPassword,
    });

    await this.mailerTransportService.sendRegistrationEmail({
      email: user.email,
      name: user.name,
      token: activationToken,
    });

    return {
      user,
      tokens: await this.generateTokens({
        id: user.id,
        email: user.email,
        role: user.role,
      }),
    };
  }

  async login(payload: LoginInput): Promise<{ user: User, tokens: TokensDto }> {
    const user = await this.usersService.findOneByEmail(payload.email);
    if (!user) {
      throw new UnauthorizedException('Credential are not valid.');
    }

    if (user.isSuspended) {
      throw new UnauthorizedException('Sorry. This user is suspended for some reason.');
    } // TODO release suspend logic in FE?

    const validatePassword = await this.passwordService.validatePassword(
      payload.password,
      user.password,
    );

    if (!validatePassword) {
      throw new UnauthorizedException('Credential are not valid.');
    }
    return {
      user,
      tokens: await this.generateTokens({
        id: user.id,
        email: user.email,
        role: user.role,
      }),
    };
  }

  async googleAuth(payload: SocialDto): Promise<{ user: User, tokens: TokensDto }> {
    const googleUser = await this.getGoogleUser({ code: payload.code });
    //
    // console.log(googleUser);
    // if (!googleUser || googleUser.instanceOf(Error)) {
    //   throw new UnauthorizedException('Invalid authorization code.');
    // }

    let user = await this.usersService.findOneByEmail(googleUser.email);

    if (user && !user.googleId) {
      await this.usersService.updateUser(user.id, {
        googleId: googleUser.sub,
        name: googleUser.name,
        avatar: googleUser.picture,
      });
    }

    if (!user) {
      user = await this.usersService.createUser({
        password: await this.passwordService.hashPassword(`${ googleUser.sub } + ${ googleUser.email } + ${ googleUser.name } + ${ this.configService.get('UNDEFINED_SECRET') }`),
        email: googleUser.email.toLowerCase(),
        googleId: googleUser.sub,
        name: googleUser.name,
        avatar: googleUser.picture,
      });
      await this.mailerTransportService.sendRegistrationEmail({
        email: user.email,
        name: user.name,
        googleId: user.googleId,
      });
    }

    return {
      user,
      tokens: await this.generateTokens({
        id: user.id,
        email: user.email,
        role: user.role,
      }),
    };
  }

  getGoogleAuthUrl() {
    const scopes = [ 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile' ];

    return this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: scopes,
    });
  }

  async getUserFromToken(token: string): Promise<User> {
    const decodedToken = this.jwtService.decode(token);
    return this.usersService.findOneById(decodedToken.id);
  }

  async forgotPassword(email: string) {
    const user = await this.usersService.findOneByEmail(email);
    if (!user) {
      return new UnauthorizedException('Credential are not valid.');
    }
    const resetToken = await this.generateResetToken(user.email);

    await this.mailerTransportService.SendPasswordRestorationEmail({
      email: user.email,
      name: user.name,
      token: resetToken,
    });
    return true;
  }

  async changePassword(id: string, password: string, newPassword: string) {
    const user = await this.usersService.findOneById(id);
    if (!user) {
      return new UnauthorizedException('Credential are not valid.');
    }

    const valid = await this.passwordService.validatePassword(password, user.password);
    if (!valid) {
      return new UnauthorizedException('Credential are not valid.');
    }
    const hashedPassword = await this.passwordService.hashPassword(newPassword);
    await this.usersService.updateUser(user.id, { password: hashedPassword });

    return true;
  }

  async resetPassword({ resetToken, newPassword }: ResetDto): Promise<boolean | Error> {
    const securityConfig = this.configService.get<SecurityConfig>('security');

    try {
      const { email } = this.jwtService.verify(resetToken, {
        secret: securityConfig.jwtResetSecret,
      });

      const user = await this.usersService.findOneByEmail(email);

      if (!user) {
        return new UnauthorizedException('Credential are not valid.');
      }
      const hashedPassword = await this.passwordService.hashPassword(newPassword);
      await this.usersService.updateUser(user.id, { password: hashedPassword });

      return true;
    } catch (e) {
      return new UnauthorizedException('Token is not valid');
    }
  }

  async generateTokens(payload: {
    id: string;
    email: string;
    role: string;
  }): Promise<TokensDto> {
    return {
      accessToken: await this.generateAccessToken(payload),
      refreshToken: await this.generateRefreshToken(payload),
    };
  }

  private async generateAccessToken(payload: {
    id: string;
    email: string;
    role: string;
  }): Promise<string> {
    return this.jwtService.sign(payload);
  }

  private async generateRefreshToken(payload: { id: string; email: string }): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security');
    return this.jwtService.sign(payload, {
      secret: securityConfig.jwtRefreshSecret,
      expiresIn: securityConfig.jwtRefreshExpiresIn,
    });
  }

  private async generateResetToken(email: string): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security');
    return this.jwtService.sign(
      { email },
      {
        secret: securityConfig.jwtResetSecret,
        expiresIn: securityConfig.jwtResetExpiresIn,
      },
    );
  }

  private async generateActivationToken(email: string): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security');
    return this.jwtService.sign(
      { email },
      {
        secret: securityConfig.jwtActivationTokenSecret,
        expiresIn: securityConfig.jwtActivationTokenExpiresIn,
      },
    );
  }

  async validateRefreshToken(refreshToken: string): Promise<User> {
    const securityConfig = this.configService.get<SecurityConfig>('security');
    try {
      return this.jwtService.verify(refreshToken, {
        secret: securityConfig.jwtRefreshSecret,
      });
    } catch (e) {
      throw new UnauthorizedException('Token is not valid');
    }
  }


  private oauth2Client = new google.auth.OAuth2(
    this.configService.get('GOOGLE_CLIENT_ID'),
    this.configService.get('GOOGLE_CLIENT_SECRET'),
    `${ this.configService.get('FRONTEND_URL') }/auth/google/`,
  );

  private async getGoogleUser({ code }) {
    try {
      const { tokens } = await this.oauth2Client.getToken(code);
      this.oauth2Client.setCredentials(tokens);

      const response = await fetch(
        `https://www.googleapis.com/oauth2/v3/userinfo?access_token=${ tokens.access_token }`, {
          headers: {
            Authorization: `Bearer ${ tokens.id_token }`,
          },
        },
      );
      if (!response.ok) {
        return new UnauthorizedException();
      }
      return await response.json();
    } catch (e) {
      throw new UnauthorizedException(e);
    }
  }

  async activateUser({ activationToken }: ActivateDto): Promise<boolean | Error> {
    const securityConfig = this.configService.get<SecurityConfig>('security');

    try {
      const { email } = this.jwtService.verify(activationToken, {
        secret: securityConfig.jwtActivationTokenSecret,
      });
      const user = await this.usersService.findOneByEmail(email);
      if (!user) {
        return new UnauthorizedException('Credential are not valid.');
      }
      if (user.isActivated) {
        return new BadRequestException('User already activated.');
      }
      await this.usersService.updateUser(user.id, { isActivated: true });
      return true;
    } catch (e) {
      return false;
    }
  }
}
