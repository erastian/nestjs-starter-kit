import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { PasswordService } from '../common/services/password.service';
import { MailerService } from '@nestjs-modules/mailer';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'nestjs-prisma';
import { ConfigService } from '@nestjs/config';
import { MailerTransportService } from '../common/services/mailer.service';
import { authUserInputFactory, userFactory } from '../../test/factories/user.factory';
import { authTokensFactory, resetTokenFactory } from '../../test/factories/auth.factory';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { google } from 'googleapis';

describe('AuthService', () => {
  let service: AuthService;
  let usersService: UsersService;
  let passwordService: PasswordService;
  let mailerTransportService: MailerTransportService;
  let jwtService: JwtService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [],
      providers: [
        AuthService,
        UsersService,
        PasswordService,
        MailerTransportService,
        MailerService,
        { provide: JwtService, useValue: { verify: jest.fn(), decode: jest.fn(), sign: jest.fn() } },
        PrismaService,
        ConfigService,
      ],
    }).overrideProvider(MailerService)
      .useValue({ sendMail: jest.fn() })
      .compile();

    service = module.get(AuthService);
    usersService = module.get(UsersService);
    passwordService = module.get(PasswordService);
    mailerTransportService = module.get(MailerTransportService);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateUser', () => {
    it('should return a user if password is valid', async () => {
      const user = userFactory.build()

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'validatePassword').mockResolvedValueOnce(true);

      const result = await service.validateUser(user.email, user.password);
      expect(result).toEqual(user);
    });

    it('should return null if password is invalid', async () => {
      const user = userFactory.build()

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'validatePassword').mockResolvedValueOnce(false);

      const result = await service.validateUser(user.email, user.password);
      expect(result).toBeNull();
    });
  });

  describe('createUser', () => {
    it('should return exception if user already exists', async () => {
      const user = userFactory.build();

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);

      await expect(service.createUser(user)).rejects.toThrow();
    });

    it('should create user correctly', async () => {
      const registrationData = authUserInputFactory.build();
      const user = userFactory.build(registrationData);
      const tokens = authTokensFactory.build();

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(null);
      jest.spyOn(usersService, 'createUser').mockResolvedValueOnce(user);
      jest.spyOn(service, 'generateTokens').mockResolvedValueOnce(tokens);
      jest.spyOn(passwordService, 'hashPassword').mockResolvedValueOnce('hashed-password');
      jest.spyOn(service as any, 'generateActivationToken').mockResolvedValueOnce('some-token');
      jest.spyOn(mailerTransportService, 'sendRegistrationEmail').mockResolvedValueOnce();

      const result = await service.createUser(registrationData);

      expect(result.user).toEqual(user);
      expect(result.tokens).toEqual(tokens);
      expect(usersService.createUser).toHaveBeenCalledTimes(1);
    });
  });

  describe('login', () => {
    it('should login user correctly', async () => {
      const loginUserInput = authUserInputFactory.build();
      const user = userFactory.build({ ...loginUserInput, isSuspended: false });
      const tokens = authTokensFactory.build();

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'validatePassword').mockResolvedValueOnce(true);
      jest.spyOn(service, 'generateTokens').mockResolvedValueOnce(tokens);

      const result = await service.login(loginUserInput);

      expect(result.user).toEqual(user);
      expect(result.tokens).toEqual(tokens);
    });

    it('should return exception if user not found', async () => {
      const loginUserInput = authUserInputFactory.build();

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(null);

      await expect(service.login(loginUserInput)).rejects.toThrow();
    });

    it('should return exception if user is suspended', async () => {
      const loginUserInput = authUserInputFactory.build();
      const user = userFactory.build({ ...loginUserInput, isSuspended: true });

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);

      await expect(service.login(loginUserInput)).rejects.toThrow();
    });

    it('should return exception if password is invalid', async () => {
      const loginUserInput = authUserInputFactory.build();
      const user = userFactory.build(loginUserInput);

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'validatePassword').mockResolvedValueOnce(false);

      await expect(service.login(loginUserInput)).rejects.toThrow();
    });
  });

  describe('googleAuth', () => {
    it('should login user if user was found', async () => {
      const googleAuthCode = 'google-auth-code';
      const user = userFactory.build({ googleId: '111' });
      const tokens = authTokensFactory.build();
      const googleUser = {
        sub: '111',
        name: user.name,
        email: user.email,
        picture: user.avatar,
      };

      jest.spyOn(service as any, 'getGoogleUser').mockResolvedValueOnce(googleUser);
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(service, 'generateTokens').mockResolvedValueOnce(tokens);

      const result = await service.googleAuth({ code: googleAuthCode });

      expect(result.user).toEqual(user);
      expect(result.tokens).toEqual(tokens);
      expect(usersService.findOneByEmail).toHaveBeenCalledTimes(1);
    });

    it('should create user if user not found', async () => {
      const googleAuthCode = 'google-auth-code';
      const user = userFactory.build();
      const tokens = authTokensFactory.build();
      const googleUser = {
        sub: '111',
        name: user.name,
        email: user.email,
        picture: user.avatar,
      };

      jest.spyOn(service as any, 'getGoogleUser').mockResolvedValueOnce(googleUser);
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(null);
      jest.spyOn(usersService, 'createUser').mockResolvedValueOnce(user);
      jest.spyOn(service, 'generateTokens').mockResolvedValueOnce(tokens);
      jest.spyOn(passwordService, 'hashPassword').mockResolvedValueOnce('hashed-password');
      jest.spyOn(mailerTransportService, 'sendRegistrationEmail').mockResolvedValueOnce();

      const result = await service.googleAuth({ code: googleAuthCode });

      expect(result.user).toEqual(user);
      expect(result.tokens).toEqual(tokens);
      expect(usersService.createUser).toHaveBeenCalledTimes(1);
    });

    it('should update user if user already exists but has no googleId', async () => {
      const googleAuthCode = 'google-auth-code';
      const user = userFactory.build({ googleId: null });
      const tokens = authTokensFactory.build();
      const googleUser = {
        sub: '111',
        name: user.name,
        email: user.email,
        picture: user.avatar,
      };

      jest.spyOn(service as any, 'getGoogleUser').mockResolvedValueOnce(googleUser);
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(usersService, 'updateUser').mockResolvedValueOnce(user);
      jest.spyOn(service, 'generateTokens').mockResolvedValueOnce(tokens);

      const result = await service.googleAuth({ code: googleAuthCode });

      expect(result.user).toEqual(user);
      expect(result.tokens).toEqual(tokens);
      expect(usersService.updateUser).toHaveBeenCalledTimes(1);
    });
  });

  describe('getGoogleAuthUrl', () => {
    it('should return google auth url', async () => {
      const result = service.getGoogleAuthUrl();
      expect(result).toBeTruthy();
    })
  });

  describe('getUserFromToken', () => {
    it('should return user from token', async () => {
      const token = authTokensFactory.build().accessToken;
      const user = userFactory.build();

      jest.spyOn(jwtService, 'decode').mockReturnValueOnce({ id: user.id });
      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(user);

      const result = await service.getUserFromToken(token);
      expect(result).toEqual(user);
    });

    it('should return null if user not found', async () => {
      const token = authTokensFactory.build().accessToken;
      const id = 'non-existent-id'

      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(null);
      jest.spyOn(jwtService, 'decode').mockReturnValueOnce({ id });

      const result = await service.getUserFromToken(token);
      expect(result).toBeNull();
    })
  });

  describe('forgotPassword', () => {
    it('should send reset password email', async () => {
      const { email } = authUserInputFactory.build();
      const user = userFactory.build({ email });

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(service as any, 'generateResetToken').mockReturnValueOnce('reset-token');
      jest.spyOn(mailerTransportService, 'SendPasswordRestorationEmail').mockResolvedValueOnce();

      const result = await service.forgotPassword(email);
      expect(result).toEqual(true);
    });

    it('should return exception if user not found', async () => {
      const { email } = authUserInputFactory.build();

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(null);

      const result = await service.forgotPassword(email);
      expect(result).toBeInstanceOf(UnauthorizedException);
    })
  });

  describe('changePassword', () => {
    it('should change password', async () => {
      const user = userFactory.build();
      const password = 'password';
      const newPassword = 'new-password';

      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'validatePassword').mockResolvedValueOnce(true);
      jest.spyOn(passwordService, 'hashPassword').mockResolvedValueOnce('hashed-password');
      jest.spyOn(usersService, 'updateUser').mockResolvedValueOnce(user);

      const result = await service.changePassword(user.id, password, newPassword);
      expect(result).toEqual(true);
    });

    it('should return exception if user not found', async () => {
      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(null);

      const result = await service.changePassword('non-existent-id', 'password', 'new-password');
      expect(result).toBeInstanceOf(UnauthorizedException);
    });

    it('should return exception if password is not valid', async () => {
      const user = userFactory.build();

      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'validatePassword').mockResolvedValueOnce(false);

      const result = await service.changePassword(user.id, 'password', 'new-password');
      expect(result).toBeInstanceOf(UnauthorizedException);
    })
  });

  describe('resetPassword', () => {
    it('should reset password correctly', async () => {
      const { email } = authUserInputFactory.build();
      const user = userFactory.build({ email });
      const { resetToken } = resetTokenFactory(user).build();
      const newPassword = 'new-password';

      jest.spyOn(jwtService, 'verify').mockReturnValueOnce({ email: user.email });
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(passwordService, 'hashPassword').mockResolvedValueOnce('hashed-password');
      jest.spyOn(usersService, 'updateUser').mockResolvedValueOnce(user);
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtResetSecret: 'some-secret'
        }
      });

      const result = await service.resetPassword({ resetToken, newPassword });
      expect(result).toEqual(true);
    });

    it('should return exception if reset token is invalid', async () => {
      const resetToken = 'invalid-reset-token';
      const newPassword = 'new-password';

      jest.spyOn(jwtService, 'verify').mockImplementationOnce(() => {
        return new Error('Token is not valid');
      });

      const result = await service.resetPassword({ resetToken, newPassword });
      expect(result).toBeInstanceOf(UnauthorizedException);
    });

    it('should return exception if user not found', async () => {
      const { email } = authUserInputFactory.build();
      const user = userFactory.build({ email });
      const { resetToken } = resetTokenFactory(user).build();
      const newPassword = 'new-password';

      jest.spyOn(jwtService, 'verify').mockReturnValueOnce({ email: user.email });
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(null);
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtResetSecret: 'some-secret'
        }
      });

      const result = await service.resetPassword({ resetToken, newPassword });
      expect(result).toBeInstanceOf(UnauthorizedException);
    });
  });

  describe('generateTokens', () => {
    it('should generate tokens correctly', async () => {
      const user = userFactory.build();
      const tokens = authTokensFactory.build();

      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(user);
      jest.spyOn(service as any, 'generateAccessToken').mockReturnValueOnce(tokens.accessToken);
      jest.spyOn(service as any, 'generateRefreshToken').mockReturnValueOnce(tokens.refreshToken);

      const result = await service.generateTokens({ id: user.id, email: user.email, role: user.role });
      expect(result).toEqual(tokens);
    })
  });

  describe('generateAccessToken', () => {
    it('should generate access token correctly', async () => {
      const user = userFactory.build();
      const accessToken = 'access-token';

      jest.spyOn(jwtService as any, 'sign').mockResolvedValueOnce(accessToken);

      const result = await (service as any).generateAccessToken({ id: user.id, email: user.email, role: user.role });
      expect(result).toEqual(accessToken);
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate refresh token correctly', async () => {
      const user = userFactory.build();
      const refreshToken = 'refresh-token';

      jest.spyOn(jwtService as any, 'sign').mockResolvedValueOnce(refreshToken);
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtRefreshSecret: 'some-secret',
          jwtRefreshExpiresIn: '1d'
        }
      });

      const result = await (service as any).generateRefreshToken({ id: user.id, email: user.email });
      expect(result).toEqual(refreshToken);
    });
  });

  describe('generateResetToken', () => {
    it('should generate reset token correctly', async () => {
      const user = userFactory.build();
      const refreshToken = 'reset-token';

      jest.spyOn(jwtService as any, 'sign').mockResolvedValueOnce(refreshToken);
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtResetSecret: 'some-secret',
          jwtResetExpiresIn: '2h'
        }
      });

      const result = await (service as any).generateResetToken({ email: user.email });
      expect(result).toEqual(refreshToken);
    });
  });

  describe('generateActivationToken', () => {
    it('should generate activation token correctly', async () => {
      const user = userFactory.build();
      const refreshToken = 'reset-token';

      jest.spyOn(jwtService as any, 'sign').mockResolvedValueOnce(refreshToken);
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtActivationTokenSecret: 'some-secret',
          jwtActivationTokenExpiresIn: '2d'
        }
      });

      const result = await (service as any).generateActivationToken({ email: user.email });
      expect(result).toEqual(refreshToken);
    });
  });

  describe('validateRefreshToken', () => {
    it('should validate refresh token correctly', async () => {
      const refreshToken = 'refresh-token';
      const user = userFactory.build();

      jest.spyOn(jwtService as any, 'verify').mockReturnValueOnce({ email: user.email });
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtRefreshSecret: 'some-secret',
        }
      });

      const result = await service.validateRefreshToken(refreshToken);
      expect(result).toEqual({ email: user.email });
    });
  });

  describe('oauth2Client', () => {
    it('should create oAuth client with correct configuration', async () => {
      const clientId = 'mock-client-id';
      const clientSecret = 'mock-client-secret';
      const frontendUrl = 'mock-frontend-url';

      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        switch (key) {
          case 'GOOGLE_CLIENT_ID':
            return clientId;
          case 'GOOGLE_CLIENT_SECRET':
            return clientSecret;
          case 'FRONTEND_URL':
            return frontendUrl;
          default:
            throw new Error(`Unknown config key: ${ key }`);
        }
      });

      const oauth2Client = new google.auth.OAuth2(
        configService.get('GOOGLE_CLIENT_ID'),
        configService.get('GOOGLE_CLIENT_SECRET'),
        `${ configService.get('FRONTEND_URL') }/auth/google/`,
      );

      expect(oauth2Client._clientId).toBe(clientId);
      expect(oauth2Client._clientSecret).toBe(clientSecret);
      expect((oauth2Client as any).redirectUri).toBe(`${ frontendUrl }/auth/google/`);
    });
  });

  describe('getGoogleUser', () => {
    it('should retrieve gUser data successfully', async () => {
      const code = 'mock-code';
      const tokens = {
        access_token: 'mock-access-token',
        id_token: 'mock-id-token',
      };
      const googleUserData = {
        sub: 'mock-sub',
        name: 'mock-name',
        email: 'mock-email',
        picture: 'mock-picture',
      };

      jest.spyOn((service as any).oauth2Client, 'getToken').mockResolvedValue({ tokens });
      jest.spyOn((service as any).oauth2Client, 'setCredentials').mockImplementationOnce(() => {
      });
      const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => googleUserData,
      } as Response);

      const result = await (service as any).getGoogleUser({ code });
      expect(result).toEqual(googleUserData);
      expect(fetchMock).toHaveBeenCalledWith(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${ tokens.access_token }`, {
        headers: {
          Authorization: `Bearer mock-id-token`,
        }
      });
    });

    it('should return UnauthorizedException if token is invalid', async () => {
      const code = 'mock-code';

      jest.spyOn((service as any).oauth2Client, 'getToken').mockRejectedValue(new Error('Invalid token'));

      await expect((service as any).getGoogleUser({ code })).rejects.toThrow(UnauthorizedException);
    });

    it('should return UnauthorizedException if response is not ok', async () => {
      const code = 'mock-code';
      const tokens = {
        access_token: 'mock-access-token',
        id_token: 'mock-id-token',
      };

      jest.spyOn((service as any).oauth2Client, 'getToken').mockResolvedValue({ tokens });
      jest.spyOn((service as any).oauth2Client, 'setCredentials').mockImplementationOnce(() => {
      });
      const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 401,
      } as Response);

      await expect((service as any).getGoogleUser({ code })).resolves.toThrow(UnauthorizedException);
      expect(fetchMock).toHaveBeenCalledWith(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${ tokens.access_token }`, {
        headers: {
          Authorization: `Bearer ${ tokens.id_token }`,
        }
      });
    })
  });

  describe('activateUser', () => {
    it('should activate user successfully', async () => {
      const user = userFactory.build({ isActivated: false });

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(usersService, 'updateUser').mockResolvedValueOnce(user);
      jest.spyOn(jwtService, 'verify').mockReturnValueOnce({ email: user.email });
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtActivationTokenSecret: 'some-secret'
        }
      });

      const result = await (service as any).activateUser({ activationToken: 'token' });
      expect(result).toEqual(true);
      expect(usersService.updateUser).toHaveBeenCalledWith(user.id, { isActivated: true });
      expect(jwtService.verify).toHaveBeenCalledWith('token', { secret: 'some-secret' });
    });

    it('should return false if user not found', async () => {
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(null);
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtActivationTokenSecret: 'some-secret'
        }
      });

      const result = await (service as any).activateUser({ activationToken: 'token' });
      expect(result).toEqual(false);
    });

    it('should return false if token is invalid', async () => {
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtActivationTokenSecret: 'some-secret'
        }
      });
      jest.spyOn(jwtService, 'verify').mockReturnValueOnce(new Error('Token is invalid'));

      const result = await (service as any).activateUser({ activationToken: 'token' });
      expect(result).toEqual(false);
    });

    it('should return false if user is already activated', async () => {
      const user = userFactory.build({ isActivated: true });

      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValueOnce(user);
      jest.spyOn(jwtService, 'verify').mockReturnValueOnce({ email: user.email });
      jest.spyOn(configService as any, 'get').mockImplementationOnce(() => {
        return {
          jwtActivationTokenSecret: 'some-secret'
        }
      });

      const result = await (service as any).activateUser({ activationToken: 'token' });
      expect(result).toBeInstanceOf(BadRequestException);
    })
  });
});
