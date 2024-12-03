import { Test, TestingModule } from '@nestjs/testing';
import { AuthResolver } from './auth.resolver';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config';
import { PasswordService } from '../common/services/password.service';
import { MailerService } from '@nestjs-modules/mailer';
import { PrismaService } from 'nestjs-prisma';
import { authUserInputFactory, userFactory } from '../../test/factories/user.factory';
import { User } from '../users/entities/user.entity';
import { MailerTransportService } from '../common/services/mailer.service';
import { BadRequestException, ConflictException, UnauthorizedException } from '@nestjs/common';
import { TokensDto } from './dto/tokens.dto';

describe('AuthResolver', () => {
  let authResolver: AuthResolver;
  let authService: AuthService;
  let usersService: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [ JwtModule.register({ secret: 'secret' }) ],
      providers: [
        AuthResolver,
        AuthService,
        UsersService,
        ConfigService,
        PasswordService,
        PrismaService,
        MailerTransportService,
        MailerService
      ],
    }).overrideProvider(MailerService)
      .useValue({ sendMail: jest.fn() })
      .compile();

    authResolver = module.get(AuthResolver);
    authService = module.get(AuthService);
    usersService = module.get(UsersService);
  });

  it('AuthResolver should be defined', () => {
    expect(authResolver).toBeDefined();
  });

  describe('register', () => {
    it('should register user correctly', async () => {
      const registerUserInput = authUserInputFactory.build();
      const expectedUser = userFactory.build(registerUserInput) as User;

      jest.spyOn(authService, 'createUser').mockResolvedValueOnce({
        user: expectedUser,
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token'
        }
      } as any);

      const result = await authResolver.register(registerUserInput, {} as any);
      expect(result.user).toEqual(expectedUser);
      expect(result.accessToken).toBeTruthy();
    })

    it('should throw an error if user already exists', async () => {
      const registerUserInput = authUserInputFactory.build();
      // @ts-ignore
      jest.spyOn(authService, 'createUser').mockRejectedValueOnce(ConflictException);
      await expect(authResolver.register(registerUserInput, {} as any)).rejects.toThrow();
    })
  });

  describe('login', () => {
    it('should login user correctly', async () => {
      const loginUserInput = authUserInputFactory.build();
      const expectedUser = userFactory.build(loginUserInput) as User;

      // @ts-ignore
      jest.spyOn(authService, 'login').mockResolvedValueOnce({
        user: expectedUser,
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token'
        }
      } as any);

      const result = await authResolver.login(loginUserInput, {} as any);
      expect(result.user).toEqual(expectedUser);
      expect(result.accessToken).toBeTruthy();
    })

    it('should return exception if credentials are invalid', async () => {
      const loginUserInput = authUserInputFactory.build();

      jest.spyOn(authService, 'login').mockRejectedValueOnce(ConflictException);
      await expect(authResolver.login(loginUserInput, {} as any)).rejects.toThrow();
    })
  })

  describe('googleAuth', () => {
    it('should login user by gAuth correctly', async () => {
      const googleAuthInput = { code: 'google-auth-input' };
      const expectedUser = userFactory.build() as User;

      // @ts-ignore
      jest.spyOn(authService, 'googleAuth').mockResolvedValueOnce({
        user: expectedUser,
        tokens: {
          accessToken: 'access-token',
          refreshToken: 'refresh-token'
        }
      } as any);

      const result = await authResolver.googleAuth(googleAuthInput, {} as any);
      expect(result.user).toEqual(expectedUser);
      expect(result.accessToken).toBeTruthy();
    })
  })

  describe('getGoogleAuthUrl', () => {
    it('should return gAuth URL', async () => {
      // @ts-ignore
      jest.spyOn(authService, 'getGoogleAuthUrl').mockResolvedValueOnce('some-url')
      const result = await authResolver.getGoogleAuthUrl();
      expect(result).toEqual('some-url');
    })
  })

  describe('logout', () => {
    it('should logout correctly', async () => {
      const result = await authResolver.logout({} as any);
      expect(result).toEqual({
        status: true,
        message: 'Logout successful. Thank you for using our service! =)'
      });
    })
  })

  describe('forgotPassword', () => {
    it('should accept email correctly', async () => {
      const userInput = authUserInputFactory.build();

      jest.spyOn(authService, 'forgotPassword').mockResolvedValueOnce(true);
      const result = await authResolver.forgotPassword(userInput.email);
      expect(result.status).toBe(true);
      expect(result.message).toBe(`Restoration email for user ${ userInput.email.toLowerCase() } was sent.`)
    });

    it('should return exception if email is not registered', async () => {
      const userInput = authUserInputFactory.build();

      jest.spyOn(authService, 'forgotPassword').mockRejectedValueOnce(UnauthorizedException);
      await expect(authResolver.forgotPassword(userInput.email)).rejects.toThrow();
    })
  });


  describe('resetPassword', () => {
    it('should reset password correctly', async () => {
      const resetPwdInput = { resetToken: 'reset-token-with-more-than-16-symbols', newPassword: 'new-password' };

      jest.spyOn(authService, 'resetPassword').mockResolvedValueOnce(true);
      const result = await authResolver.resetPassword(resetPwdInput);
      expect(result).toBe(true);
    });

    it('should return exception if reset token is invalid', async () => {
      const resetPwdInput = { resetToken: 'reset-token-with-more-than-16-symbols', newPassword: 'new-password' };

      jest.spyOn(authService, 'resetPassword').mockRejectedValueOnce(UnauthorizedException);
      await expect(authResolver.resetPassword(resetPwdInput)).rejects.toThrow();
    });
  });

  describe('activateProfile', () => {
    it('should activate profile correctly', async () => {
      const activateInput = { activationToken: 'activation-token' };

      jest.spyOn(authService, 'activateUser').mockResolvedValueOnce(true);
      const result = await authResolver.activateProfile(activateInput);
      expect(result).toBe(true);
    });

    it('should return exception if activation token is invalid', async () => {
      const activateInput = { activationToken: 'activation-token' };

      jest.spyOn(authService, 'activateUser').mockRejectedValueOnce(UnauthorizedException);
      await expect(authResolver.activateProfile(activateInput)).rejects.toThrow();
    });

    it('should return exception if user already activated', async () => {
      const activateInput = { activationToken: 'activation-token' };

      jest.spyOn(authService, 'activateUser').mockRejectedValueOnce(BadRequestException);
      await expect(authResolver.activateProfile(activateInput)).rejects.toThrow();
    });
  });

  describe('changePassword', () => {
    it('should change password correctly', async () => {
      const user = userFactory.build();
      const changePwdInput = { password: 'old-password', newPassword: 'new-password' };

      jest.spyOn(authService, 'changePassword').mockResolvedValueOnce(true);
      const result = await authResolver.changePassword(user, changePwdInput);
      expect(result).toBe(true);
    });
  });

  describe('refreshToken', () => {
    it('should return new accessToken correctly if refresh token is valid', async () => {
      const req = { cookies: { refreshToken: 'refresh-token' } } as any;
      const user = userFactory.build({ isSuspended: false });
      const tokens: TokensDto = { accessToken: 'new-access-token', refreshToken: 'new-refresh-token' };

      jest.spyOn(authService, 'validateRefreshToken').mockResolvedValueOnce(user);
      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(user);
      jest.spyOn(authService, 'generateTokens').mockResolvedValueOnce(tokens);

      const result = await authResolver.refresh(req);
      expect(result).toEqual({ accessToken: tokens.accessToken });
    });

    it('should throw UnauthorizedException if user suspended', async () => {
      const req = { cookies: { refreshToken: 'valid-token' } } as any;
      const user = userFactory.build({ isSuspended: true });

      jest.spyOn(authService, 'validateRefreshToken').mockResolvedValueOnce(user);
      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(user);

      await expect(authResolver.refresh(req)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if user not found', async () => {
      const req = { cookies: { refreshToken: 'valid-token' } } as any;
      const user = userFactory.build({ isSuspended: false });

      jest.spyOn(authService, 'validateRefreshToken').mockResolvedValueOnce(user);
      jest.spyOn(usersService, 'findOneById').mockResolvedValueOnce(null);

      await expect(authResolver.refresh(req)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if no refresh token is provided', async () => {
      const req = { cookies: {} } as any;

      await expect(authResolver.refresh(req)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if refresh token is invalid', async () => {
      const req = { cookies: { refreshToken: 'invalid-token' } } as any;

      jest.spyOn(authService, 'validateRefreshToken').mockResolvedValueOnce(null);

      await expect(authResolver.refresh(req)).rejects.toThrow(UnauthorizedException);
    });
  });
});
