import { E2EApp, initializeApp } from '../test-utils/initialize-app';
import { authUserInputFactory } from '../../factories/user.factory';
import Role from '../../../src/common/enums/roles.enum';
import * as request from 'supertest';
import { print } from 'graphql';
import {
  ActivateProfileQuery, ChangePasswordQuery,
  ForgotPasswordQuery,
  GetGoogleAuthUrlQuery,
  GoogleAuthQuery,
  LoginQuery,
  LogoutQuery, RefreshQuery,
  RegisterQuery, ResetPasswordQuery,
} from '../queries/queries';
import { AuthService } from '../../../src/auth/auth.service';
import { googleUserFactory } from '../../factories/auth.factory';
import { UnauthorizedException } from '@nestjs/common';

describe('AuthModule (e2e)', () => {
  let e2e: E2EApp;

  beforeAll(async () => {
    e2e = await initializeApp();
  });

  afterAll(async () => {
    e2e.cleanup();
  });

  const authUserInput = authUserInputFactory.build();
  let resetToken: string;
  let activationToken: string;
  let testAccessToken: string;
  let tempPassword: string;
  let tempRefreshToken: string;

  describe('register mutation', () => {
    it('should return error if email is corrupted', async () => {
      const fakeEmail = 'fake-email';
      const somePassword = 'some-password';

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(RegisterQuery), variables: { input: { email: fakeEmail, password: somePassword } } })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return error if password is too short', async () => {
      const shortPassword = 'short';

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({
          query: print(RegisterQuery),
          variables: { input: { email: authUserInput.email, password: shortPassword } },
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should register and login a new user', async () => {
      const variables = { input: authUserInput };
      const authService = e2e.app.get(AuthService);
      const tokenSpy = jest.spyOn(authService as any, 'generateActivationToken');

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(RegisterQuery), variables })
        .expect(200)
        .expect(async (res) => {
          const cookies = res.headers['set-cookie'] as any;
          expect(cookies.some((cookie: string) => /refreshToken=.*HttpOnly/.test(cookie))).toBe(true);
          expect(res.body.data.register.user).toBeDefined();
          expect(res.body.data.register.user.email).toBe(authUserInput.email.toLowerCase());
          expect(res.body.data.register.user.name).toBe(null);
          expect(res.body.data.register.user.role).toBe(Role.USER);
          expect(res.body.data.register.user.isActivated).toBe(false);
          expect(res.body.data.register.user.isSuspended).toBe(false);
          expect(res.body.data.register.accessToken).toBeDefined();
          activationToken = await tokenSpy.mock.results[0].value;
        });
    });

    it('should throw an error if user already exists', async () => {
      const variables = { input: authUserInput };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(RegisterQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('login query', () => {
    it('should login a user', async () => {
      const variables = { input: authUserInput };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(LoginQuery), variables })
        .expect(200)
        .expect((res) => {
          const cookies = res.headers['set-cookie'] as any;
          expect(cookies.some((cookie: string) => /refreshToken=.*HttpOnly/.test(cookie))).toBe(true);
          expect(res.body.data.login.user).toBeDefined();
          expect(res.body.data.login.user.email).toBe(authUserInput.email.toLowerCase());
          expect(res.body.data.login.user.name).toBe(null);
          expect(res.body.data.login.user.role).toBe(Role.USER);
          expect(res.body.data.login.user.isActivated).toBe(false);
          expect(res.body.data.login.user.isSuspended).toBe(false);
          expect(res.body.data.login.accessToken).toBeDefined();
          testAccessToken = res.body.data.login.accessToken;
          tempRefreshToken = cookies.find((cookie: string) => /refreshToken=.*HttpOnly/.test(cookie))?.split('=')[1].split(';')[0];
        });
    });

    it('should throw an error if user does not exist', async () => {
      const variables = { input: authUserInputFactory.build() };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(LoginQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should throw an error if password is incorrect', async () => {
      const variables = { input: { email: authUserInput.email, password: 'wrong-password' } };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(LoginQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('Google Auth query', () => {
    let authService: AuthService;
    const gUser = googleUserFactory.build();

    beforeEach(() => {
      authService = e2e.app.get(AuthService);
    });

    it('should register and login user by gAuth correctly if user does not exist', async () => {
      const gAuthToken = 'some-valid-g-auth-token';
      const variables = { data: { code: gAuthToken } };

      jest.spyOn(authService as any, 'getGoogleUser').mockResolvedValueOnce(gUser);

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({
          query: print(GoogleAuthQuery),
          variables,
        })
        .expect(200)
        .expect((res) => {
          const cookies = res.headers['set-cookie'] as any;
          expect(cookies.some((cookie: string) => /refreshToken=.*HttpOnly/.test(cookie))).toBe(true);
          expect(res.body.data.googleAuth.user).toBeDefined();
          expect(res.body.data.googleAuth.user.email).toBe(gUser.email.toLowerCase());
          expect(res.body.data.googleAuth.user.name).toBe(gUser.name);
          expect(res.body.data.googleAuth.user.role).toBe(Role.USER);
          expect(res.body.data.googleAuth.user.googleId).toBe(gUser.sub);
          expect(res.body.data.googleAuth.user.isActivated).toBe(true);
          expect(res.body.data.googleAuth.user.isSuspended).toBe(false);
          expect(res.body.data.googleAuth.accessToken).toBeDefined();
        });
    });


    it('should return error if token is invalid', async () => {
      const gAuthToken = 'some-invalid-g-auth-token';
      const variables = { data: { code: gAuthToken } };

      jest.spyOn(authService as any, 'getGoogleUser').mockRejectedValueOnce(UnauthorizedException);

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({
          query: print(GoogleAuthQuery),
          variables,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('Get gAuth URL query', () => {
    it('should return gAuth URL', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(GetGoogleAuthUrlQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.getGoogleAuthUrl).toBeDefined();
        });
    });
  });

  describe('Logout query', () => {
    it('should logout a user', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Cookie', 'refreshToken=some-refresh-token; HttpOnly')
        .send({ query: print(LogoutQuery) })
        .expect(200)
        .expect((res) => {
          const cookies = res.headers['set-cookie'] as any;
          expect(cookies.some((cookie: string) => /refreshToken=.*HttpOnly/.test(cookie))).toBe(false);
          expect(res.body.data.logout).toBeDefined();
          expect(res.body.data.logout.status).toBe(true);
          expect(res.body.data.logout.message).toBeTruthy();
        });
    });
  });

  describe('forgotPassword query', () => {
    it('should accept valid email', async () => {
      const variables = { input: authUserInput.email };
      const authService = e2e.app.get(AuthService);
      const tokenSpy = jest.spyOn(authService as any, 'generateResetToken');

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(ForgotPasswordQuery), variables })
        .expect(200)
        .expect(async (res) => {
          expect(res.body.data.forgotPassword).toBeDefined();
          expect(res.body.data.forgotPassword.status).toBe(true);
          expect(res.body.data.forgotPassword.message).toBeTruthy();
          resetToken = await tokenSpy.mock.results[0].value;
        });
    });

    it('should return error if email is not valid', async () => {
      const variables = { input: { email: authUserInputFactory.build().email } };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(ForgotPasswordQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('resetPassword mutation', () => {
    it('should reset password with valid token correctly', async () => {
      const variables = {
        input: {
          resetToken: resetToken,
          newPassword: authUserInputFactory.build().password,
        },
      };
      tempPassword = variables.input.newPassword;

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(ResetPasswordQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.resetPassword).toBeDefined();
          expect(res.body.data.resetPassword).toBeTruthy();
        });
    });

    it('should return error if token is invalid', async () => {
      const token = 'some-invalid-token';
      const variables = {
        input: {
          resetToken: token,
          newPassword: authUserInputFactory.build().password,
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(ResetPasswordQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('activateProfile mutation', () => {
    it('should activate profile', async () => {
      const variables = { input: { activationToken: activationToken } };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(ActivateProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.activateProfile).toBeDefined();
          expect(res.body.data.activateProfile).toBeTruthy();
        });
    });

    it('should return error if token is invalid', async () => {
      const token = 'some-invalid-token';
      const variables = { input: { activationToken: token } };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(ActivateProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('changePassword mutation', () => {
    it('should return error if old password is incorrect', async () => {
      const variables = {
        data: {
          password: 'wrong-password',
          newPassword: authUserInputFactory.build().password,
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ testAccessToken }`)
        .send({ query: print(ChangePasswordQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return error if new password is too short', async () => {
      const variables = {
        data: {
          password: tempPassword,
          newPassword: 'short',
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ testAccessToken }`)
        .send({ query: print(ChangePasswordQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should change password', async () => {
      const variables = {
        data: {
          password: tempPassword,
          newPassword: authUserInputFactory.build().password,
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ testAccessToken }`)
        .send({ query: print(ChangePasswordQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.changePassword).toBeDefined();
          expect(res.body.data.changePassword).toBeTruthy();
        });
    });
  });

  describe('refresh query', () => {
    it('should return error if refresh token malformed', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Cookie', 'refreshToken=some-refresh-token; HttpOnly')
        .send({ query: print(RefreshQuery) })
        .expect(200)
        .expect((res) => {
          const cookies = res.headers['set-cookie'] as any;
          expect(cookies).toBeFalsy();
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return error if refresh token is not found', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(RefreshQuery) })
        .expect(200)
        .expect((res) => {
          const cookies = res.headers['set-cookie'] as any;
          expect(cookies).toBeFalsy();
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return access token if refresh token is valid', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Cookie', `refreshToken=${ tempRefreshToken }; HttpOnly`)
        .send({ query: print(RefreshQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.refresh).toBeDefined();
          expect(res.body.data.refresh.accessToken).toBeTruthy();
        });
    });
  });
});
