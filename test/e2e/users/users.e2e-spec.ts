import { E2EApp, initializeApp } from '../test-utils/initialize-app';
import { prismaService } from '../../config/setupTests.e2e';
import { authUserInputFactory, userFactory } from '../../factories/user.factory';
import { AuthResolver } from '../../../src/auth/auth.resolver';
import * as request from 'supertest';
import { print } from 'graphql';
import {
  GetAllUsersQuery,
  GetProfileQuery,
  GetUserQuery,
  UpdateProfileQuery,
  UpdateUserProfileQuery,
} from '../queries/queries';
import Role from '../../../src/common/enums/roles.enum';

describe('UsersModule (e2e)', () => {
  let e2e: E2EApp;
  const authUserInput = authUserInputFactory.build();
  const authAdminInput = authUserInputFactory.build();
  let userWithToken: any;
  let adminWithToken: any;

  beforeAll(async () => {
    e2e = await initializeApp();

    const authResolver = e2e.app.get(AuthResolver);
    userWithToken = await authResolver.register(authUserInput, {} as any);
    adminWithToken = await authResolver.register(authAdminInput, {} as any);

    await prismaService.user.update({
      where: { id: adminWithToken.user.id },
      data: { role: Role.ADMIN },
    });

    adminWithToken = await authResolver.login(authAdminInput, {} as any);
  });

  afterAll(async () => {
    e2e.cleanup();
  });


  describe('getProfile query', () => {
    it('should return user profile', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ userWithToken.accessToken }`)
        .send({ query: print(GetProfileQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.user).toBeDefined();
          expect(res.body.data.user.id).toEqual(userWithToken.user.id);
          expect(res.body.data.user.email).toEqual(userWithToken.user.email);
          expect(res.body.data.user.isActivated).toEqual(userWithToken.user.isActivated);
          expect(res.body.data.user.isSuspended).toEqual(userWithToken.user.isSuspended);
          expect(res.body.data.user.googleId).toBeNull();
          expect(res.body.data.user.avatar).toBeNull();
          expect(res.body.data.user.role).toBe(Role.USER);
        });
    });

    it('should return error if user not authenticated', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(GetProfileQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('getAllUsers query', () => {
    it('should return error if user not admin', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ userWithToken.accessToken }`)
        .send({ query: print(GetAllUsersQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return all users if user is admin', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ adminWithToken.accessToken }`)
        .send({ query: print(GetAllUsersQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.users).toBeDefined();
          expect(res.body.data.users).toHaveLength(2);
        });
    });

    it('should return error if user not authenticated', async () => {
      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(GetAllUsersQuery) })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('getUser query', () => {
    it('should return error if current user not admin', async () => {
      const variables = { input: userWithToken.user.id };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ userWithToken.accessToken }`)
        .send({ query: print(GetUserQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return user by ID if current user is admin', async () => {
      const variables = { input: userWithToken.user.id };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ adminWithToken.accessToken }`)
        .send({ query: print(GetUserQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.getUser).toBeDefined();
          expect(res.body.data.getUser.id).toEqual(userWithToken.user.id);
          expect(res.body.data.getUser.email).toEqual(userWithToken.user.email);
          expect(res.body.data.getUser.isActivated).toEqual(userWithToken.user.isActivated);
          expect(res.body.data.getUser.isSuspended).toEqual(userWithToken.user.isSuspended);
          expect(res.body.data.getUser.googleId).toBeNull();
          expect(res.body.data.getUser.avatar).toEqual(userWithToken.user.avatar);
          expect(res.body.data.getUser.role).toBe(Role.USER);
        });
    });

    it('should return error if current user not authenticated', async () => {
      const variables = { input: userWithToken.user.id };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(GetUserQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });
  });

  describe('updateProfile mutation', () => {
    it('should return error if user not authenticated', async () => {
      const updatedUserData = userFactory.build();
      const variables = {
        input: {
          name: updatedUserData.name,
          avatar: updatedUserData.avatar,
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(UpdateProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should update user profile if user is authenticated', async () => {
      const updatedUserData = userFactory.build();
      const variables = {
        input: {
          name: updatedUserData.name,
          avatar: updatedUserData.avatar,
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ userWithToken.accessToken }`)
        .send({ query: print(UpdateProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.updateProfile).toBeDefined();
          expect(res.body.data.updateProfile.name).toEqual(updatedUserData.name);
          expect(res.body.data.updateProfile.avatar).toEqual(updatedUserData.avatar);
        });
    })
  });

  describe('updateUserProfile mutation', () => {
    it('should return error if user not authenticated', async () => {
      const variables = { input: userWithToken.user.id };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .send({ query: print(UpdateUserProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should return error if current user not admin', async () => {
      const variables = { input: userWithToken.user.id };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ userWithToken.accessToken }`)
        .send({ query: print(UpdateUserProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.errors).toBeDefined();
        });
    });

    it('should update user profile if current user is admin', async () => {
      const updatedUserData = userFactory.build();
      const variables = {
        input: {
          id: userWithToken.user.id,
          isActivated: true,
          name: updatedUserData.name,
          avatar: updatedUserData.avatar,
        },
      };

      return await request(e2e.app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${ adminWithToken.accessToken }`)
        .send({ query: print(UpdateUserProfileQuery), variables })
        .expect(200)
        .expect((res) => {
          expect(res.body.data.updateUserProfile).toBeDefined();
          expect(res.body.data.updateUserProfile.id).toEqual(userWithToken.user.id);
          expect(res.body.data.updateUserProfile.email).toEqual(userWithToken.user.email);
          expect(res.body.data.updateUserProfile.name).toEqual(updatedUserData.name);
          expect(res.body.data.updateUserProfile.isActivated).toEqual(true);
          expect(res.body.data.updateUserProfile.isSuspended).toEqual(userWithToken.user.isSuspended);
          expect(res.body.data.updateUserProfile.googleId).toBeNull();
          expect(res.body.data.updateUserProfile.avatar).toEqual(updatedUserData.avatar);
          expect(res.body.data.updateUserProfile.role).toBe(Role.USER);
        });
    });
  });
});