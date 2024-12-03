import { Test, TestingModule } from '@nestjs/testing';
import { UsersResolver } from './users.resolver';
import { UsersService } from './users.service';
import { PrismaService } from 'nestjs-prisma';
import { ConfigService } from '@nestjs/config';
import { userFactory } from '../../test/factories/user.factory';
import { UpdateProfileInput } from './dto/update-profile.input';
import { UpdateUserProfileInput } from './dto/update-user-profile.input';

describe('UsersResolver', () => {
  let resolver: UsersResolver;
  let service: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ UsersResolver, UsersService, PrismaService, ConfigService ],
    }).compile();

    resolver = module.get(UsersResolver);
    service = module.get(UsersService);
  });

  it('should be defined', () => {
    expect(resolver).toBeDefined();
  });

  describe('getAllUsers', () => {
    it('should return an array of users', async () => {
      const expected = userFactory.buildList(3);

      jest.spyOn(service, 'findAllUsers').mockResolvedValueOnce(expected as any);

      const result = await resolver.getAllUsers();
      expect(result).toEqual(expected);
    })
  });

  describe('getUserById', () => {
    it('should return a user by id', async () => {
      const expected = userFactory.build();

      jest.spyOn(service, 'findOneById').mockResolvedValueOnce(expected);

      const result = await resolver.getUser(expected.id);
      expect(result).toEqual(expected);
    });

    it('should return null if user not found', async () => {
      const expected = null;

      jest.spyOn(service, 'findOneById').mockResolvedValueOnce(expected);

      const result = await resolver.getUser('invalid-id');
      expect(result).toEqual(expected);
    })
  })

  describe('getProfile', () => {
    it('should return a current user', async () => {
      const expected = userFactory.build();

      jest.spyOn(service, 'findOneById').mockResolvedValueOnce(expected);

      const result = await resolver.getProfile(expected);
      expect(result).toEqual(expected);
    })
  })

  describe('updateProfile', () => {
    it('should return an updated user', async () => {
      const [ originalUser, anotherUser ] = userFactory.buildList(2);
      const updateUserInput: UpdateProfileInput = {
        name: anotherUser.name,
        avatar: anotherUser.avatar
      }
      const expected = { ...originalUser, ...updateUserInput };

      jest.spyOn(service, 'updateUser').mockResolvedValueOnce(expected);

      const result = await resolver.updateProfile(originalUser, updateUserInput);
      expect(result).toEqual(expected);
    })
  })

  describe('updateUserProfile', () => {
    it('should return an updated user', async () => {
      const [ originalUser, anotherUser ] = userFactory.buildList(2);

      const updateUserInput: UpdateUserProfileInput = {
        id: originalUser.id,
        name: anotherUser.name,
        avatar: anotherUser.avatar,
        role: anotherUser.role,
        isActivated: anotherUser.isActivated,
        isSuspended: anotherUser.isSuspended
      }
      const expected = { ...originalUser, ...updateUserInput };

      jest.spyOn(service, 'updateUser').mockResolvedValueOnce(expected);

      const result = await resolver.updateUserProfile(updateUserInput);
      expect(result).toEqual(expected);
    })
  })
});
