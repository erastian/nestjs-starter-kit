import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { PrismaService } from 'nestjs-prisma';
import { ConfigService } from '@nestjs/config';
import { authUserInputFactory, userFactory } from '../../test/factories/user.factory';
import { NotFoundException } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';

const prismaMock = {
  user: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  }
}

describe('UsersService', () => {
  let service: UsersService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ UsersService, ConfigService, { provide: PrismaService, useValue: prismaMock } ],
    }).compile();

    service = module.get(UsersService);

    prismaMock.user.findUnique.mockClear();
    prismaMock.user.findMany.mockClear();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findOneByEmail', () => {
    it('should return a user by email', async () => {
      const expected = userFactory.build();
      prismaMock.user.findUnique.mockResolvedValueOnce(expected);

      const result = await service.findOneByEmail(expected.email);
      expect(result).toEqual(expected);
      expect(prismaMock.user.findUnique).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { email: expected.email } });
    });

    it('should return null if user not found', async () => {
      prismaMock.user.findUnique.mockResolvedValueOnce(null);

      await expect(service.findOneByEmail('nonexistent@email.some')).resolves.toBeNull();
      expect(prismaMock.user.findUnique).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { email: 'nonexistent@email.some' } });
    });
  });

  describe('findOneById', () => {
    it('should return a user by id', async () => {
      const expected = userFactory.build();
      prismaMock.user.findUnique.mockResolvedValueOnce(expected);

      const result = await service.findOneById(expected.id);
      expect(result).toEqual(expected);
      expect(prismaMock.user.findUnique).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { id: expected.id } });
    });

    it('should return null if user not found', async () => {
      prismaMock.user.findUnique.mockResolvedValueOnce(null);

      await expect(service.findOneById('nonexistent-id')).resolves.toBeNull();
      expect(prismaMock.user.findUnique).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { id: 'nonexistent-id' } });
    })
  });

  describe('findOneByGoogleId', () => {
    it('should return a user by google id', async () => {
      const expected = userFactory.build({ googleId: 'some-existent-id' });
      prismaMock.user.findUnique.mockResolvedValueOnce(expected);

      const result = await service.findOneByGoogleId(expected.id);
      expect(result).toEqual(expected);
      expect(prismaMock.user.findUnique).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { googleId: expected.id } });
    });

    it('should return null if google user not found', async () => {
      prismaMock.user.findUnique.mockResolvedValueOnce(null);

      await expect(service.findOneByGoogleId('nonexistent-id')).resolves.toBeNull();
      expect(prismaMock.user.findUnique).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { googleId: 'nonexistent-id' } });
    })
  });

  describe('findAllUsers', () => {
    it('should return an array of users', async () => {
      const expected = userFactory.buildList(3);
      prismaMock.user.findMany.mockResolvedValueOnce(expected);

      const result = await service.findAllUsers();
      expect(result).toEqual(expected);
      expect(prismaMock.user.findMany).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findMany).toHaveBeenCalledWith({});
    });

    it('should return an empty array if no users found', async () => {
      prismaMock.user.findMany.mockResolvedValueOnce([]);

      const result = await service.findAllUsers();
      expect(result).toEqual([]);
      expect(prismaMock.user.findMany).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.findMany).toHaveBeenCalledWith({});
    })
  })

  describe('createUser', () => {
    beforeEach(() => {
      prismaMock.user.create.mockClear();
    });

    it('should create a new user by email & password', async () => {
      const userRegisterInput = authUserInputFactory.build();
      const expectedUser = userFactory.build(userRegisterInput);

      prismaMock.user.create.mockResolvedValueOnce(expectedUser);

      const result = await service.createUser(userRegisterInput);
      expect(result).toEqual(expectedUser);
      expect(prismaMock.user.create).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.create).toHaveBeenCalledWith({ data: userRegisterInput });
    })

    it('should create a new user by google id', async () => {
      const userRegisterInput = authUserInputFactory.build();
      const expectedUser = userFactory.build({ ...userRegisterInput, googleId: 'some-google-id', isActivated: true });

      prismaMock.user.create.mockResolvedValueOnce(expectedUser);

      const result = await service.createUser(userRegisterInput);
      expect(result).toEqual(expectedUser);
      expect(result.isActivated).toBe(true);
      expect(prismaMock.user.create).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.create).toHaveBeenCalledWith({ data: userRegisterInput });
    })
  })

  describe('updateUser', () => {
    it('should update a user', async () => {
      const [ originalUser, anotherUser ] = userFactory.buildList(2);
      const updateUserInput: UpdateUserDto = {
        name: anotherUser.name,
        avatar: anotherUser.avatar,
        role: anotherUser.role,
        isActivated: anotherUser.isActivated,
        isSuspended: anotherUser.isSuspended
      }
      const expectedUser = { ...originalUser, ...updateUserInput };

      jest.spyOn(service, 'findOneById').mockResolvedValueOnce(originalUser);

      prismaMock.user.update.mockResolvedValueOnce(expectedUser);

      const result = await service.updateUser(originalUser.id, updateUserInput);
      expect(result).toEqual(expectedUser);
      expect(prismaMock.user.update).toHaveBeenCalledTimes(1);
      expect(prismaMock.user.update).toHaveBeenCalledWith({ where: { id: originalUser.id }, data: updateUserInput });
    })

    it('should return exception if user not found', async () => {
      const [ originalUser, anotherUser ] = userFactory.buildList(2);
      const updateUserInput: UpdateUserDto = {
        name: anotherUser.name,
      }
      prismaMock.user.findUnique.mockResolvedValueOnce(null);

      await expect(service.updateUser(originalUser.id, updateUserInput)).resolves.toThrow(NotFoundException);
    })
  })
});
