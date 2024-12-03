import { Injectable, NotFoundException } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'nestjs-prisma';
import { UpdateUserDto } from './dto/update-user.dto';
import { RegisterDto } from '../auth/dto/register.dto';


@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async findOneByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { email } });
  }

  async findOneById(id: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { id } });
  }

  async findOneByGoogleId(id: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { googleId: id } });
  }

  async findAllUsers(): Promise<User[]> {
    return this.prisma.user.findMany({});
  }

  async createUser(payload: RegisterDto): Promise<User> {
    if (payload.googleId) {
      return this.prisma.user.create({
        data: {
          ...payload,
          isActivated: true,
        },
      });
    }
    return this.prisma.user.create({
      data: {
        ...payload,
      },
    });
  }

  async updateUser(id: string, payload: UpdateUserDto): Promise<User | Error> {
    const user = await this.findOneById(id);
    if (!user) {
      return new NotFoundException('User not found.')
    }
    return this.prisma.user.update({
      where: { id },
      data: payload,
    });
  }
}
