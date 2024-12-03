import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { UseGuards } from '@nestjs/common';
import { UserEntity } from '../common/decorators/user.decorator';
import { RolesGuard } from '../common/guards/roles.guard';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { Roles } from '../common/decorators/roles.decorator';
import Role from '../common/enums/roles.enum';
import { UpdateProfileInput } from './dto/update-profile.input';
import { UpdateUserProfileInput } from './dto/update-user-profile.input';

@Resolver(() => User)
export class UsersResolver {
  constructor(private readonly usersService: UsersService) {}

  @Query(() => User, { name: 'user' })
  @UseGuards(JwtAuthGuard)
  async getProfile(@UserEntity() user: User): Promise<User> {
    return this.usersService.findOneById(user.id);
  }

  @Query(() => [ User ], { name: 'users' })
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async getAllUsers(): Promise<User[]> {
    return this.usersService.findAllUsers();
  }

  @Query(() => User)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async getUser(@Args('id') id: string): Promise<User> {
    return this.usersService.findOneById(id);
  }

  @Mutation(() => User)
  @UseGuards(JwtAuthGuard)
  async updateProfile(
    @UserEntity() user: User,
    @Args('data') data: UpdateProfileInput
  ): Promise<User | Error> {
    return this.usersService.updateUser(user.id as string, data);
  }

  @Mutation(() => User)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async updateUserProfile(
    @Args('data') data: UpdateUserProfileInput
  ): Promise<User | Error> {
    return this.usersService.updateUser(data.id, data);
  }
}
