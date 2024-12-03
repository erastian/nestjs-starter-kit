import {
  Resolver,
  Query,
  Mutation,
  Args,
  Context,
  Parent,
  ResolveField,
} from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { Auth } from './entities/auth.entity';
import { Token } from './entities/token.entity';
import { RegisterInput } from './dto/register.input';
import { LoginInput } from './dto/login.input';
import express from 'express';
import { ConfigService } from '@nestjs/config';
import ms from 'ms';
import { UnauthorizedException, UseGuards } from '@nestjs/common';
import { User } from '../users/entities/user.entity';
import { SocialAuthInput } from './dto/social.input';
import { ChangePwdInput } from './dto/change-pwd.input';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { ResetPwdInput } from './dto/reset-pwd.input';
import { ServerResponseEntity } from '../common/entities/server-response.entity';
import { ActivateInput } from './dto/activate.input';
import { UsersService } from '../users/users.service';
import { UserEntity } from '../common/decorators/user.decorator';

@Resolver(() => Auth)
export class AuthResolver {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
  }

  @Mutation(() => Auth)
  async register(
    @Args('data') data: RegisterInput,
    @Context('req') req: express.Request,
  ) {
    data.email = data.email.toLowerCase();
    const { user, tokens } = await this.authService.createUser(data);

    req.res?.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      maxAge: ms(this.configService.get('security.jwtRefreshExpiresIn')),
    });

    delete user.password;

    return {
      user,
      accessToken: tokens.accessToken,
    };
  }

  @Query(() => Auth)
  async login(
    @Args('data') data: LoginInput,
    @Context('req') req: express.Request,
  ) {
    data.email = data.email.toLowerCase();
    const { user, tokens } = await this.authService.login(data);

    req.res?.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      maxAge: ms(this.configService.get('security.jwtRefreshExpiresIn')),
    });

    delete user.password;

    return {
      user,
      accessToken: tokens.accessToken,
    };
  }

  @Query(() => Auth)
  async googleAuth(@Args('data') data: SocialAuthInput, @Context('req') req: express.Request) {
    const { user, tokens } = await this.authService.googleAuth(data);

    req.res?.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      maxAge: ms(this.configService.get('security.jwtRefreshExpiresIn')),
    });

    delete user.password;

    return {
      user,
      accessToken: tokens.accessToken,
    };
  }

  @Query(() => String)
  async getGoogleAuthUrl() {
    return this.authService.getGoogleAuthUrl();
  }

  @Query(() => ServerResponseEntity)
  async logout(@Context('req') req: express.Request) {
    req.res?.clearCookie('refreshToken');
    return {
      status: true,
      message: 'Logout successful. Thank you for using our service! =)'
    };
  }

  @Query(() => ServerResponseEntity)
  async forgotPassword(@Args('email') email: string) {
    return {
      status: await this.authService.forgotPassword(email.toLowerCase()),
      message: `Restoration email for user ${ email.toLowerCase() } was sent.`,
    };
  }

  @Mutation(() => String)
  async resetPassword(@Args('data') data: ResetPwdInput) {
    return await this.authService.resetPassword(data)
  }

  @Mutation(() => String)
  async activateProfile(@Args('data') data: ActivateInput) {
    return await this.authService.activateUser(data);
  }

  @Mutation(() => Boolean)
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @UserEntity() user: User,
    @Args('data') data: ChangePwdInput
  ) {
    return this.authService.changePassword(user.id, data.password, data.newPassword);
  }

  @Query(() => Token)
  async refresh(
    @Context('req') req: express.Request,
  ): Promise<{ accessToken: string }> {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
      throw new UnauthorizedException('Access denied.');
    }
    const userFromToken =
      await this.authService.validateRefreshToken(refreshToken);

    if (!userFromToken) {
      throw new UnauthorizedException('Access denied.');
    }

    const user = await this.usersService.findOneById(userFromToken.id)

    if (!user || user.isSuspended) {
      throw new UnauthorizedException('Access denied.');
    }

    const tokens = await this.authService.generateTokens({
      id: userFromToken.id,
      email: userFromToken.email,
      role: userFromToken.role,
    });

    req.res?.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      maxAge: ms(this.configService.get('security.jwtRefreshExpiresIn')),
    });
    return {
      accessToken: tokens.accessToken,
    };
  }

  @ResolveField('user', () => User)
  async user(@Parent() auth: Auth) {
    return await this.authService.getUserFromToken(auth.accessToken);
  }
}
