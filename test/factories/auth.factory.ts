import * as Factory from 'factory.ts';
import { faker } from '@faker-js/faker';
import { JwtService } from '@nestjs/jwt';
import { User } from '../../src/users/entities/user.entity';
import * as process from 'node:process';

interface Tokens {
  accessToken: string;
  refreshToken: string;
}

const jwtService = new JwtService({
  secretOrPrivateKey: 'jwt',
  signOptions: {
    expiresIn: '60m',
  },
});

export function tokenFactory(user: Partial<User>) {
  return jwtService.sign({
    id: user.id,
    email: user.email,
    role: user.role,
  });
}

export function AuthHeaderFactory(user: Partial<User>) {
  return `Bearer ${ tokenFactory(user) }`;
}

export const authTokensFactory = Factory.Sync.makeFactory<Tokens>({
  accessToken: Factory.each(() => faker.internet.jwt()),
  refreshToken: Factory.each(() => faker.internet.jwt()),
});

export const resetTokenFactory = (user: Partial<User>) => Factory.Sync.makeFactory<{ resetToken: string }>({
  resetToken: Factory.each(() => jwtService.sign({
    email: user.email,
  }, {
    secret: 'some-secret',
    expiresIn: process.env.JWT_RESET_EXPIRATION || '2h',
  })),
});

export const googleUserFactory = Factory.Sync.makeFactory({
  sub: Factory.each(() => faker.string.numeric({ length: 21, allowLeadingZeros: false })),
  name: Factory.each(() => faker.person.fullName()),
  given_name: Factory.each(() => faker.person.firstName()),
  family_name: Factory.each(() => faker.person.lastName()),
  picture: Factory.each(() => faker.image.avatar()),
  email: Factory.each(() => faker.internet.email()),
  email_verified: true,
});