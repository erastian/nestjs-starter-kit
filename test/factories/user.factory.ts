import * as Factory from 'factory.ts';
import { faker } from '@faker-js/faker';
import Role from '../../src/common/enums/roles.enum';

interface Base {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}

interface IUser extends Base {
  name: string;
  googleId: string | null;
  avatar: string;
  role: Role;
  isActivated: boolean;
  isSuspended: boolean;
}

interface IAuth {
  email: string;
  password: string;
}


export const authUserInputFactory = Factory.Sync.makeFactory<IAuth>({
  email: Factory.each(() => faker.internet.email()),
  password: Factory.each(() => faker.internet.password()),
})


export const userFactory = Factory.Sync.makeFactory<IUser>({
  id: Factory.each(() => faker.string.uuid()),
  name: Factory.each(() => faker.internet.username()),
  googleId: undefined,
  avatar: Factory.each(() => faker.image.avatar()),
  role: Factory.each(() => faker.helpers.enumValue(Role)),
  isActivated: Factory.each(() => faker.datatype.boolean()),
  isSuspended: Factory.each(() => faker.datatype.boolean()),
  createdAt: Factory.each(() => faker.date.past()),
  updatedAt: Factory.each(() => faker.date.recent()),
}).combine(authUserInputFactory)