import { Field, ObjectType } from '@nestjs/graphql';
import { GraphQLJWT } from 'graphql-scalars';

@ObjectType()
export class Token {
  @Field(() => GraphQLJWT, { description: 'JWT Access token' })
  accessToken: string;
}