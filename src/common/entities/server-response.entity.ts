import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class ServerResponseEntity {
  @Field()
  status: Boolean;

  @Field()
  message: String;
}