import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class UpdateProfileInput {
  @Field({ nullable: true })
  name?: string;

  @Field({ nullable: true })
  avatar?: string;
}