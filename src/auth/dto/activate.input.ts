import { Field, InputType } from '@nestjs/graphql';
import { IsJWT, IsNotEmpty } from 'class-validator';

@InputType()
export class ActivateInput {
  @Field()
  @IsJWT({ message: 'Error! Invalid token.' })
  @IsNotEmpty()
  activationToken: string;
}