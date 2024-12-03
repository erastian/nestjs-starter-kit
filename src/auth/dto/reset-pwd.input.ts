import { Field, InputType } from '@nestjs/graphql';
import { IsJWT, IsNotEmpty, MinLength } from 'class-validator';

@InputType()
export class ResetPwdInput {
  @Field()
  @IsJWT({ message: 'Error! Invalid token.' })
  @IsNotEmpty()
  resetToken: string;

  @Field()
  @IsNotEmpty()
  @MinLength(8)
  newPassword: string;
}