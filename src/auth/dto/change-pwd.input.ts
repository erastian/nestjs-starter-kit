import { Field, InputType } from '@nestjs/graphql';
import { IsNotEmpty, MinLength } from 'class-validator';

@InputType()
export class ChangePwdInput {
    @Field()
    @IsNotEmpty()
    @MinLength(8)
    password: string;

    @Field()
    @IsNotEmpty()
    @MinLength(8)
    newPassword: string;
}