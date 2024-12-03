import { Field, InputType } from '@nestjs/graphql';
import { IsEnum, IsOptional, IsUUID } from 'class-validator';
import Role from '../../common/enums/roles.enum';

@InputType()
export class UpdateUserProfileInput {
  @Field()
  @IsUUID(4, { message: 'Error! Invalid id.' })
  id: string;

  @Field({ nullable: true, description: 'This is username field' })
  name?: string;

  @Field({ nullable: true })
  avatar?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsEnum(Role, { message: 'Error! Invalid role.' })
  role?: Role;

  @Field({ nullable: true })
  isActivated?: boolean;

  @Field({ nullable: true })
  isSuspended?: boolean;
}