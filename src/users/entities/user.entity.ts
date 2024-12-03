import { ObjectType, Field, registerEnumType, HideField, ID } from '@nestjs/graphql';
import { IsEmail, IsOptional, IsUUID } from 'class-validator';
import { Role } from '@prisma/client';


registerEnumType(Role, {
  name: 'Role',
  description: 'User role'
})

@ObjectType()
export class User {
  @Field(() => ID)
  @IsUUID(4)
  id: string;

  @Field()
  @IsEmail()
  email: string;

  @HideField()
  password: string;

  @Field({ nullable: true })
  @IsOptional()
  name?: string;

  @Field(() => Role)
  role: Role;

  @Field({ nullable: true })
  googleId?: string | null;

  @Field({ nullable: true })
  avatar?: string | null;

  @Field(() => Boolean, { defaultValue: false })
  isActivated: boolean;

  @Field(() => Boolean, { defaultValue: false })
  isSuspended: boolean;

  @Field({description: 'Identifies the date and time when the object was created.'})
  createdAt: Date;

  @Field({description: 'Identifies the date and time when the object was last updated.'})
  updatedAt: Date;
}
