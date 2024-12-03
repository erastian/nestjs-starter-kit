import { Field, ID, ObjectType } from '@nestjs/graphql';

@ObjectType({ isAbstract: true })
export abstract class BaseEntity {
  @Field(() => ID)
  id: string | number;

  @Field({description: 'Identifies the date and time when the object was created.'})
  createdAt: Date;

  @Field({description: 'Identifies the date and time when the object was last updated.'})
  updatedAt: Date;
}