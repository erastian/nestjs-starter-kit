import Role from '../../common/enums/roles.enum';

export interface UpdateUserDto {
  name?: string;
  password?: string;
  avatar?: string;
  googleId?: string | null;
  role?: Role;
  isActivated?: boolean;
  isSuspended?: boolean;
}
