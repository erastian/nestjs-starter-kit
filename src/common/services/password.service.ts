import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecurityConfig } from '../configs/config.interface';
import { hash, compare } from 'bcrypt';

@Injectable()
export class PasswordService {
  get bcryptSaltRound(): string | number {
    const securityConfig = this.configService.get<SecurityConfig>('security');
    const saltOrRounds = securityConfig.saltOrRounds;

    return +saltOrRounds;
  }

  constructor(private configService: ConfigService) {}

  validatePassword(password: string, hash: string): Promise<boolean> {
    return compare(password, hash);
  }

  hashPassword(password: string): Promise<string> {
    return hash(password, this.bcryptSaltRound);
  }
}
