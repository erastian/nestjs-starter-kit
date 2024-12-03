import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import Role from '../enums/roles.enum';
import { GqlExecutionContext } from '@nestjs/graphql';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) {}
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if(!requiredRoles) {
            return true;
        }

        const ctx = GqlExecutionContext.create(context);
        const user = ctx.getContext().req.user;

        return requiredRoles.some((role) => user.role?.includes(role))
    }
}

