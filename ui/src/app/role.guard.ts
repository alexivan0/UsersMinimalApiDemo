
import { inject } from '@angular/core';
import { CanActivateFn, Router, ActivatedRouteSnapshot } from '@angular/router';
import { AuthService } from './auth.service';

export const roleGuard: CanActivateFn = (route: ActivatedRouteSnapshot) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const roles = route.data['roles'] as string[];
  if (!roles || roles.includes(auth.role || '')) return true;
  router.navigate(['/home']);
  return false;
};
