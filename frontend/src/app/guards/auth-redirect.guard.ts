import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { CookieAuthService } from '../services/cookie-auth.service';

export const authRedirectGuard: CanActivateFn = (route, state) => {
  const router = inject(Router);
  const authService = inject(CookieAuthService);

  if (!authService.isAuthenticated()) {
    return true;
  }

  // Se l'utente è autenticato, reindirizza alla dashboard
      router.navigate(['/private/dashboard']);
      return false;
}; 