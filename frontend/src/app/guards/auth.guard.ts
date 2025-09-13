import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { CookieAuthService } from '../services/cookie-auth.service';
import { map, catchError, of } from 'rxjs';

export const authGuard: CanActivateFn = () => {
  const router = inject(Router);
  const authService = inject(CookieAuthService);

  // First check local sessionStorage for immediate response
  const localAuth = authService.isAuthenticated();

  if (localAuth) {
    // Even if we have local auth, verify with server to ensure data is fresh
    return authService.handleUserSwitch().pipe(
      map(response => {
        if (response.success && response.data?.user) {
          authService.setAuthStatus('authenticated');
          return true;
        } else {
          authService.clearAllAuthData();
          router.navigate(['/login']);
          return false;
        }
      }),
      catchError(error => {
        console.error('Auth check failed:', error);
        authService.clearAllAuthData();
        router.navigate(['/login']);
        return of(false);
      })
    );
  }

  // If no local auth, check with server
  return authService.checkAuthStatus().pipe(
    map(response => {
      if (response.success && response.data?.authenticated) {
        authService.setAuthStatus('authenticated');
        return true;
      } else {
        router.navigate(['/login']);
        return false;
      }
    }),
    catchError(error => {
      console.error('Auth check failed:', error);
      router.navigate(['/login']);
      return of(false);
    })
  );
}; 