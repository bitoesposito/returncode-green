import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { CookieAuthService } from '../services/cookie-auth.service';
import { map, catchError, of } from 'rxjs';

export const roleGuard: CanActivateFn = (route, state) => {
  const router = inject(Router);
  const authService = inject(CookieAuthService);
  
  // Check if user is authenticated using cookie-based auth
  if (!authService.isAuthenticated()) {
    router.navigate(['/login']);
    return false;
  }

  // Get required roles from route data
  const requiredRoles = route.data['roles'] as string[];
  if (!requiredRoles || requiredRoles.length === 0) {
    return true; // No roles required
  }

  // For cookie-based auth, we need to get fresh user data from the server
  // This ensures we always have the latest user data and role information
  return authService.handleUserSwitch().pipe(
    map(response => {
      if (response.success && response.data?.user?.role) {
        const userRole = response.data.user.role;
        if (requiredRoles.includes(userRole)) {
          return true;
        } else {
          // User doesn't have required role, redirect to dashboard
          router.navigate(['/']);
          return false;
        }
      } else {
        // No user data or role, redirect to login
        authService.clearAllAuthData();
        router.navigate(['/login']);
        return false;
      }
    }),
    catchError((error) => {
      // Authentication error, clear data and redirect to login
      authService.clearAllAuthData();
      router.navigate(['/login']);
      return of(false);
    })
  );
}; 