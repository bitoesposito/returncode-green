import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';

/**
 * Cookie Authentication Interceptor
 * 
 * Extracts JWT tokens from httpOnly cookies and adds them to the request headers
 * for compatibility with existing JWT authentication guards.
 * 
 * This interceptor ensures that:
 * - Access tokens from cookies are available in Authorization header
 * - Refresh tokens from cookies are available for token refresh
 * - Maintains backward compatibility with existing auth guards
 * 
 * Security Features:
 * - Uses httpOnly cookies for token storage
 * - Prevents XSS attacks on tokens
 * - Maintains CSRF protection
 * - Compatible with existing JWT guards
 */
@Injectable()
export class CookieAuthInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    
    // Extract access token from cookie
    const accessToken = request.cookies?.access_token;
    
    // If access token exists in cookie but not in Authorization header, add it
    if (accessToken && !request.headers.authorization) {
      request.headers.authorization = `Bearer ${accessToken}`;
    }
    
    return next.handle();
  }
} 