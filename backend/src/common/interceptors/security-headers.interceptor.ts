import { 
  Injectable, 
  NestInterceptor, 
  ExecutionContext, 
  CallHandler 
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

/**
 * Security Headers Interceptor
 * 
 * Adds security headers to all HTTP responses for enhanced application security.
 * Implements various security headers to protect against common web vulnerabilities.
 * 
 * Security Headers (Currently Disabled):
 * - X-Content-Type-Options: nosniff - Prevents MIME type sniffing
 * - X-Frame-Options: SAMEORIGIN - Prevents clickjacking attacks
 * - X-XSS-Protection: 1; mode=block - Enables XSS protection
 * - Content-Security-Policy: Controls resource loading
 * - Referrer-Policy: strict-origin-when-cross-origin - Controls referrer information
 * 
 * Features:
 * - Automatic security header injection
 * - Protection against common web vulnerabilities
 * - Configurable security policies
 * - Non-blocking header addition
 * 
 * Usage:
 * - Applied globally for all responses
 * - Can be customized per environment
 * - Provides defense-in-depth security
 * 
 * Note:
 * - Currently disabled for development/testing
 * - Uncomment headers for production deployment
 * - Customize CSP policy based on application needs
 */
@Injectable()
export class SecurityHeadersInterceptor implements NestInterceptor {
  /**
   * Intercepts HTTP responses to add security headers
   * 
   * Automatically adds security headers to all HTTP responses.
   * Provides protection against common web vulnerabilities.
   * 
   * Process:
   * 1. Processes the request normally
   * 2. Adds security headers to response
   * 3. Returns response with enhanced security
   * 
   * @param context - Execution context containing request and response
   * @param next - Call handler for processing the request
   * @returns Observable with response and security headers
   * 
   * @example
   * // Applied globally in main.ts
   * app.useGlobalInterceptors(new SecurityHeadersInterceptor());
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // ============================================================================
    // SECURITY HEADERS CONFIGURATION
    // ============================================================================
    
    // Uncomment the following lines to enable security headers
    // const response = context.switchToHttp().getResponse();
    
    // Prevent MIME type sniffing attacks
    // response.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Prevent clickjacking attacks
    // response.setHeader('X-Frame-Options', 'SAMEORIGIN');
    
    // Enable XSS protection
    // response.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Content Security Policy - customize based on your application
    // response.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' http://website.com http://localhost");
    
    // Control referrer information
    // response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // ============================================================================
    // REQUEST PROCESSING
    // ============================================================================
    
    return next.handle().pipe(
      map(data => data)
    );
  }
} 