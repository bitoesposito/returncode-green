import { 
  Injectable, 
  NestInterceptor, 
  ExecutionContext, 
  CallHandler 
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';

// Local imports
import { MetricsService, RequestMetric } from '../services/metrics.service';

/**
 * Metrics Interceptor
 * 
 * Automatically collects and records request metrics for all HTTP requests.
 * Provides comprehensive monitoring and analytics data for the application.
 * 
 * Features:
 * - Request timing measurement
 * - User identification and tracking
 * - IP address extraction
 * - User agent tracking
 * - Response status monitoring
 * - Automatic metrics recording
 * 
 * Metrics Collected:
 * - Request timestamp
 * - HTTP method and path
 * - Response status code
 * - Response time (milliseconds)
 * - User agent string
 * - Client IP address
 * - User ID and email (if authenticated)
 * 
 * Usage:
 * - Applied globally for automatic metrics collection
 * - Used by MetricsService for analytics and monitoring
 * - Provides data for performance analysis and debugging
 * 
 * Security:
 * - Handles various proxy configurations for IP extraction
 * - Safely extracts user information from authenticated requests
 * - Non-blocking metrics collection
 */
@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  constructor(private readonly metricsService: MetricsService) {}

  /**
   * Intercepts HTTP requests to collect metrics
   * 
   * Automatically records request metrics for every HTTP request.
   * Measures response time and collects comprehensive request data.
   * 
   * Process:
   * 1. Records request start time
   * 2. Extracts request information
   * 3. Processes the request
   * 4. Records response time and metrics
   * 5. Sends metrics to MetricsService
   * 
   * @param context - Execution context containing request and response
   * @param next - Call handler for processing the request
   * @returns Observable with request processing and metrics recording
   * 
   * @example
   * // Applied globally in main.ts
   * app.useGlobalInterceptors(new MetricsInterceptor(metricsService));
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const startTime = Date.now();

    // Extract user information from authenticated request
    const user = (request as any).user;
    const userId = user?.uuid;
    const userEmail = user?.email;

    return next.handle().pipe(
      tap(() => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        // Prepare comprehensive request metric
        const metric: RequestMetric = {
          timestamp: new Date(),
          method: request.method,
          path: request.route?.path || request.path,
          statusCode: response.statusCode,
          responseTime,
          userAgent: request.get('User-Agent'),
          ipAddress: this.getClientIp(request),
          userId,
          userEmail
        };

        // Record metric for analytics and monitoring
        this.metricsService.recordRequest(metric);
      })
    );
  }

  /**
   * Extract client IP address from request
   * 
   * Handles various proxy configurations and headers to determine
   * the actual client IP address for accurate metrics collection.
   * 
   * Priority order:
   * 1. X-Forwarded-For header (first IP in list)
   * 2. X-Real-IP header
   * 3. Connection remote address
   * 4. Socket remote address
   * 
   * @param request - Express request object
   * @returns Client IP address or 'unknown' if not available
   * 
   * @example
   * // Behind a proxy
   * X-Forwarded-For: 192.168.1.1, 10.0.0.1
   * Returns: "192.168.1.1"
   */
  private getClientIp(request: Request): string {
    // Get IP from various headers and sources
    const forwardedFor = request.headers['x-forwarded-for'] as string;
    const realIp = request.headers['x-real-ip'] as string;
    const remoteAddr = request.connection.remoteAddress || request.socket.remoteAddress;
    
    // If we have X-Forwarded-For, take the first IP (original client)
    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      return ips[0];
    }
    
    // If we have X-Real-IP, use it
    if (realIp) {
      return realIp;
    }
    
    // If we have remote address, clean it up
    if (remoteAddr) {
      // Remove IPv6 prefix if present (::ffff:)
      return remoteAddr.replace(/^::ffff:/, '');
    }
    
    return 'unknown';
  }
} 