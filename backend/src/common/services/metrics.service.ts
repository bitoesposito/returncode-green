import { Injectable, Logger } from '@nestjs/common';
import { AuditService, AuditEventType } from './audit.service';

/**
 * Interface for individual request metrics
 * 
 * Defines the structure of metrics collected for each HTTP request.
 * Used for tracking performance, errors, and user activity.
 */
export interface RequestMetric {
  /** Timestamp when the request was processed */
  timestamp: Date;
  /** HTTP method (GET, POST, PUT, DELETE, etc.) */
  method: string;
  /** Request path/endpoint */
  path: string;
  /** HTTP status code returned */
  statusCode: number;
  /** Response time in milliseconds */
  responseTime: number;
  /** User agent string from request headers */
  userAgent?: string;
  /** Client IP address */
  ipAddress?: string;
  /** User ID if authenticated */
  userId?: string;
  /** User email if authenticated */
  userEmail?: string;
}

/**
 * Interface for system-wide metrics
 * 
 * Defines aggregated metrics for system monitoring and performance analysis.
 * Provides insights into system health, usage patterns, and error rates.
 */
export interface SystemMetrics {
  /** Total number of requests in the time period */
  totalRequests: number;
  /** Number of successful requests (status < 400) */
  successfulRequests: number;
  /** Number of failed requests (status >= 400) */
  failedRequests: number;
  /** Average response time in milliseconds */
  averageResponseTime: number;
  /** Error rate as a percentage */
  errorRate: number;
  /** Requests per minute (calculated from last hour) */
  requestsPerMinute: number;
  /** Number of unique users in the time period */
  uniqueUsers: number;
  /** Top 10 most accessed endpoints */
  topEndpoints: Array<{path: string, count: number}>;
  /** Breakdown of errors by status code */
  errorBreakdown: Array<{statusCode: number, count: number}>;
}

/**
 * Interface for hourly metrics data
 * 
 * Defines metrics aggregated by hour for trend analysis.
 * Used for historical performance tracking and capacity planning.
 */
export interface HourlyMetrics {
  /** Hour timestamp in ISO format */
  hour: string;
  /** Number of requests in this hour */
  requests: number;
  /** Number of errors in this hour */
  errors: number;
  /** Average response time in milliseconds */
  avgResponseTime: number;
  /** Number of unique users in this hour */
  uniqueUsers: number;
}

/**
 * Metrics Service
 * 
 * Provides comprehensive metrics collection and analysis for the application.
 * Tracks request performance, system health, and user activity patterns.
 * 
 * Features:
 * - Real-time request metrics collection
 * - System performance monitoring
 * - Error rate tracking and alerting
 * - User activity analysis
 * - Historical metrics aggregation
 * - Automated alert generation
 * 
 * Metrics Collection:
 * - Request/response timing
 * - HTTP status codes and error tracking
 * - User identification and activity
 * - Endpoint usage patterns
 * - System load monitoring
 * 
 * Analysis Capabilities:
 * - 24-hour system metrics
 * - 7-day hourly trends
 * - Real-time alerts
 * - User activity patterns
 * - Performance bottleneck identification
 * 
 * Alert System:
 * - High error rate detection
 * - Performance degradation alerts
 * - System load monitoring
 * - Low activity notifications
 * 
 * Usage:
 * - Injected into interceptors for automatic metrics collection
 * - Provides dashboard data for system monitoring
 * - Enables proactive system maintenance
 * - Supports capacity planning and optimization
 * 
 * @example
 * // Record a request metric
 * this.metricsService.recordRequest({
 *   timestamp: new Date(),
 *   method: 'GET',
 *   path: '/api/users',
 *   statusCode: 200,
 *   responseTime: 150,
 *   userId: 'user123'
 * });
 * 
 * @example
 * // Get system metrics
 * const metrics = await this.metricsService.getSystemMetrics();
 * console.log(`Error rate: ${metrics.errorRate}%`);
 * 
 * @example
 * // Get real-time alerts
 * const alerts = await this.metricsService.getAlerts();
 * alerts.forEach(alert => console.log(alert.message));
 */
@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);
  private requestMetrics: RequestMetric[] = [];
  private readonly maxMetricsHistory = 10000; // Keep last 10k requests

  constructor(private readonly auditService: AuditService) {}

  // ============================================================================
  // METRICS COLLECTION
  // ============================================================================

  /**
   * Record a new request metric
   * 
   * Adds a request metric to the collection and maintains
   * the maximum history limit for memory management.
   * 
   * @param metric - Request metric data to record
   * 
   * @example
   * this.recordRequest({
   *   timestamp: new Date(),
   *   method: 'POST',
   *   path: '/api/auth/login',
   *   statusCode: 200,
   *   responseTime: 250,
   *   userId: 'user123',
   *   userEmail: 'user@example.com'
   * });
   */
  recordRequest(metric: RequestMetric): void {
    this.requestMetrics.push(metric);
    
    // Keep only the last maxMetricsHistory metrics
    if (this.requestMetrics.length > this.maxMetricsHistory) {
      this.requestMetrics = this.requestMetrics.slice(-this.maxMetricsHistory);
    }
  }

  // ============================================================================
  // METRICS ANALYSIS
  // ============================================================================

  /**
   * Get system metrics for the last 24 hours
   * 
   * Calculates comprehensive system metrics including performance,
   * error rates, and usage patterns for the last 24 hours.
   * 
   * @returns Promise with system metrics data
   * 
   * @example
   * const metrics = await this.getSystemMetrics();
   * console.log(`Total requests: ${metrics.totalRequests}`);
   * console.log(`Error rate: ${metrics.errorRate}%`);
   * console.log(`Avg response time: ${metrics.averageResponseTime}ms`);
   */
  async getSystemMetrics(): Promise<SystemMetrics> {
    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    // Filter metrics from last 24 hours
    const recentMetrics = this.requestMetrics.filter(
      metric => metric.timestamp >= twentyFourHoursAgo
    );

    if (recentMetrics.length === 0) {
      return this.getEmptyMetrics();
    }

    const totalRequests = recentMetrics.length;
    const successfulRequests = recentMetrics.filter(m => m.statusCode < 400).length;
    const failedRequests = recentMetrics.filter(m => m.statusCode >= 400).length;
    const averageResponseTime = recentMetrics.reduce((sum, m) => sum + m.responseTime, 0) / totalRequests;
    const errorRate = failedRequests / totalRequests;
    
    // Calculate requests per minute (last hour)
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const lastHourMetrics = recentMetrics.filter(m => m.timestamp >= oneHourAgo);
    const requestsPerMinute = lastHourMetrics.length / 60;

    // Get unique users
    const uniqueUsers = new Set(recentMetrics.map(m => m.userId).filter(Boolean)).size;

    // Get top endpoints
    const endpointCounts = new Map<string, number>();
    recentMetrics.forEach(m => {
      const key = `${m.method} ${m.path}`;
      endpointCounts.set(key, (endpointCounts.get(key) || 0) + 1);
    });
    const topEndpoints = Array.from(endpointCounts.entries())
      .map(([path, count]) => ({ path, count }))
      .filter(e => e.path !== 'GET /admin/metrics' && e.path !== 'GET /admin/metrics/detailed')
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Get error breakdown
    const errorCounts = new Map<number, number>();
    recentMetrics.filter(m => m.statusCode >= 400).forEach(m => {
      errorCounts.set(m.statusCode, (errorCounts.get(m.statusCode) || 0) + 1);
    });
    const errorBreakdown = Array.from(errorCounts.entries())
      .map(([statusCode, count]) => ({ statusCode, count }))
      .sort((a, b) => b.count - a.count);

    return {
      totalRequests,
      successfulRequests,
      failedRequests,
      averageResponseTime: Math.round(averageResponseTime * 100) / 100,
      errorRate: Math.round(errorRate * 10000) / 100, // Percentage with 2 decimal places
      requestsPerMinute: Math.round(requestsPerMinute * 100) / 100,
      uniqueUsers,
      topEndpoints,
      errorBreakdown
    };
  }

  /**
   * Get hourly metrics for the last 7 days
   * 
   * Provides hourly breakdown of metrics for trend analysis.
   * Useful for identifying patterns and capacity planning.
   * 
   * @returns Promise with array of hourly metrics
   * 
   * @example
   * const hourlyMetrics = await this.getHourlyMetrics();
   * hourlyMetrics.forEach(hour => {
   *   console.log(`${hour.hour}: ${hour.requests} requests, ${hour.errors} errors`);
   * });
   */
  async getHourlyMetrics(): Promise<HourlyMetrics[]> {
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    const recentMetrics = this.requestMetrics.filter(
      metric => metric.timestamp >= sevenDaysAgo
    );

    const hourlyData: Map<string, HourlyMetrics> = new Map();

    // Initialize hourly buckets for the last 7 days
    for (let i = 0; i < 7 * 24; i++) {
      const hour = new Date(now.getTime() - i * 60 * 60 * 1000);
      const hourKey = hour.toISOString().slice(0, 13) + ':00:00.000Z';
      
      hourlyData.set(hourKey, {
        hour: hourKey,
        requests: 0,
        errors: 0,
        avgResponseTime: 0,
        uniqueUsers: 0
      });
    }

    // Group metrics by hour
    recentMetrics.forEach(metric => {
      const hourKey = new Date(metric.timestamp.getTime() - metric.timestamp.getMinutes() * 60 * 1000 - metric.timestamp.getSeconds() * 1000 - metric.timestamp.getMilliseconds())
        .toISOString();
      
      const hourData = hourlyData.get(hourKey);
      if (hourData) {
        hourData.requests++;
        if (metric.statusCode >= 400) {
          hourData.errors++;
        }
        hourData.avgResponseTime = (hourData.avgResponseTime * (hourData.requests - 1) + metric.responseTime) / hourData.requests;
      }
    });

    // Calculate unique users per hour
    for (const [hourKey, hourData] of hourlyData) {
      const hourStart = new Date(hourKey);
      const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000);
      
      const hourMetrics = recentMetrics.filter(m => 
        m.timestamp >= hourStart && m.timestamp < hourEnd && m.userId
      );
      
      hourData.uniqueUsers = new Set(hourMetrics.map(m => m.userId)).size;
      hourData.avgResponseTime = Math.round(hourData.avgResponseTime * 100) / 100;
    }

    return Array.from(hourlyData.values())
      .sort((a, b) => new Date(a.hour).getTime() - new Date(b.hour).getTime());
  }

  // ============================================================================
  // ALERTING SYSTEM
  // ============================================================================

  /**
   * Get real-time alerts based on current metrics
   * 
   * Analyzes current system metrics and generates alerts for
   * potential issues or anomalies that require attention.
   * 
   * Alert Types:
   * - Error: Critical issues requiring immediate attention
   * - Warning: Issues that should be monitored
   * - Info: Informational alerts for awareness
   * 
   * @returns Promise with array of active alerts
   * 
   * @example
   * const alerts = await this.getAlerts();
   * alerts.forEach(alert => {
   *   if (alert.type === 'error') {
   *     // Send immediate notification
   *   }
   * });
   */
  async getAlerts(): Promise<Array<{id: string, type: 'error' | 'warning' | 'info', message: string, timestamp: string, resolved: boolean}>> {
    const metrics = await this.getSystemMetrics();
    const alerts: Array<{id: string, type: 'error' | 'warning' | 'info', message: string, timestamp: string, resolved: boolean}> = [];

    // High error rate alert
    if (metrics.errorRate > 5) {
      alerts.push({
        id: `alert_error_rate_${Date.now()}`,
        type: 'error',
        message: `High error rate detected: ${metrics.errorRate}%`,
        timestamp: new Date().toISOString(),
        resolved: false
      });
    } else if (metrics.errorRate > 2) {
      alerts.push({
        id: `alert_error_rate_${Date.now()}`,
        type: 'warning',
        message: `Elevated error rate: ${metrics.errorRate}%`,
        timestamp: new Date().toISOString(),
        resolved: false
      });
    }

    // High response time alert
    if (metrics.averageResponseTime > 2000) {
      alerts.push({
        id: `alert_response_time_${Date.now()}`,
        type: 'warning',
        message: `High average response time: ${metrics.averageResponseTime}ms`,
        timestamp: new Date().toISOString(),
        resolved: false
      });
    }

    // Low activity alert
    if (metrics.requestsPerMinute < 1) {
      alerts.push({
        id: `alert_low_activity_${Date.now()}`,
        type: 'info',
        message: 'Low system activity detected',
        timestamp: new Date().toISOString(),
        resolved: false
      });
    }

    // High load alert
    if (metrics.requestsPerMinute > 100) {
      alerts.push({
        id: `alert_high_load_${Date.now()}`,
        type: 'warning',
        message: `High system load: ${metrics.requestsPerMinute} requests/minute`,
        timestamp: new Date().toISOString(),
        resolved: false
      });
    }

    return alerts;
  }

  // ============================================================================
  // USER ACTIVITY ANALYSIS
  // ============================================================================

  /**
   * Get user activity metrics from audit logs
   * 
   * Analyzes user activity patterns using audit logs to provide
   * insights into user engagement and growth trends.
   * 
   * @returns Promise with user activity metrics
   * 
   * @example
   * const userMetrics = await this.getUserActivityMetrics();
   * console.log(`Active users: ${userMetrics.activeUsers}`);
   * console.log(`New users today: ${userMetrics.newUsersToday}`);
   */
  async getUserActivityMetrics(): Promise<{
    totalUsers: number;
    activeUsers: number;
    newUsersToday: number;
    userGrowth: Array<{date: string, count: number}>;
  }> {
    try {
      // Get all login events from audit logs
      const loginLogs = await this.auditService.getAuditLogsByType(AuditEventType.USER_LOGIN_SUCCESS, 10000);
      
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

      // Calculate active users (logged in last 24 hours)
      const activeUsers = new Set(
        loginLogs
          .filter(log => new Date(log.timestamp) >= yesterday)
          .map(log => log.user?.uuid)
          .filter(Boolean)
      ).size;

      // Calculate new users today (this would need to be enhanced with registration events)
      const newUsersToday = 0; // Placeholder - would need registration audit logs

      // Calculate user growth for last 7 days
      const userGrowth: Array<{date: string, count: number}> = [];
      for (let i = 6; i >= 0; i--) {
        const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
        const dayStart = new Date(date.getFullYear(), date.getMonth(), date.getDate());
        const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);

        const uniqueUsers = new Set(
          loginLogs
            .filter(log => {
              const logDate = new Date(log.timestamp);
              return logDate >= dayStart && logDate < dayEnd;
            })
            .map(log => log.user?.uuid)
            .filter(Boolean)
        ).size;

        userGrowth.push({
          date: dayStart.toISOString().split('T')[0],
          count: uniqueUsers
        });
      }

      return {
        totalUsers: 0, // Would need to get from user repository
        activeUsers,
        newUsersToday,
        userGrowth
      };
    } catch (error) {
      this.logger.error('Failed to get user activity metrics', { error: error.message });
      return {
        totalUsers: 0,
        activeUsers: 0,
        newUsersToday: 0,
        userGrowth: []
      };
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Get empty metrics structure
   * 
   * Returns a default metrics object when no data is available.
   * Used to provide consistent response structure.
   * 
   * @returns Empty system metrics object
   */
  private getEmptyMetrics(): SystemMetrics {
    return {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      errorRate: 0,
      requestsPerMinute: 0,
      uniqueUsers: 0,
      topEndpoints: [],
      errorBreakdown: []
    };
  }
} 