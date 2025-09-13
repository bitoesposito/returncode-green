import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ApiResponseDto } from '../common.interface';

/**
 * Global Validation Exception Filter
 * 
 * Handles validation errors and other exceptions to ensure consistent
 * API response format across the application. Transforms validation
 * errors into standardized error responses with proper HTTP status codes.
 * 
 * Features:
 * - Handles ValidationPipe errors with detailed validation messages
 * - Converts HTTP exceptions to standardized API response format
 * - Provides detailed error information for debugging
 * - Maintains consistent error response structure
 * - Logs errors for monitoring and debugging
 * 
 * Response Format:
 * - success: false for all errors
 * - http_status_code: Appropriate HTTP status code
 * - message: Human-readable error message
 * - data: null for error responses
 * - validation_errors: Detailed validation errors (if applicable)
 */
@Catch()
export class ValidationExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ValidationExceptionFilter.name);

  /**
   * Catch and handle all exceptions
   * 
   * Processes all exceptions thrown by the application and converts
   * them to standardized API responses. Handles both validation errors
   * and general HTTP exceptions.
   * 
   * @param exception - The exception that was thrown
   * @param host - Execution context containing request and response
   */
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let validationErrors: any[] = [];

    // Handle different types of exceptions
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      
      // Skip logging for NotFoundException (404) - these are normal routing errors
      const isNotFoundError = status === HttpStatus.NOT_FOUND;
      
      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const responseObj = exceptionResponse as any;
        message = responseObj.message || responseObj.error || message;
        
        // Handle validation errors specifically
        if (responseObj.message && Array.isArray(responseObj.message)) {
          validationErrors = responseObj.message.map((msg: any) => ({
            property: msg.property || 'unknown',
            value: msg.value,
            constraints: msg.constraints || {},
            message: Object.values(msg.constraints || {}).join(', ')
          }));
          message = 'Validation failed';
        }
      }
      
      // For NotFoundException, just return the response without logging as validation error
      if (isNotFoundError) {
        const errorResponse: ApiResponseDto<null> = {
          success: false,
          http_status_code: status,
          message,
          data: null
        };
        response.status(status).json(errorResponse);
        return;
      }
    } else if (exception instanceof Error) {
      // Handle custom validation errors from ValidationPipe
      try {
        const errorData = JSON.parse(exception.message);
        if (errorData.http_status_code && errorData.validation_errors) {
          status = errorData.http_status_code;
          message = errorData.message;
          validationErrors = errorData.validation_errors;
        } else {
          message = exception.message;
        }
      } catch {
        // If it's not a JSON error, use the message as is
        message = exception.message;
      }
    }

    // Log the error for debugging (skip 404 errors as they are normal routing errors)
    if (status !== HttpStatus.NOT_FOUND) {
      this.logger.error('Exception caught by ValidationExceptionFilter', {
        exception: exception instanceof Error ? exception.message : 'Unknown exception',
        stack: exception instanceof Error ? exception.stack : undefined,
        url: request.url,
        method: request.method,
        status,
        validationErrors: validationErrors.length > 0 ? validationErrors : undefined
      });
    }

    // Create standardized error response
    const errorResponse: ApiResponseDto<null> = {
      success: false,
      http_status_code: status,
      message,
      data: null,
      ...(validationErrors.length > 0 && { validation_errors: validationErrors })
    };

    // Send error response
    response.status(status).json(errorResponse);
  }
}

