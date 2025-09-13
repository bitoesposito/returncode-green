import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { LoggerService } from './common/services/logger.service';
import { MetricsInterceptor } from './common/interceptors/metrics.interceptor';
import { CookieAuthInterceptor } from './auth/interceptors/cookie-auth.interceptor';
import * as cookieParser from 'cookie-parser';
import * as fs from 'fs';
import * as path from 'path';
import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ValidationExceptionFilter } from './common/filters/validation-exception.filter';

// Tutti i redirect e override di console.log, console.warn, console.error e i relativi commenti/documentazione di debug sono stati rimossi da questo file.

async function bootstrap() {
  const logger = new Logger('AppLogger');
  
  try {
  
    const app = await NestFactory.create(AppModule, {
      logger: ['error', 'warn', 'log', 'debug', 'verbose'],
    });
    
    // Enable cookie parser
    app.use(cookieParser());
    
    // Get FE_URL from config
    const configService = app.get(ConfigService);
    const feUrl = configService.get<string>('FE_URL') || 'http://localhost:4200';


    // Enable CORS with cookie support and allowed origin
    app.enableCors({
      origin: feUrl,
      credentials: true,
    });
    
    // Trust proxy for correct IP detection behind reverse proxy/Docker
    app.getHttpAdapter().getInstance().set('trust proxy', true);
    
    // Apply global validation pipe for DTO validation
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true, // Remove properties that don't have decorators
      forbidNonWhitelisted: true, // Throw error if non-whitelisted properties are present
      transform: true, // Automatically transform payloads to DTO instances
      transformOptions: {
        enableImplicitConversion: true, // Convert types automatically
      },
      exceptionFactory: (errors) => {
        // Custom error response format
        const result = errors.map((error) => ({
          property: error.property,
          value: error.value,
          constraints: error.constraints,
        }));
        return new Error(JSON.stringify({
          success: false,
          http_status_code: 400,
          message: 'Validation failed',
          data: null,
          validation_errors: result
        }));
      },
    }));
    
    // Apply global exception filter
    app.useGlobalFilters(new ValidationExceptionFilter());
    
    // Apply global interceptors
    const metricsInterceptor = app.get(MetricsInterceptor);
    // const cookieAuthInterceptor = app.get(CookieAuthInterceptor);
    app.useGlobalInterceptors(metricsInterceptor);
    
    // Set global prefix in case of SSL configuration with nginx
    // app.setGlobalPrefix('backend');
    
    const port = process.env.PORT ?? 3000;
    await app.listen(port);
    logger.log(`Application started on port ${port}`, 'Bootstrap');
  } catch (error) {
    logger.error('Failed to start application:', 'Bootstrap', { error: error.message, stack: error.stack });
    process.exit(1);
  }
}
bootstrap();
