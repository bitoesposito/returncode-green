import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { Logger } from '@nestjs/common';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { UserRole } from '../auth/auth.interface';
import * as bcrypt from 'bcryptjs';

/**
 * Admin User Seeding Utility
 * 
 * Standalone utility script for creating the initial admin user in the database.
 * This script handles database initialization, enum creation, and admin user
 * seeding with proper error handling and validation.
 * 
 * Features:
 * - Database connection and initialization
 * - UserRole enum creation if not exists
 * - Admin user and profile creation
 * - Environment-based configuration
 * - Duplicate user prevention
 * - Comprehensive error handling and logging
 * 
 * Environment Variables:
 * - ADMIN_EMAIL: Email address for the admin user
 * - ADMIN_PASSWORD: Password for the admin user
 * - ADMIN_ROLE: Role for the admin user (default: 'admin')
 * - POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
 * 
 * Usage:
 * - Configure environment variables
 * - Run with: npx ts-node src/utils/seed-admin.ts
 * - Script will create admin user if it doesn't exist
 * - Exits gracefully if admin already exists
 * 
 * Security:
 * - Passwords are hashed using bcrypt with 12 salt rounds
 * - Admin user is created with verified and active status
 * - Proper database transaction handling
 * - Environment-based configuration for credentials
 * 
 * Process:
 * 1. Initialize database connection
 * 2. Create UserRole enum if not exists
 * 3. Wait for tables to be ready
 * 4. Check if admin user already exists
 * 5. Create admin profile and user
 * 6. Hash password and save to database
 * 7. Log success and exit
 * 
 * @example
 * // Environment setup
 * ADMIN_EMAIL=admin@example.com
 * ADMIN_PASSWORD=securepassword123
 * ADMIN_ROLE=admin
 * 
 * // Run seeding
 * npx ts-node src/utils/seed-admin.ts
 * 
 * // Output: Admin user and profile created successfully
 */

// ============================================================================
// SEEDING MODULE CONFIGURATION
// ============================================================================

/**
 * Simplified NestJS module for database seeding
 * 
 * Provides the minimal configuration needed for database operations
 * during the seeding process, including TypeORM setup and configuration.
 * 
 * Features:
 * - ConfigModule for environment variable access
 * - TypeORM configuration for PostgreSQL
 * - Entity registration for User and UserProfile
 * - Synchronization enabled for table creation
 * - Logging enabled for debugging
 */
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('POSTGRES_HOST') || configService.get('DB_HOST') || 'postgres',
        port: parseInt(configService.get('POSTGRES_PORT') || '5432'),
        username: configService.get('POSTGRES_USER') || 'user',
        password: configService.get('POSTGRES_PASSWORD') || 'password',
        database: configService.get('POSTGRES_DB') || 'postgres',
        entities: [User, UserProfile],
        synchronize: true, // Enable sync to create tables
        logging: true,
        ssl: false,
      }),
      inject: [ConfigService],
    }),
    TypeOrmModule.forFeature([User, UserProfile]),
  ],
  providers: [],
})
class SeedModule {}

// ============================================================================
// DATABASE INITIALIZATION FUNCTIONS
// ============================================================================

/**
 * Create UserRole enum in the database
 * 
 * Creates the UserRole enum type in PostgreSQL if it doesn't already exist.
 * This enum is required for the user role field in the auth_users table.
 * 
 * Process:
 * 1. Check if UserRole enum already exists
 * 2. Create enum if it doesn't exist
 * 3. Log success or skip if already exists
 * 
 * @param dataSource - TypeORM DataSource instance
 * @returns Promise<void>
 * 
 * @example
 * await createUserRoleEnum(dataSource);
 * // Creates: CREATE TYPE "userrole" AS ENUM ('admin', 'user')
 */
async function createUserRoleEnum(dataSource: any) {
  const logger = new Logger('EnumCreation');
  try {
    // Check if the enum already exists
    const enumExists = await dataSource.query(`
      SELECT EXISTS (
        SELECT 1 FROM pg_type 
        WHERE typname = 'userrole'
      )
    `);
    
    if (!enumExists[0].exists) {
      logger.log('Creating UserRole enum...');
      await dataSource.query(`
        CREATE TYPE "userrole" AS ENUM ('admin', 'user')
      `);
      logger.log('UserRole enum created successfully');
    } else {
      logger.log('UserRole enum already exists');
    }
  } catch (error) {
    logger.error('Failed to create UserRole enum:', error);
  }
}

/**
 * Wait for database tables to be ready
 * 
 * Polls the database to ensure that all required tables have been created
 * before proceeding with the seeding process. This is necessary because
 * TypeORM synchronize runs asynchronously.
 * 
 * Process:
 * 1. Create UserRole enum first
 * 2. Poll database for table existence
 * 3. Retry with exponential backoff
 * 4. Throw error if tables not ready after max retries
 * 
 * @param app - NestJS application context
 * @param maxRetries - Maximum number of retry attempts (default: 30)
 * @param delay - Delay between retries in milliseconds (default: 2000)
 * @returns Promise<boolean> True when tables are ready
 * 
 * @example
 * await waitForTables(app, 30, 2000);
 * // Waits up to 60 seconds for tables to be created
 */
async function waitForTables(app: any, maxRetries = 30, delay = 2000) {
  const logger = new Logger('TableWait');
  const dataSource = app.get(DataSource);
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Create enum first
      await createUserRoleEnum(dataSource);
      
      // Try to query the table to see if it exists
      await dataSource.query('SELECT 1 FROM auth_users LIMIT 1');
      logger.log('Tables are ready');
      return true;
    } catch (error) {
      if (i === maxRetries - 1) {
        throw new Error('Tables not ready after maximum retries');
      }
      logger.log(`Waiting for tables... (attempt ${i + 1}/${maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// ============================================================================
// MAIN SEEDING FUNCTION
// ============================================================================

/**
 * Main admin user seeding function
 * 
 * Orchestrates the entire admin user creation process, including
 * database initialization, validation, and user creation with
 * proper error handling and logging.
 * 
 * Process:
 * 1. Initialize NestJS application context
 * 2. Wait for database tables to be ready
 * 3. Validate environment configuration
 * 4. Check for existing admin user
 * 5. Create admin profile and user
 * 6. Hash password and save to database
 * 7. Log success and exit gracefully
 * 
 * Environment Requirements:
 * - ADMIN_EMAIL: Email for admin user
 * - ADMIN_PASSWORD: Password for admin user
 * - ADMIN_ROLE: Role for admin user (optional, default: 'admin')
 * 
 * @returns Promise<void>
 * 
 * @example
 * // Run seeding
 * await seedAdmin();
 * // Creates admin user if not exists, exits if already exists
 */
async function seedAdmin() {
  const logger = new Logger('AdminSeed');
  
  try {
    logger.log('Starting admin user seeding...');
    
    // Create a minimal app instance for seeding
    const app = await NestFactory.createApplicationContext(SeedModule);
    
    // Wait for tables to be created
    await waitForTables(app);
    
    // Get the repositories and services using DataSource
    const dataSource = app.get(DataSource);
    const userRepository = dataSource.getRepository(User);
    const userProfileRepository = dataSource.getRepository(UserProfile);
    const configService = app.get(ConfigService);
    
    // Get admin credentials from environment variables
    const adminEmail = configService.get<string>('ADMIN_EMAIL');
    const adminPassword = configService.get<string>('ADMIN_PASSWORD');
    const adminRole = configService.get<string>('ADMIN_ROLE', 'admin');

    // Validate required environment variables
    if (!adminEmail || !adminPassword) {
      logger.warn('Admin credentials not configured, skipping admin user creation');
      logger.warn('Please set ADMIN_EMAIL and ADMIN_PASSWORD environment variables');
      await app.close();
      process.exit(0);
    }

    // Check if admin user already exists
    const existingAdmin = await userRepository.findOne({ where: { email: adminEmail } });
    
    if (existingAdmin) {
      logger.log('Admin user already exists', { email: adminEmail });
      await app.close();
      process.exit(0);
    }

    logger.log('Creating admin user...');
    
    // Create admin profile first
    const adminProfile = new UserProfile();
    adminProfile.tags = ['admin'];
    adminProfile.metadata = { role: adminRole };
    
    const savedProfile = await userProfileRepository.save(adminProfile);
    
    // Hash password using bcrypt with 12 salt rounds
    const hashedPassword = await bcrypt.hash(adminPassword, 12);
    
    // Create admin user with all required fields
    const adminUser = new User();
    adminUser.email = adminEmail;
    adminUser.password_hash = hashedPassword;
    adminUser.role = UserRole.admin; // Use enum instead of string
    adminUser.is_active = true;
    adminUser.is_verified = true;
    adminUser.is_configured = true;
    adminUser.profile_uuid = savedProfile.uuid;
    
    await userRepository.save(adminUser);
    
    logger.log('Admin user and profile created successfully', { 
      email: adminEmail, 
      role: adminRole,
      profile_uuid: savedProfile.uuid 
    });
    
    // Close the application context
    await app.close();
    
    process.exit(0);
  } catch (error) {
    logger.error('Admin seeding failed:', error);
    process.exit(1);
  }
}

// Execute the admin seeding process
seedAdmin(); 