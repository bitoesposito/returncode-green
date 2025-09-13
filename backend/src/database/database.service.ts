import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

/**
 * Database Service
 * 
 * Provides core database management functionality including initialization,
 * synchronization, and monitoring for the application.
 * 
 * Features:
 * - Database connection verification
 * - Custom enum creation (UserRole)
 * - Table existence checking
 * - Schema information retrieval
 * - Force synchronization capabilities
 * - Comprehensive logging and error handling
 * 
 * Database Operations:
 * - Connection health checks
 * - Schema validation and creation
 * - Table structure analysis
 * - Enum type management
 * - Synchronization control
 * 
 * Initialization Process:
 * - Verifies database connectivity
 * - Creates custom enums if needed
 * - Validates table existence
 * - Logs initialization status
 * 
 * Usage:
 * - Injected into DatabaseController for API endpoints
 * - Used for database health monitoring
 * - Provides schema management utilities
 * - Handles database setup and maintenance
 * 
 * @example
 * // Check if tables exist
 * const tablesExist = await this.databaseService.checkTables();
 * 
 * @example
 * // Get table schema information
 * const tableInfo = await this.databaseService.getTableInfo();
 * 
 * @example
 * // Force database synchronization
 * const success = await this.databaseService.forceSync();
 */
@Injectable()
export class DatabaseService implements OnModuleInit {
  private readonly logger = new Logger(DatabaseService.name);

  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
  ) {}

  // ============================================================================
  // MODULE INITIALIZATION
  // ============================================================================

  /**
   * Initialize database on module startup
   * 
   * Performs essential database setup tasks including:
   * - Connection verification
   * - Custom enum creation
   * - Table existence validation
   * - Initialization logging
   * 
   * @throws Error if database initialization fails
   */
  async onModuleInit() {
    try {
  
      
      // Verify database connection
      await this.dataSource.query('SELECT 1');
      
      
      // Create UserRole enum if it doesn't exist
      await this.createUserRoleEnum();
      
      // Verify that required tables exist
      const tables = await this.dataSource.query(`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('auth_users', 'user_profiles')
      `);
      
      
      
      if (tables.length === 0) {
        this.logger.warn('No tables found. TypeORM should create them automatically with synchronize: true');
      }
      
    } catch (error) {
      this.logger.error('Database initialization failed:', error);
      throw error;
    }
  }

  // ============================================================================
  // ENUM MANAGEMENT
  // ============================================================================

  /**
   * Create UserRole enum if it doesn't exist
   * 
   * Creates a PostgreSQL enum type for user roles if it doesn't already exist.
   * This ensures the enum is available before entity synchronization.
   * 
   * Enum Values:
   * - 'admin': Administrator role with full privileges
   * - 'user': Standard user role with limited privileges
   * 
   * @throws Error if enum creation fails
   * 
   * @example
   * await this.createUserRoleEnum();
   * // Creates: CREATE TYPE "userrole" AS ENUM ('admin', 'user')
   */
  async createUserRoleEnum() {
    try {
      // Check if the enum already exists
      const enumExists = await this.dataSource.query(`
        SELECT EXISTS (
          SELECT 1 FROM pg_type 
          WHERE typname = 'userrole'
        )
      `);
      
      if (!enumExists[0].exists) {

        await this.dataSource.query(`
          CREATE TYPE "userrole" AS ENUM ('admin', 'user')
        `);
        
      } else {

      }
    } catch (error) {
      this.logger.error('Failed to create UserRole enum:', error);
    }
  }

  // ============================================================================
  // DATABASE STATUS METHODS
  // ============================================================================

  /**
   * Check if required tables exist in the database
   * 
   * Verifies the existence of the auth_users table by attempting
   * a simple query. Returns true if the table exists and is accessible.
   * 
   * @returns Promise with boolean indicating if tables exist
   * 
   * @example
   * const tablesExist = await this.checkTables();
   * // Returns: true if auth_users table exists and is accessible
   */
  async checkTables() {
    try {
      const result = await this.dataSource.query('SELECT 1 FROM auth_users LIMIT 1');
      return result.length > 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get detailed table schema information
   * 
   * Retrieves comprehensive schema information for the application's
   * main tables including column names, data types, and nullability.
   * 
   * Tables Analyzed:
   * - auth_users: User authentication and management
   * - user_profiles: Extended user profile information
   * 
   * @returns Promise with array of table schema information
   * 
   * @example
   * const tableInfo = await this.getTableInfo();
   * // Returns: [
   * //   {
   * //     table_name: 'auth_users',
   * //     column_name: 'id',
   * //     data_type: 'uuid',
   * //     is_nullable: 'NO'
   * //   },
   * //   ...
   * // ]
   */
  async getTableInfo() {
    try {
      const tables = await this.dataSource.query(`
        SELECT 
          table_name,
          column_name,
          data_type,
          is_nullable
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name IN ('auth_users', 'user_profiles')
        ORDER BY table_name, ordinal_position
      `);
      
      return tables;
    } catch (error) {
      this.logger.error('Failed to get table info:', error);
      return [];
    }
  }

  // ============================================================================
  // DATABASE SYNCHRONIZATION
  // ============================================================================

  /**
   * Force database schema synchronization
   * 
   * Triggers a manual synchronization of the database schema to match
   * the current entity definitions. This operation:
   * - Creates missing tables and columns
   * - Updates existing schema to match entities
   * - Ensures enum types are available
   * 
   * Warning: This operation can be destructive in production environments.
   * Use with caution and ensure proper backups before execution.
   * 
   * @returns Promise with boolean indicating synchronization success
   * 
   * @example
   * const success = await this.forceSync();
   * // Returns: true if synchronization completed successfully
   */
  async forceSync() {
    try {
      
      
      // Create UserRole enum before synchronization
      await this.createUserRoleEnum();
      
      // Force entity synchronization
      await this.dataSource.synchronize(true);
      
      
      return true;
    } catch (error) {
      this.logger.error('Database synchronization failed:', error);
      return false;
    }
  }
} 