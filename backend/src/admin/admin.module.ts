import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

// Local imports
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { CommonModule } from '../common/modules/common.module';
import { GuardsModule } from '../auth/guards/guards.module';

/**
 * Admin Module
 * 
 * This module provides administrative functionality for the application including:
 * - User management (list, delete users)
 * - System metrics and analytics
 * - Audit log viewing
 * - Administrative operations
 * 
 * Dependencies:
 * - TypeORM for database operations
 * - CommonModule for shared services (audit, metrics, etc.)
 * - User and UserProfile entities for data access
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([User, UserProfile]),
    CommonModule,
    GuardsModule,
  ],
  controllers: [AdminController],
  providers: [AdminService],
  exports: [AdminService],
})
export class AdminModule {} 