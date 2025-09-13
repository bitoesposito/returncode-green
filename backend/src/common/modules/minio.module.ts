import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

// Local imports
import { MinioService } from '../services/minio.service';

/**
 * Minio Module
 * 
 * Provides object storage functionality using MinIO (S3-compatible storage).
 * Handles file uploads, downloads, and management in cloud storage.
 * 
 * Features:
 * - S3-compatible object storage
 * - File upload and download
 * - Bucket management
 * - File metadata handling
 * - Secure file access
 * 
 * Services:
 * - MinioService: Core object storage functionality
 * 
 * Dependencies:
 * - ConfigModule: For MinIO configuration (endpoint, credentials, etc.)
 * 
 * Configuration:
 * - MinIO server endpoint
 * - Access key and secret key
 * - Default bucket names
 * - File upload limits
 * - Storage policies
 * 
 * Usage:
 * - Imported by other modules for file storage
 * - Used for user uploads, media files, etc.
 * - Provides scalable object storage solution
 * 
 * Note:
 * - Currently disabled in CommonModule
 * - Enable when MinIO server is configured
 * - Requires proper MinIO server setup
 */
@Module({
  // Import configuration module for MinIO settings
  imports: [ConfigModule],
  
  // Service providers for object storage
  providers: [
    MinioService,     // Object storage service
  ],
  
  // Export service for use in other modules
  exports: [
    MinioService,     // Object storage functionality
  ],
})
export class MinioModule {}
