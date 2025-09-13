import { Module } from '@nestjs/common';

// Local imports
import { ImageOptimizerService } from '../services/image-optimizer.service';

/**
 * Image Optimizer Module
 * 
 * Provides image processing and optimization functionality for the application.
 * Handles image resizing, compression, format conversion, and optimization.
 * 
 * Features:
 * - Image resizing and scaling
 * - Image compression and optimization
 * - Format conversion (JPEG, PNG, WebP, etc.)
 * - Thumbnail generation
 * - Image quality optimization
 * - Batch image processing
 * 
 * Services:
 * - ImageOptimizerService: Core image processing functionality
 * 
 * Dependencies:
 * - Sharp library for image processing
 * - File system for image storage
 * 
 * Configuration:
 * - Supported image formats
 * - Quality settings for different formats
 * - Resize options and limits
 * - Output directory paths
 * - Processing timeouts
 * 
 * Usage:
 * - Imported by other modules for image processing
 * - Used for user uploads, media optimization, etc.
 * - Provides efficient image handling for web applications
 * 
 * Performance:
 * - Asynchronous image processing
 * - Memory-efficient operations
 * - Caching for processed images
 * - Batch processing capabilities
 */
@Module({
  // Service providers for image optimization
  providers: [
    ImageOptimizerService,   // Core image processing service
  ],
  
  // Export service for use in other modules
  exports: [
    ImageOptimizerService,   // Image optimization functionality
  ],
})
export class ImageOptimizerModule {} 