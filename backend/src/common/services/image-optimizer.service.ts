import { Injectable, Logger } from '@nestjs/common';
import * as sharp from 'sharp';

/**
 * Supported image formats for optimization
 * 
 * Defines the image formats that can be processed and optimized.
 * Each format has specific optimization settings for best results.
 */
export type ImageFormat = 'jpeg' | 'png' | 'webp' | 'gif' | 'avif' | 'tiff' | 'svg';

/**
 * Interface for image optimization options
 * 
 * Defines the parameters for image optimization including
 * dimensions, quality, and output format.
 */
export interface ImageOptimizationOptions {
  /** Maximum width in pixels */
  maxWidth?: number;
  /** Maximum height in pixels */
  maxHeight?: number;
  /** Quality setting (1-100) */
  quality?: number;
  /** Output format for the optimized image */
  format?: ImageFormat;
}

/**
 * Image Optimizer Service
 * 
 * Provides image optimization and format conversion functionality.
 * Uses Sharp library for high-performance image processing.
 * 
 * Features:
 * - Image resizing with aspect ratio preservation
 * - Format conversion and optimization
 * - Quality and compression settings
 * - Automatic format detection
 * - Support for multiple image formats
 * - HEIC/HEIF and BMP conversion
 * 
 * Supported Formats:
 * - JPEG: Photos and complex images with lossy compression
 * - PNG: Images with transparency or sharp edges
 * - WebP: Modern format with excellent compression
 * - GIF: Animated images and simple graphics
 * - AVIF: Next-generation format with superior compression
 * - TIFF: High-quality images with lossless compression
 * - SVG: Vector graphics (no optimization needed)
 * 
 * Optimization Features:
 * - Automatic aspect ratio preservation
 * - Format-specific compression settings
 * - Quality control for file size optimization
 * - Metadata preservation where possible
 * - Error handling and logging
 * 
 * Usage:
 * - Injected into services that handle image uploads
 * - Provides optimized images for web delivery
 * - Supports format conversion for compatibility
 * - Handles various input formats automatically
 * 
 * @example
 * // Optimize image with default settings
 * const optimized = await this.imageOptimizer.optimizeImage(imageBuffer);
 * 
 * @example
 * // Optimize with custom settings
 * const optimized = await this.imageOptimizer.optimizeImage(imageBuffer, {
 *   maxWidth: 1200,
 *   maxHeight: 800,
 *   quality: 85,
 *   format: 'webp'
 * });
 * 
 * @example
 * // Determine best format automatically
 * const bestFormat = await this.imageOptimizer.determineBestFormat(imageBuffer);
 */
@Injectable()
export class ImageOptimizerService {
  private readonly logger = new Logger(ImageOptimizerService.name);

  // ============================================================================
  // MAIN OPTIMIZATION METHODS
  // ============================================================================

  /**
   * Optimizes an image buffer according to the specified parameters
   * 
   * Processes an image buffer to optimize file size and dimensions
   * while maintaining visual quality. Supports multiple output formats
   * with format-specific optimization settings.
   * 
   * @param buffer - The image buffer to optimize
   * @param options - Optimization options including dimensions, quality, and format
   * @returns Promise with optimized image buffer
   * @throws Error if image processing fails
   * 
   * @example
   * const optimized = await this.optimizeImage(imageBuffer, {
   *   maxWidth: 800,
   *   maxHeight: 600,
   *   quality: 85,
   *   format: 'webp'
   * });
   */
  async optimizeImage(
    buffer: Buffer,
    options: ImageOptimizationOptions = {}
  ): Promise<Buffer> {
    try {
      const {
        maxWidth = 800,
        maxHeight = 800,
        quality = 80,
        format = 'jpeg'
      } = options;

      // Get image metadata for dimension calculations
      const metadata = await sharp(buffer).metadata();
      
      // Calculate new dimensions maintaining aspect ratio
      let width = metadata.width;
      let height = metadata.height;
      
      if (width > maxWidth || height > maxHeight) {
        const ratio = Math.min(maxWidth / width, maxHeight / height);
        width = Math.round(width * ratio);
        height = Math.round(height * ratio);
      }

      // Initialize image processing pipeline
      const processedImage = sharp(buffer)
        .resize(width, height, {
          fit: 'inside',
          withoutEnlargement: true
        });

      // Apply format-specific optimizations
      switch (format) {
        case 'jpeg':
          return processedImage
            .jpeg({
              quality,
              mozjpeg: true, // Use mozjpeg for better compression
              chromaSubsampling: '4:4:4' // Better color quality
            })
            .toBuffer();

        case 'png':
          return processedImage
            .png({
              quality,
              compressionLevel: 9, // Maximum compression
              palette: true // Use palette for better compression
            })
            .toBuffer();

        case 'webp':
          return processedImage
            .webp({
              quality,
              effort: 6, // Higher effort for better compression
              lossless: false
            })
            .toBuffer();

        case 'gif':
          return processedImage
            .gif({
              effort: 6,
              dither: 1.0
            })
            .toBuffer();

        case 'avif':
          return processedImage
            .avif({
              quality,
              effort: 6,
              chromaSubsampling: '4:4:4'
            })
            .toBuffer();

        case 'tiff':
          return processedImage
            .tiff({
              quality,
              compression: 'lzw'
            })
            .toBuffer();

        case 'svg':
          // For SVG, we don't need to optimize as it's already vector-based
          return buffer;

        default:
          throw new Error(`Unsupported format: ${format}`);
      }
    } catch (error) {
      this.logger.error('Failed to optimize image:', error);
      throw error;
    }
  }

  /**
   * Determines the best format for an image based on its content
   * 
   * Analyzes image metadata to recommend the optimal output format
   * based on image characteristics like transparency, animation, and complexity.
   * 
   * @param buffer - The image buffer to analyze
   * @returns Promise with recommended format
   * 
   * @example
   * const bestFormat = await this.determineBestFormat(imageBuffer);
   * // Returns: 'png' for images with transparency, 'webp' for photos, etc.
   */
  async determineBestFormat(buffer: Buffer): Promise<ImageFormat> {
    try {
      const metadata = await sharp(buffer).metadata();
      
      // If image has transparency, use PNG
      if (metadata.hasAlpha) {
        return 'png';
      }

      // For animated images, use GIF
      if (metadata.pages && metadata.pages > 1) {
        return 'gif';
      }

      // For vector graphics, keep as SVG
      if (metadata.format === 'svg') {
        return 'svg';
      }

      // For photos and complex images, use WebP
      if (metadata.channels === 3) {
        return 'webp';
      }

      // Default to JPEG for other cases
      return 'jpeg';
    } catch (error) {
      this.logger.error('Failed to determine best format:', error);
      return 'jpeg'; // Fallback to JPEG
    }
  }

  // ============================================================================
  // FORMAT CONVERSION METHODS
  // ============================================================================

  /**
   * Converts HEIC/HEIF images to JPEG
   * 
   * Provides fallback conversion for HEIC/HEIF images when native
   * support is not available. HEIC is Apple's image format.
   * 
   * @param buffer - HEIC/HEIF image buffer
   * @returns Promise with JPEG buffer
   * @throws Error if conversion fails
   * 
   * @example
   * const jpegBuffer = await this.convertHeicToJpeg(heicBuffer);
   */
  private async convertHeicToJpeg(buffer: Buffer): Promise<Buffer> {
    try {
      return await sharp(buffer)
        .jpeg({
          quality: 90,
          mozjpeg: true
        })
        .toBuffer();
    } catch (error) {
      this.logger.error('Failed to convert HEIC to JPEG:', error);
      throw error;
    }
  }

  /**
   * Converts BMP images to PNG
   * 
   * Provides fallback conversion for BMP images when native
   * support is not available. BMP is an uncompressed format.
   * 
   * @param buffer - BMP image buffer
   * @returns Promise with PNG buffer
   * @throws Error if conversion fails
   * 
   * @example
   * const pngBuffer = await this.convertBmpToPng(bmpBuffer);
   */
  private async convertBmpToPng(buffer: Buffer): Promise<Buffer> {
    try {
      return await sharp(buffer)
        .png({
          quality: 90,
          compressionLevel: 9
        })
        .toBuffer();
    } catch (error) {
      this.logger.error('Failed to convert BMP to PNG:', error);
      throw error;
    }
  }
} 