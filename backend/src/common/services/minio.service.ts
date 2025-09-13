import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { S3Client, PutObjectCommand, GetObjectCommand, CreateBucketCommand, HeadBucketCommand, PutBucketPolicyCommand, ListObjectsV2Command, ListBucketsCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as https from 'https';

/**
 * MinIO Service
 * 
 * Provides object storage functionality using MinIO (S3-compatible storage).
 * Handles file uploads, downloads, and management with comprehensive logging.
 * 
 * Features:
 * - S3-compatible object storage operations
 * - File upload and download with streaming
 * - Public URL generation for file access
 * - Bucket management and policy configuration
 * - Health checks and monitoring
 * - Comprehensive error handling and logging
 * 
 * Storage Configuration:
 * - Configurable MinIO endpoint and credentials
 * - Automatic bucket creation and policy setup
 * - Support for both internal and public endpoints
 * - SSL/TLS configuration support
 * - Backup directory initialization
 * 
 * Security Features:
 * - Secure credential management
 * - Public read access policy configuration
 * - SSL verification options for development
 * - Access control through bucket policies
 * 
 * File Operations:
 * - Upload files with metadata preservation
 * - Download files with streaming support
 * - List files with prefix filtering
 * - Get file metadata and size information
 * - Generate public URLs for file access
 * 
 * Usage:
 * - Injected into services that need file storage
 * - Provides S3-compatible API for file operations
 * - Handles MinIO configuration automatically
 * - Supports both development and production environments
 * 
 * @example
 * // Upload a file
 * const fileUrl = await this.minioService.uploadFile(file, 'uploads/image.jpg');
 * 
 * @example
 * // Download a file
 * const fileBuffer = await this.minioService.downloadFile('uploads/image.jpg');
 * 
 * @example
 * // List files in a directory
 * const files = await this.minioService.listFiles('uploads/');
 * 
 * @example
 * // Get file URL
 * const url = await this.minioService.getFileUrl('uploads/image.jpg');
 */
@Injectable()
export class MinioService implements OnModuleInit {
  private s3Client: S3Client;
  private bucket: string;
  private publicEndpoint: string;
  private internalEndpoint: string;
  private readonly logger = new Logger(MinioService.name);

  constructor(private configService: ConfigService) {
    // Load MinIO configuration from environment variables
    const minioEndpoint = this.configService.getOrThrow<string>('MINIO_ENDPOINT');
    const minioPort = this.configService.getOrThrow<string>('MINIO_PORT');
    const minioUser = this.configService.getOrThrow<string>('MINIO_ROOT_USER');
    const minioPassword = this.configService.getOrThrow<string>('MINIO_ROOT_PASSWORD');
    this.bucket = this.configService.getOrThrow<string>('MINIO_BUCKET_NAME');

    // Configure endpoints for different access patterns
    this.internalEndpoint = `http://minio:${minioPort}`;
    
    // Configure public endpoint using MINIO_URL or fallback to localhost
    const minioUrl = this.configService.get<string>('MINIO_URL');
    if (minioUrl) {
      this.publicEndpoint = `http://${minioUrl}/minio`;
    } else {
    const useSSL = this.configService.get<string>('MINIO_USE_SSL') === 'true';
    const protocol = useSSL ? 'https' : 'http';
      this.publicEndpoint = `${protocol}://localhost:${minioPort}/minio`;
    }



    // Initialize S3 client with MinIO configuration
    this.s3Client = new S3Client({
      endpoint: this.internalEndpoint,
      region: 'us-east-1',
      credentials: {
        accessKeyId: minioUser,
        secretAccessKey: minioPassword,
      },
      forcePathStyle: true,
      // Disable SSL verification for local development
      requestHandler: {
        httpsAgent: new https.Agent({
          rejectUnauthorized: false
        })
      }
    });
  }

  // ============================================================================
  // MODULE INITIALIZATION
  // ============================================================================

  /**
   * Initialize MinIO service on module startup
   * 
   * Performs necessary setup tasks including bucket creation,
   * policy configuration, and access verification.
   * 
   * @throws Error if initialization fails
   */
  async onModuleInit() {


    // Perform initialization tasks
    await this.createBucketIfNotExists();
    await this.setBucketPolicy();
    await this.createBackupsDirectory();

    // Verify bucket access
    try {
      const command = new HeadBucketCommand({ Bucket: this.bucket });
      await this.s3Client.send(command);

    } catch (error) {
      this.logger.error(`Failed to access bucket: ${error.message}`);
      throw error;
    }
  }

  // ============================================================================
  // BUCKET MANAGEMENT METHODS
  // ============================================================================

  /**
   * Create bucket if it doesn't exist
   * 
   * Checks if the configured bucket exists and creates it if necessary.
   * Uses HeadBucketCommand to check existence and CreateBucketCommand to create.
   * 
   * @throws Error if bucket creation fails
   */
  private async createBucketIfNotExists() {
    try {
      const command = new HeadBucketCommand({ Bucket: this.bucket });
      await this.s3Client.send(command);
      
    } catch (error) {
      if (error.name === 'NotFound') {
        const createCommand = new CreateBucketCommand({
          Bucket: this.bucket,
        });
        await this.s3Client.send(createCommand);

      } else {
        throw error;
      }
    }
  }

  /**
   * Set bucket policy for public read access
   * 
   * Configures the bucket policy to allow public read access to all objects.
   * This enables direct URL access to uploaded files.
   * 
   * @throws Error if policy configuration fails
   */
  private async setBucketPolicy() {
    try {
      const policy = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: '*',
            Action: ['s3:GetObject'],
            Resource: [`arn:aws:s3:::${this.bucket}/*`]
          }
        ]
      };

      const command = new PutBucketPolicyCommand({
        Bucket: this.bucket,
        Policy: JSON.stringify(policy)
      });

      await this.s3Client.send(command);

    } catch (error) {
      this.logger.error('Failed to set bucket policy:', error);
      throw error;
    }
  }

  /**
   * Create backups directory in bucket
   * 
   * Creates a backups directory by uploading a placeholder file.
   * This establishes the directory structure for backup operations.
   * 
   * Note: This method doesn't throw errors as it's not critical for operation.
   */
  private async createBackupsDirectory() {
    try {
      // Create a placeholder file to establish the backups directory
      const command = new PutObjectCommand({
        Bucket: this.bucket,
        Key: 'backups/.keep',
        Body: Buffer.from('Backups directory placeholder'),
        ContentType: 'text/plain',
      });

      await this.s3Client.send(command);

    } catch (error) {
      this.logger.error('Failed to create backups directory:', error);
      // Don't throw error as this is not critical
    }
  }

  // ============================================================================
  // FILE OPERATIONS
  // ============================================================================

  /**
   * Upload a file to MinIO storage
   * 
   * Uploads a file buffer to MinIO with metadata preservation.
   * Returns a public URL for accessing the uploaded file.
   * 
   * @param file - Express Multer file object with buffer and metadata
   * @param key - Storage key (path) for the file
   * @returns Promise with public URL for the uploaded file
   * @throws Error if upload fails
   * 
   * @example
   * const fileUrl = await this.uploadFile(multerFile, 'uploads/profile.jpg');
   * // Returns: 'https://example.com/minio/bucket/uploads/profile.jpg'
   */
  async uploadFile(file: Express.Multer.File, key: string): Promise<string> {


    try {
      const command = new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: file.buffer,
        ContentType: file.mimetype,
      });



      await this.s3Client.send(command);


      const fileUrl = await this.getFileUrl(key);
      
      return fileUrl;
    } catch (error) {
      this.logger.error('Failed to upload file to MinIO:', {
        error: error.message,
        stack: error.stack,
        bucket: this.bucket,
        key
      });
      throw error;
    }
  }

  /**
   * Generate public URL for a file
   * 
   * Creates a public URL for accessing a file stored in MinIO.
   * The URL is constructed using the public endpoint configuration.
   * 
   * @param key - Storage key (path) of the file
   * @returns Promise with public URL for the file
   * @throws Error if URL generation fails
   * 
   * @example
   * const url = await this.getFileUrl('uploads/image.jpg');
   * // Returns: 'https://example.com/minio/bucket/uploads/image.jpg'
   */
  async getFileUrl(key: string): Promise<string> {
    try {
      // Return a clean URL without AWS signature parameters
      const fileUrl = `${this.publicEndpoint}/${this.bucket}/${key}`;
      return fileUrl;
    } catch (error) {
      this.logger.error('Error generating file URL:', {
        error: error.message,
        stack: error.stack,
        bucket: this.bucket,
        key,
        endpoint: this.publicEndpoint
      });
      throw new Error(`Failed to generate file URL: ${error.message}`);
    }
  }

  /**
   * Generate signed URL for direct file download
   * 
   * Creates a signed URL that allows direct file download without authentication.
   * The URL is valid for a specified duration and includes AWS signature parameters.
   * 
   * @param key - Storage key (path) of the file
   * @param expiresIn - URL expiration time in seconds (default: 3600 = 1 hour)
   * @returns Promise with signed URL for direct download
   * @throws Error if URL generation fails
   * 
   * @example
   * const url = await this.getSignedDownloadUrl('uploads/document.pdf', 7200);
   * // Returns: 'https://minio.example.com/bucket/uploads/document.pdf?X-Amz-Algorithm=...'
   */
  async getSignedDownloadUrl(key: string, expiresIn: number = 3600): Promise<string> {
    try {
      // Create a temporary S3 client with public endpoint for signed URLs
      const publicS3Client = new S3Client({
        endpoint: this.publicEndpoint.replace('/minio', ''), // Remove /minio suffix for S3 client
        region: 'us-east-1',
        credentials: {
          accessKeyId: this.configService.getOrThrow<string>('MINIO_ROOT_USER'),
          secretAccessKey: this.configService.getOrThrow<string>('MINIO_ROOT_PASSWORD'),
        },
        forcePathStyle: true,
        // Disable SSL verification for local development
        requestHandler: {
          httpsAgent: new https.Agent({
            rejectUnauthorized: false
          })
        }
      });

      const command = new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
      });

      const fileUrl = await getSignedUrl(publicS3Client, command, { expiresIn });
      return fileUrl;
    } catch (error) {
      this.logger.error('Error generating signed download URL:', {
        error: error.message,
        stack: error.stack,
        bucket: this.bucket,
        key,
        expiresIn
      });
      throw new Error(`Failed to generate signed download URL: ${error.message}`);
    }
  }

  /**
   * Download a file from MinIO storage
   * 
   * Downloads a file from MinIO and returns it as a buffer.
   * Handles streaming response and buffer conversion.
   * 
   * @param key - Storage key (path) of the file to download
   * @returns Promise with file buffer
   * @throws Error if download fails
   * 
   * @example
   * const fileBuffer = await this.downloadFile('uploads/document.pdf');
   */
  async downloadFile(key: string): Promise<Buffer> {

    try {
      const command = new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
      });

      const response = await this.s3Client.send(command);
      
      if (!response.Body) {
        throw new Error('No file content received from MinIO');
      }

      // Convert stream to buffer
      const chunks: Uint8Array[] = [];
      for await (const chunk of response.Body as any) {
        chunks.push(chunk);
      }
      const buffer = Buffer.concat(chunks);

      return buffer;
    } catch (error) {
      this.logger.error('Failed to download file from MinIO:', {
        error: error.message,
        stack: error.stack,
        bucket: this.bucket,
        key
      });
      throw error;
    }
  }

  /**
   * List files in a directory
   * 
   * Lists all files with a given prefix (directory path).
   * Returns an array of file keys (paths).
   * 
   * @param prefix - Directory prefix to list files from
   * @returns Promise with array of file keys
   * @throws Error if listing fails
   * 
   * @example
   * const files = await this.listFiles('uploads/');
   * // Returns: ['uploads/file1.jpg', 'uploads/file2.pdf', ...]
   */
  async listFiles(prefix: string): Promise<string[]> {

    try {
      const command = new ListObjectsV2Command({
        Bucket: this.bucket,
        Prefix: prefix,
      });

      const response = await this.s3Client.send(command);
      
      if (!response.Contents) {
        return [];
      }

      const files = response.Contents.map(obj => obj.Key).filter(key => key !== undefined) as string[];

      return files;
    } catch (error) {
      this.logger.error('Failed to list files from MinIO:', {
        error: error.message,
        stack: error.stack,
        bucket: this.bucket,
        prefix
      });
      throw error;
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Perform health check on MinIO service
   * 
   * Verifies that MinIO is accessible and responding.
   * Uses ListBucketsCommand to test connectivity.
   * 
   * @returns Promise with boolean indicating health status
   * 
   * @example
   * const isHealthy = await this.healthCheck();
   * // Returns: true if MinIO is accessible
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.s3Client.send(new ListBucketsCommand({}));
      return true;
    } catch (error) {
      this.logger.error('MinIO health check failed', { error: error.message });
      return false;
    }
  }

  /**
   * Get file size from MinIO
   * 
   * Retrieves the size of a file stored in MinIO.
   * Uses HeadObjectCommand to get metadata without downloading.
   * 
   * @param key - Storage key (path) of the file
   * @returns Promise with file size in bytes or null if not found
   * 
   * @example
   * const size = await this.getFileSize('uploads/large-file.zip');
   * // Returns: 1048576 (file size in bytes)
   */
  async getFileSize(key: string): Promise<number | null> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.bucket,
        Key: key
      });
      const result = await this.s3Client.send(command);
      if (result && typeof result.ContentLength === 'number') {
        return result.ContentLength;
      }
      return null;
    } catch (error) {
      this.logger.error('Failed to get file size from MinIO:', { key, error: error.message });
      return null;
    }
  }
}