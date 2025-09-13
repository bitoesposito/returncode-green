import { 
  Injectable, 
  Logger, 
  NotFoundException, 
  BadRequestException, 
  InternalServerErrorException 
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request, Response } from 'express';
import * as crypto from 'crypto';
import * as path from 'path';

// Local imports
import { Certificate } from './entities/certificate.entity';
import { User } from '../auth/entities/user.entity';
import { CryptoService } from './services/crypto.service';
import { PdfService } from './services/pdf.service';
import { MinioService } from '../common/services/minio.service';
import { AuditService, AuditEventType } from '../common/services/audit.service';
import { ApiResponseDto } from '../common/common.interface';
import { 
  GenerateCertificateDto, 
  CertificateResponseDto, 
  VerificationResultDto,
  RevokeCertificateDto
} from './dto/certificate.dto';

/**
 * Certificates Service
 * 
 * Core business logic for certificate operations including generation,
 * verification, download, and revocation. Handles cryptographic operations,
 * file storage, and database persistence with comprehensive error handling.
 * 
 * Features:
 * - Certificate generation with digital signatures
 * - Cryptographic verification of certificate authenticity
 * - Secure file storage and retrieval via MinIO
 * - Certificate revocation and audit logging
 * - User authorization and access control
 * 
 * Security:
 * - SHA256 hash calculation for file integrity
 * - RSA/ECDSA digital signatures for authenticity
 * - Secure key management and rotation support
 * - Comprehensive audit logging for all operations
 * - Input validation and sanitization
 * 
 * Dependencies:
 * - Certificate repository for database operations
 * - User repository for user validation
 * - CryptoService for cryptographic operations
 * - MinioService for file storage operations
 * - AuditService for security and compliance logging
 */
@Injectable()
export class CertificatesService {
  private readonly logger = new Logger(CertificatesService.name);

  constructor(
    @InjectRepository(Certificate)
    private readonly certificateRepository: Repository<Certificate>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly cryptoService: CryptoService,
    private readonly pdfService: PdfService,
    private readonly minioService: MinioService,
    private readonly auditService: AuditService,
  ) {}

  // ============================================================================
  // CERTIFICATE GENERATION METHODS
  // ============================================================================

  /**
   * Generate new digital certificate
   * 
   * Creates a new certificate with cryptographic signature for a user.
   * Generates PDF automatically from template and handles storage,
   * hash calculation, signature generation, and database persistence.
   * 
   * Process:
   * 1. Validate user existence and input data
   * 2. Generate PDF certificate from template
   * 3. Upload PDF file to MinIO storage
   * 4. Calculate SHA256 hash of file content
   * 5. Generate digital signature using private key
   * 6. Store certificate metadata in database
   * 7. Log certificate generation event
   * 8. Return certificate information
   * 
   * @param generateCertificateDto - Certificate generation data
   * @param req - Express request object for audit logging
   * @returns Promise with certificate generation result
   * 
   * @throws BadRequestException if input validation fails
   * @throws NotFoundException if user does not exist
   * @throws InternalServerErrorException if generation process fails
   */
  async generateCertificate(
    generateCertificateDto: GenerateCertificateDto,
    req: Request,
  ): Promise<ApiResponseDto<CertificateResponseDto>> {
    this.logger.log('Starting certificate generation process', {
      userId: generateCertificateDto.user_uuid,
      courseName: generateCertificateDto.course_name
    });

    try {
      // 1. Validate user existence
      const user = await this.userRepository.findOne({
        where: { uuid: generateCertificateDto.user_uuid }
      });

      if (!user) {
        this.logger.warn('Certificate generation failed: User not found', {
          userId: generateCertificateDto.user_uuid
        });
        throw new NotFoundException('User not found');
      }

      // 2. Generate TXT certificate file for testing
      const now = new Date();
      const certificateId = crypto.randomUUID();
      
      this.logger.debug('Generating TXT certificate file for testing', { certificateId });
      
      const txtContent = this.generateCertificateTxt({
        studentEmail: user.email,
        courseName: generateCertificateDto.course_name,
        issuedDate: generateCertificateDto.issued_date || now.toISOString(),
        certificateId: certificateId,
        description: generateCertificateDto.description,
        organizationName: 'ReturnCode Academy',
        instructorName: 'Docente Certificato'
      });

      const txtBuffer = Buffer.from(txtContent, 'utf-8');

      this.logger.debug('TXT certificate generated successfully', { 
        certificateId,
        txtSize: txtBuffer.length 
      });

      // 3. Generate file path for MinIO storage
      const year = now.getFullYear();
      const month = String(now.getMonth() + 1).padStart(2, '0');
      const fileName = `${certificateId}.txt`;
      const filePath = `certificates/${year}/${month}/${user.uuid}/${fileName}`;

      this.logger.debug('Generated file path for certificate', { filePath });

      // 4. Calculate SHA256 hash of TXT content
      const fileHash = this.cryptoService.calculateSHA256(txtBuffer);
      this.logger.debug('Calculated file hash', { hashLength: fileHash.length });

      // 5. Generate digital signature
      const signature = await this.cryptoService.signHash(fileHash);
      const publicKeyId = this.cryptoService.getCurrentKeyId();
      
      this.logger.debug('Generated digital signature', { 
        publicKeyId,
        signatureLength: signature.length 
      });

      // 6. Upload TXT file to MinIO (with rollback capability)
      let fileUrl: string;
      try {
        // Crea oggetto file compatibile con MinioService
        const txtFile: Express.Multer.File = {
          fieldname: 'certificate_file',
          originalname: fileName,
          encoding: '7bit',
          mimetype: 'text/plain',
          buffer: txtBuffer,
          size: txtBuffer.length
        } as Express.Multer.File;

        fileUrl = await this.minioService.uploadFile(txtFile, filePath);
        this.logger.debug('TXT file uploaded to MinIO', { fileUrl });
      } catch (uploadError) {
        this.logger.error('Failed to upload TXT file to MinIO', uploadError);
        throw new InternalServerErrorException('Failed to upload certificate file');
      }

      // 7. Create certificate record in database
      const certificate = this.certificateRepository.create({
        id: certificateId,
        user_uuid: user.uuid,
        course_name: generateCertificateDto.course_name,
        description: generateCertificateDto.description || null,
        issued_date: generateCertificateDto.issued_date 
          ? new Date(generateCertificateDto.issued_date) 
          : now,
        file_path: filePath,
        original_filename: fileName,
        content_type: 'text/plain',
        file_size: txtBuffer.length,
        hash: fileHash,
        signature: signature,
        public_key_id: publicKeyId,
        revoked: false,
        metadata: generateCertificateDto.metadata || {}
      });

      try {
        await this.certificateRepository.save(certificate);
        this.logger.log('Certificate saved to database', { certificateId });
      } catch (dbError) {
        this.logger.error('Failed to save certificate to database', dbError);
        
        // Rollback: Delete uploaded file from MinIO
        try {
          // Note: MinioService doesn't have deleteFile method yet, 
          // this would need to be implemented
          this.logger.warn('File rollback not implemented - manual cleanup required', { filePath });
        } catch (rollbackError) {
          this.logger.error('Failed to rollback file upload', rollbackError);
        }
        
        throw new InternalServerErrorException('Failed to save certificate record');
      }

      // 8. Log certificate generation event
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);
      
      try {
        await this.auditService.log({
          event_type: AuditEventType.DATA_ACCESS,
          user_id: user.uuid,
          user_email: user.email,
          ip_address: clientIp,
          user_agent: userAgent,
          resource: `/certificates`,
          action: 'POST',
          status: 'SUCCESS',
          details: {
            operation: 'CERTIFICATE_GENERATED',
            certificateId: certificate.id,
            courseName: certificate.course_name,
            publicKeyId: certificate.public_key_id,
            fileSize: certificate.file_size,
            contentType: certificate.content_type,
            generatedFromTemplate: true
          },
          metadata: {
            originalFilename: certificate.original_filename,
            filePath: certificate.file_path
          }
        });
      } catch (auditError) {
        this.logger.error('Failed to log certificate generation event', auditError);
        // Don't fail the operation for audit logging errors
      }

      // 9. Prepare response
      const response: CertificateResponseDto = {
        id: certificate.id,
        user_uuid: certificate.user_uuid,
        user_email: user.email,
        course_name: certificate.course_name,
        description: certificate.description,
        issued_date: certificate.issued_date,
        file_path: certificate.file_path,
        original_filename: certificate.original_filename,
        content_type: certificate.content_type,
        file_size: certificate.file_size,
        public_key_id: certificate.public_key_id,
        revoked: certificate.revoked,
        revoked_at: certificate.revoked_at,
        revoked_reason: certificate.revoked_reason,
        metadata: certificate.metadata,
        created_at: certificate.created_at,
        updated_at: certificate.updated_at
      };

      this.logger.log('Certificate generation completed successfully', {
        certificateId: certificate.id,
        userId: user.uuid,
        courseName: certificate.course_name
      });

      return ApiResponseDto.success(
        response,
        'Certificate generated successfully'
      );

    } catch (error) {
      this.logger.error('Certificate generation failed', {
        error: error.message,
        stack: error.stack,
        userId: generateCertificateDto.user_uuid,
        courseName: generateCertificateDto.course_name
      });

      // Re-throw known exceptions
      if (error instanceof NotFoundException || 
          error instanceof BadRequestException || 
          error instanceof InternalServerErrorException) {
        throw error;
      }

      // Wrap unknown errors
      throw new InternalServerErrorException('Certificate generation failed');
    }
  }

  // ============================================================================
  // CERTIFICATE VERIFICATION METHODS
  // ============================================================================

  /**
   * Verify certificate authenticity
   * 
   * Verifies the authenticity of a certificate by validating its
   * cryptographic signature against the stored hash and public key.
   * 
   * Process:
   * 1. Retrieve certificate metadata from database
   * 2. Check if certificate is revoked
   * 3. Download original file from MinIO storage
   * 4. Recalculate SHA256 hash of file content
   * 5. Verify digital signature using public key
   * 6. Log verification attempt
   * 7. Return verification result
   * 
   * @param certificateId - UUID of certificate to verify
   * @returns Promise with verification result
   * 
   * @throws NotFoundException if certificate does not exist
   * @throws InternalServerErrorException if verification process fails
   */
  async verifyCertificate(certificateId: string): Promise<ApiResponseDto<VerificationResultDto>> {
    this.logger.log(`Starting certificate verification for ID: ${certificateId}`);

    try {
      // 1. Retrieve certificate metadata from database
      const certificate = await this.certificateRepository.findOne({
        where: { id: certificateId },
        relations: ['user']
      });

      if (!certificate) {
        this.logger.warn('Certificate verification failed: Certificate not found', {
          certificateId
        });

        const result: VerificationResultDto = {
          valid: false,
          reason: 'Certificate not found',
          verified_at: new Date()
        };

        return ApiResponseDto.success(result, 'Certificate verification completed');
      }

      // 2. Check if certificate is revoked
      if (certificate.revoked) {
        this.logger.log('Certificate verification failed: Certificate is revoked', {
          certificateId,
          revokedAt: certificate.revoked_at,
          revokedReason: certificate.revoked_reason
        });

        const result: VerificationResultDto = {
          valid: false,
          reason: `Certificate has been revoked: ${certificate.revoked_reason}`,
          verified_at: new Date(),
          public_key_id: certificate.public_key_id
        };

        return ApiResponseDto.success(result, 'Certificate verification completed');
      }

      // 3. Download original file from MinIO storage
      let fileBuffer: Buffer;
      try {
        fileBuffer = await this.minioService.downloadFile(certificate.file_path);
        this.logger.debug('File downloaded from MinIO for verification', {
          certificateId,
          filePath: certificate.file_path,
          downloadedSize: fileBuffer.length
        });
      } catch (downloadError) {
        this.logger.error('Failed to download certificate file for verification', {
          certificateId,
          filePath: certificate.file_path,
          error: downloadError.message
        });

        const result: VerificationResultDto = {
          valid: false,
          reason: 'Certificate file not accessible',
          verified_at: new Date(),
          public_key_id: certificate.public_key_id
        };

        return ApiResponseDto.success(result, 'Certificate verification completed');
      }

      // 4. Recalculate SHA256 hash of file content
      const recalculatedHash = this.cryptoService.calculateSHA256(fileBuffer);
      
      this.logger.debug('Hash recalculated for verification', {
        certificateId,
        originalHash: certificate.hash,
        recalculatedHash,
        hashMatch: recalculatedHash === certificate.hash
      });

      // 5. Verify hash integrity
      if (recalculatedHash !== certificate.hash) {
        this.logger.warn('Certificate verification failed: Hash mismatch', {
          certificateId,
          originalHash: certificate.hash,
          recalculatedHash
        });

        const result: VerificationResultDto = {
          valid: false,
          reason: 'Certificate file has been tampered with (hash mismatch)',
          verified_at: new Date(),
          public_key_id: certificate.public_key_id
        };

        return ApiResponseDto.success(result, 'Certificate verification completed');
      }

      // 6. Verify digital signature using public key
      let signatureValid: boolean;
      try {
        signatureValid = await this.cryptoService.verifySignature(
          certificate.hash,
          certificate.signature,
          certificate.public_key_id
        );

        this.logger.debug('Digital signature verification completed', {
          certificateId,
          publicKeyId: certificate.public_key_id,
          signatureValid
        });
      } catch (verificationError) {
        this.logger.error('Failed to verify digital signature', {
          certificateId,
          publicKeyId: certificate.public_key_id,
          error: verificationError.message
        });

        const result: VerificationResultDto = {
          valid: false,
          reason: 'Signature verification failed',
          verified_at: new Date(),
          public_key_id: certificate.public_key_id
        };

        return ApiResponseDto.success(result, 'Certificate verification completed');
      }

      // 7. Prepare verification result
      const verifiedAt = new Date();
      
      if (signatureValid) {
        // Certificate is valid - prepare certificate info
        const certificateInfo = {
          id: certificate.id,
          user_email: certificate.user.email,
          course_name: certificate.course_name,
          description: certificate.description,
          issued_date: certificate.issued_date,
          revoked: certificate.revoked,
          public_key_id: certificate.public_key_id,
          metadata: certificate.metadata
        };

        const result: VerificationResultDto = {
          valid: true,
          certificate: certificateInfo,
          verified_at: verifiedAt,
          public_key_id: certificate.public_key_id
        };

        this.logger.log('Certificate verification successful', {
          certificateId,
          userId: certificate.user_uuid,
          courseName: certificate.course_name
        });

        return ApiResponseDto.success(result, 'Certificate is valid');
      } else {
        const result: VerificationResultDto = {
          valid: false,
          reason: 'Invalid digital signature',
          verified_at: verifiedAt,
          public_key_id: certificate.public_key_id
        };

        this.logger.warn('Certificate verification failed: Invalid signature', {
          certificateId,
          publicKeyId: certificate.public_key_id
        });

        return ApiResponseDto.success(result, 'Certificate verification completed');
      }

    } catch (error) {
      this.logger.error('Certificate verification error', {
        certificateId,
        error: error.message,
        stack: error.stack
      });

      // For public verification endpoint, don't expose internal errors
      const result: VerificationResultDto = {
        valid: false,
        reason: 'Verification process failed',
        verified_at: new Date()
      };

      return ApiResponseDto.success(result, 'Certificate verification completed');
    }
  }

  // ============================================================================
  // CERTIFICATE DOWNLOAD METHODS
  // ============================================================================

  /**
   * Download certificate file
   * 
   * Retrieves and streams certificate file to authenticated user.
   * Validates user ownership or admin privileges before allowing download.
   * 
   * Process:
   * 1. Validate certificate existence
   * 2. Check user authorization (owner or admin)
   * 3. Retrieve file from MinIO storage
   * 4. Set appropriate response headers
   * 5. Stream file to client
   * 6. Log download event
   * 
   * @param certificateId - UUID of certificate to download
   * @param req - Express request object for user identification
   * @param res - Express response object for file streaming
   * 
   * @throws NotFoundException if certificate does not exist
   * @throws UnauthorizedException if user lacks permission
   * @throws InternalServerErrorException if download fails
   */
  async downloadCertificate(
    certificateId: string,
    req: Request,
    res: Response,
  ): Promise<void> {
    this.logger.log(`Starting certificate download for ID: ${certificateId}`);

    try {
      // 1. Validate certificate existence
      const certificate = await this.certificateRepository.findOne({
        where: { id: certificateId },
        relations: ['user']
      });

      if (!certificate) {
        this.logger.warn('Certificate download failed: Certificate not found', {
          certificateId
        });
        res.status(404).json({
          success: false,
          message: 'Certificate not found',
          error: 'CERTIFICATE_NOT_FOUND'
        });
        return;
      }

      // 2. Check user authorization (owner or admin)
      const requestingUserId = this.getUserIdFromRequest(req);
      const isAdmin = this.isAdmin(req);

      if (!requestingUserId) {
        this.logger.warn('Certificate download failed: No user ID in request', {
          certificateId
        });
        res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: 'UNAUTHORIZED'
        });
        return;
      }

      const isOwner = certificate.user_uuid === requestingUserId;

      if (!isOwner && !isAdmin) {
        this.logger.warn('Certificate download failed: Insufficient permissions', {
          certificateId,
          requestingUserId,
          certificateOwnerId: certificate.user_uuid,
          isAdmin
        });
        res.status(403).json({
          success: false,
          message: 'Insufficient permissions to download this certificate',
          error: 'FORBIDDEN'
        });
        return;
      }

      // 3. Retrieve file from MinIO storage
      let fileBuffer: Buffer;
      try {
        fileBuffer = await this.minioService.downloadFile(certificate.file_path);
        this.logger.debug('File retrieved from MinIO for download', {
          certificateId,
          filePath: certificate.file_path,
          fileSize: fileBuffer.length
        });
      } catch (downloadError) {
        this.logger.error('Failed to retrieve certificate file from storage', {
          certificateId,
          filePath: certificate.file_path,
          error: downloadError.message
        });
        res.status(500).json({
          success: false,
          message: 'Failed to retrieve certificate file',
          error: 'STORAGE_ERROR'
        });
        return;
      }

      // 4. Set appropriate response headers
      const filename = certificate.original_filename || `certificate-${certificate.id}.pdf`;
      const contentType = certificate.content_type || 'application/octet-stream';

      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Length', fileBuffer.length);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      // 5. Log download event
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);

      try {
        await this.auditService.log({
          event_type: AuditEventType.DATA_DOWNLOAD,
          user_id: requestingUserId,
          user_email: certificate.user.email,
          ip_address: clientIp,
          user_agent: userAgent,
          resource: `/certificates/${certificateId}/download`,
          action: 'GET',
          status: 'SUCCESS',
          details: {
            operation: 'CERTIFICATE_DOWNLOADED',
            certificateId: certificate.id,
            courseName: certificate.course_name,
            originalFilename: certificate.original_filename,
            fileSize: certificate.file_size,
            downloadedBy: isOwner ? 'owner' : 'admin'
          },
          metadata: {
            filePath: certificate.file_path,
            contentType: certificate.content_type
          }
        });
      } catch (auditError) {
        this.logger.error('Failed to log certificate download event', auditError);
        // Don't fail the download for audit logging errors
      }

      // 6. Stream file to client
      this.logger.log('Certificate download completed successfully', {
        certificateId,
        requestingUserId,
        filename,
        fileSize: fileBuffer.length
      });

      res.send(fileBuffer);

    } catch (error) {
      this.logger.error('Certificate download error', {
        certificateId,
        error: error.message,
        stack: error.stack
      });

      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: 'Certificate download failed',
          error: 'INTERNAL_SERVER_ERROR'
        });
      }
    }
  }

  // ============================================================================
  // CERTIFICATE REVOCATION METHODS
  // ============================================================================

  /**
   * Revoke certificate
   * 
   * Marks a certificate as revoked, preventing future successful verifications.
   * Maintains audit trail and preserves original certificate file.
   * 
   * Process:
   * 1. Validate certificate existence
   * 2. Check if already revoked
   * 3. Update revocation status in database
   * 4. Log revocation event with reason
   * 5. Return revocation confirmation
   * 
   * @param certificateId - UUID of certificate to revoke
   * @param revokeCertificateDto - Revocation details including reason
   * @param req - Express request object for audit logging
   * @returns Promise with revocation result
   * 
   * @throws NotFoundException if certificate does not exist
   * @throws BadRequestException if certificate already revoked
   * @throws InternalServerErrorException if revocation fails
   */
  async revokeCertificate(
    certificateId: string,
    revokeCertificateDto: RevokeCertificateDto,
    req: Request,
  ): Promise<ApiResponseDto<void>> {
    this.logger.log(`Starting certificate revocation for ID: ${certificateId}`, {
      reason: revokeCertificateDto.reason
    });

    try {
      // 1. Validate certificate existence
      const certificate = await this.certificateRepository.findOne({
        where: { id: certificateId },
        relations: ['user']
      });

      if (!certificate) {
        this.logger.warn('Certificate revocation failed: Certificate not found', {
          certificateId
        });
        throw new NotFoundException('Certificate not found');
      }

      // 2. Check if already revoked
      if (certificate.revoked) {
        this.logger.warn('Certificate revocation failed: Certificate already revoked', {
          certificateId,
          revokedAt: certificate.revoked_at,
          previousReason: certificate.revoked_reason
        });
        throw new BadRequestException('Certificate is already revoked');
      }

      // 3. Get revoking user information
      const revokingUserId = this.getUserIdFromRequest(req);
      if (!revokingUserId) {
        throw new BadRequestException('Unable to identify revoking user');
      }

      // 4. Update revocation status in database
      const revokedAt = new Date();
      
      await this.certificateRepository.update(certificateId, {
        revoked: true,
        revoked_at: revokedAt,
        revoked_reason: revokeCertificateDto.reason,
        revoked_by: revokingUserId,
        updated_at: revokedAt
      });

      this.logger.log('Certificate revocation status updated in database', {
        certificateId,
        revokedBy: revokingUserId,
        revokedAt
      });

      // 5. Log revocation event with comprehensive details
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);

      try {
        await this.auditService.log({
          event_type: AuditEventType.DATA_ACCESS,
          user_id: revokingUserId,
          user_email: certificate.user.email,
          ip_address: clientIp,
          user_agent: userAgent,
          resource: `/certificates/${certificateId}/revoke`,
          action: 'POST',
          status: 'SUCCESS',
          details: {
            operation: 'CERTIFICATE_REVOKED',
            certificateId: certificate.id,
            courseName: certificate.course_name,
            certificateOwnerId: certificate.user_uuid,
            certificateOwnerEmail: certificate.user.email,
            revocationReason: revokeCertificateDto.reason,
            additionalDetails: revokeCertificateDto.additional_details,
            revokedAt: revokedAt.toISOString(),
            revokedBy: revokingUserId
          },
          metadata: {
            originalFilename: certificate.original_filename,
            filePath: certificate.file_path,
            publicKeyId: certificate.public_key_id,
            issuedDate: certificate.issued_date.toISOString()
          }
        });
      } catch (auditError) {
        this.logger.error('Failed to log certificate revocation event', auditError);
        // Don't fail the revocation for audit logging errors
      }

      // 6. Log successful revocation
      this.logger.log('Certificate revocation completed successfully', {
        certificateId,
        courseName: certificate.course_name,
        certificateOwnerId: certificate.user_uuid,
        revokedBy: revokingUserId,
        reason: revokeCertificateDto.reason
      });

      return ApiResponseDto.success(
        undefined,
        'Certificate revoked successfully'
      );

    } catch (error) {
      this.logger.error('Certificate revocation failed', {
        certificateId,
        reason: revokeCertificateDto.reason,
        error: error.message,
        stack: error.stack
      });

      // Re-throw known exceptions
      if (error instanceof NotFoundException || 
          error instanceof BadRequestException) {
        throw error;
      }

      // Wrap unknown errors
      throw new InternalServerErrorException('Certificate revocation failed');
    }
  }

  // ============================================================================
  // USER CERTIFICATE LISTING METHODS
  // ============================================================================

  /**
   * Get user certificates
   * 
   * Retrieves list of certificates belonging to a specific user.
   * Validates user authorization before returning certificate data.
   * 
   * Process:
   * 1. Validate user existence
   * 2. Check authorization (owner or admin)
   * 3. Query certificates from database
   * 4. Format response data
   * 5. Return certificate list
   * 
   * @param userId - UUID of user whose certificates to retrieve
   * @param req - Express request object for authorization
   * @returns Promise with list of user certificates
   * 
   * @throws NotFoundException if user does not exist
   * @throws UnauthorizedException if user lacks permission
   * @throws InternalServerErrorException if query fails
   */
  async getUserCertificates(
    userId: string,
    req: Request,
  ): Promise<ApiResponseDto<CertificateResponseDto[]>> {
    this.logger.log(`Retrieving certificates for user ID: ${userId}`);

    try {
      // 1. Validate user existence
      const user = await this.userRepository.findOne({
        where: { uuid: userId }
      });

      if (!user) {
        this.logger.warn('Get user certificates failed: User not found', {
          userId
        });
        throw new NotFoundException('User not found');
      }

      // 2. Check authorization (owner or admin)
      const requestingUserId = this.getUserIdFromRequest(req);
      const isAdmin = this.isAdmin(req);

      if (!requestingUserId) {
        throw new BadRequestException('Unable to identify requesting user');
      }

      const isOwner = userId === requestingUserId;

      if (!isOwner && !isAdmin) {
        this.logger.warn('Get user certificates failed: Insufficient permissions', {
          userId,
          requestingUserId,
          isAdmin
        });
        throw new BadRequestException('Insufficient permissions to view these certificates');
      }

      // 3. Query certificates from database
      const certificates = await this.certificateRepository.find({
        where: { user_uuid: userId },
        relations: ['user'],
        order: {
          created_at: 'DESC' // Most recent first
        }
      });

      this.logger.debug('Retrieved certificates from database', {
        userId,
        certificateCount: certificates.length
      });

      // 4. Format response data
      const certificateResponses: CertificateResponseDto[] = certificates.map(cert => ({
        id: cert.id,
        user_uuid: cert.user_uuid,
        user_email: cert.user.email,
        course_name: cert.course_name,
        description: cert.description,
        issued_date: cert.issued_date,
        file_path: isOwner || isAdmin ? cert.file_path : undefined, // Only show file path to authorized users
        original_filename: cert.original_filename,
        content_type: cert.content_type,
        file_size: cert.file_size,
        public_key_id: cert.public_key_id,
        revoked: cert.revoked,
        revoked_at: cert.revoked_at,
        revoked_reason: cert.revoked_reason,
        metadata: cert.metadata,
        created_at: cert.created_at,
        updated_at: cert.updated_at
      }));

      // 5. Log access event
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);

      try {
        await this.auditService.log({
          event_type: AuditEventType.DATA_ACCESS,
          user_id: requestingUserId,
          user_email: user.email,
          ip_address: clientIp,
          user_agent: userAgent,
          resource: `/certificates/user/${userId}`,
          action: 'GET',
          status: 'SUCCESS',
          details: {
            operation: 'CERTIFICATES_LISTED',
            targetUserId: userId,
            targetUserEmail: user.email,
            certificateCount: certificates.length,
            accessType: isOwner ? 'owner' : 'admin'
          },
          metadata: {
            certificateIds: certificates.map(cert => cert.id)
          }
        });
      } catch (auditError) {
        this.logger.error('Failed to log certificate listing event', auditError);
        // Don't fail the operation for audit logging errors
      }

      this.logger.log('User certificates retrieved successfully', {
        userId,
        requestingUserId,
        certificateCount: certificates.length,
        accessType: isOwner ? 'owner' : 'admin'
      });

      return ApiResponseDto.success(
        certificateResponses,
        `Retrieved ${certificates.length} certificate(s) for user`
      );

    } catch (error) {
      this.logger.error('Get user certificates failed', {
        userId,
        error: error.message,
        stack: error.stack
      });

      // Re-throw known exceptions
      if (error instanceof NotFoundException || 
          error instanceof BadRequestException) {
        throw error;
      }

      // Wrap unknown errors
      throw new InternalServerErrorException('Failed to retrieve user certificates');
    }
  }

  // ============================================================================
  // CERTIFICATE FILE GENERATION METHODS
  // ============================================================================

  /**
   * Genera contenuto TXT per certificato di test
   * 
   * Crea un file di testo con le informazioni del corso per testing.
   * Formato semplice e leggibile per verificare la funzionalità.
   * 
   * @param certificateData - Dati certificato per generare contenuto
   * @returns Contenuto TXT formattato
   */
  private generateCertificateTxt(certificateData: {
    studentEmail: string;
    courseName: string;
    issuedDate: string;
    certificateId: string;
    description?: string;
    organizationName: string;
    instructorName: string;
  }): string {
    const issuedDate = new Date(certificateData.issuedDate).toLocaleDateString('it-IT', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    return `
═══════════════════════════════════════════════════════════════════════════════
                           CERTIFICATO DI COMPLETAMENTO
═══════════════════════════════════════════════════════════════════════════════

Organizzazione: ${certificateData.organizationName}
Data di emissione: ${issuedDate}
ID Certificato: ${certificateData.certificateId}

───────────────────────────────────────────────────────────────────────────────

Il presente certificato attesta che

${certificateData.studentEmail}

ha completato con successo il corso:

"${certificateData.courseName}"

${certificateData.description ? `\nDescrizione corso:\n${certificateData.description}\n` : ''}

───────────────────────────────────────────────────────────────────────────────

Docente: ${certificateData.instructorName}
Organizzazione: ${certificateData.organizationName}

Questo certificato è stato generato automaticamente e contiene una firma 
digitale per verificarne l'autenticità.

Per verificare questo certificato, visita:
https://api.returncode.academy/certificates/${certificateData.certificateId}/verify

═══════════════════════════════════════════════════════════════════════════════
Generato il: ${new Date().toISOString()}
Sistema: ReturnCode Certificate Management System
═══════════════════════════════════════════════════════════════════════════════
`.trim();
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract client IP address from request
   * 
   * Handles various proxy configurations to determine actual client IP.
   * Used for audit logging and security monitoring.
   * 
   * @param req - Express request object
   * @returns Client IP address or 'Unknown'
   */
  private getClientIp(req: Request): string {
    const forwardedFor = req.headers['x-forwarded-for'] as string;
    const realIp = req.headers['x-real-ip'] as string;
    const remoteAddr = req.socket?.remoteAddress;
    
    if (forwardedFor) {
      return forwardedFor.split(',')[0].trim();
    }
    
    if (realIp) {
      return realIp;
    }
    
    if (remoteAddr) {
      return remoteAddr.replace(/^::ffff:/, '');
    }
    
    return 'Unknown';
  }

  /**
   * Extract user agent from request
   * 
   * @param req - Express request object
   * @returns User agent string or 'Unknown'
   */
  private getUserAgent(req: Request): string {
    return req.headers['user-agent'] || 'Unknown';
  }

  /**
   * Extract user ID from JWT token in request
   * 
   * @param req - Express request object with JWT payload
   * @returns User UUID from token or null
   */
  private getUserIdFromRequest(req: Request): string | null {
    const user = (req as any).user;
    return user?.uuid || user?.sub || null;
  }

  /**
   * Check if user has admin role
   * 
   * @param req - Express request object with JWT payload
   * @returns True if user is admin
   */
  private isAdmin(req: Request): boolean {
    const user = (req as any).user;
    return user?.role === 'admin';
  }
}