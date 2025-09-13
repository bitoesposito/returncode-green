import { 
  Controller, 
  Post, 
  Get, 
  Param, 
  Body, 
  UseGuards, 
  Req, 
  Res,
  ParseUUIDPipe,
  HttpStatus,
  BadRequestException
} from '@nestjs/common';
import { Request, Response } from 'express';

// Local imports
import { CertificatesService } from './certificates.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles, UserRole } from '../auth/auth.interface';
import { ApiResponseDto } from '../common/common.interface';
import { 
  GenerateCertificateDto, 
  CertificateResponseDto, 
  VerificationResultDto,
  RevokeCertificateDto,
  CertificateListQueryDto,
  CertificateListResponseDto
} from './dto/certificate.dto';

/**
 * Certificates Controller
 * 
 * Handles HTTP requests for certificate operations including generation,
 * verification, download, and revocation. Implements RESTful API endpoints
 * with proper authentication, authorization, and error handling.
 * 
 * Endpoints:
 * - POST /certificates - Generate new certificate (admin only)
 * - GET /certificates/:id/verify - Verify certificate (public)
 * - GET /certificates/:id/download - Download certificate (authenticated)
 * - POST /certificates/:id/revoke - Revoke certificate (admin only)
 * - GET /certificates/user/:userId - List user certificates (authenticated)
 * 
 * Security:
 * - JWT authentication for protected endpoints
 * - Role-based access control for administrative functions
 * - Input validation and sanitization
 * - Audit logging for all operations
 * 
 * File Upload:
 * - Supports PDF and JSON certificate files
 * - File size limits and type validation
 * - Secure file handling and storage
 */
@Controller('certificates')
export class CertificatesController {
  constructor(
    private readonly certificatesService: CertificatesService,
  ) {}

  // ============================================================================
  // CERTIFICATE GENERATION ENDPOINT
  // ============================================================================

  /**
   * Generate new certificate
   * 
   * Creates a new digital certificate for a user upon course completion.
   * Generates PDF automatically based on course data. Requires admin role.
   * 
   * @param generateCertificateDto - Certificate generation data
   * @param req - Express request object for audit logging
   * @returns Promise with certificate generation result
   * 
   * @example
   * POST /certificates
   * Content-Type: application/json
   * Authorization: Bearer <jwt-token>
   * 
   * {
   *   "user_uuid": "123e4567-e89b-12d3-a456-426614174000",
   *   "course_name": "Advanced TypeScript Development",
   *   "description": "Comprehensive course covering advanced TypeScript concepts"
   * }
   */
  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.admin)
  async generateCertificate(
    @Body() generateCertificateDto: GenerateCertificateDto,
    @Req() req: Request,
  ): Promise<ApiResponseDto<CertificateResponseDto>> {
    return this.certificatesService.generateCertificate(
      generateCertificateDto,
      req
    );
  }

  // ============================================================================
  // CERTIFICATE VERIFICATION ENDPOINT
  // ============================================================================

  /**
   * Verify certificate authenticity
   * 
   * Public endpoint for verifying certificate authenticity using
   * cryptographic signature verification. No authentication required.
   * 
   * @param certificateId - UUID of certificate to verify
   * @returns Promise with verification result
   * 
   * @example
   * GET /certificates/123e4567-e89b-12d3-a456-426614174000/verify
   * 
   * Response:
   * {
   *   "success": true,
   *   "data": {
   *     "valid": true,
   *     "certificate": {
   *       "id": "123e4567-e89b-12d3-a456-426614174000",
   *       "user_email": "user@example.com",
   *       "course_name": "Advanced TypeScript Development",
   *       "issued_date": "2024-01-15T10:30:00.000Z",
   *       "revoked": false
   *     },
   *     "verified_at": "2024-01-15T15:45:00.000Z"
   *   }
   * }
   */
  @Get(':id/verify')
  async verifyCertificate(
    @Param('id', ParseUUIDPipe) certificateId: string,
  ): Promise<ApiResponseDto<VerificationResultDto>> {
    // Implementation will be added in service task
    return this.certificatesService.verifyCertificate(certificateId);
  }

  // ============================================================================
  // CERTIFICATE DOWNLOAD ENDPOINT
  // ============================================================================

  /**
   * Download certificate file
   * 
   * Authenticated endpoint for downloading certificate files.
   * Users can only download their own certificates unless they are admin.
   * 
   * @param certificateId - UUID of certificate to download
   * @param req - Express request object for user identification
   * @param res - Express response object for file streaming
   * 
   * @example
   * GET /certificates/123e4567-e89b-12d3-a456-426614174000/download
   * Authorization: Bearer <jwt-token>
   * 
   * Response: Certificate file with appropriate headers
   */
  @Get(':id/download')
  @UseGuards(JwtAuthGuard)
  async downloadCertificate(
    @Param('id', ParseUUIDPipe) certificateId: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    // Implementation will be added in service task
    return this.certificatesService.downloadCertificate(
      certificateId,
      req,
      res
    );
  }

  // ============================================================================
  // CERTIFICATE REVOCATION ENDPOINT
  // ============================================================================

  /**
   * Revoke certificate
   * 
   * Admin-only endpoint for revoking certificates when necessary.
   * Marks certificate as invalid for future verifications.
   * 
   * @param certificateId - UUID of certificate to revoke
   * @param revokeCertificateDto - Revocation details including reason
   * @param req - Express request object for audit logging
   * @returns Promise with revocation result
   * 
   * @example
   * POST /certificates/123e4567-e89b-12d3-a456-426614174000/revoke
   * Authorization: Bearer <jwt-token>
   * 
   * {
   *   "reason": "Certificate issued in error"
   * }
   */
  @Post(':id/revoke')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.admin)
  async revokeCertificate(
    @Param('id', ParseUUIDPipe) certificateId: string,
    @Body() revokeCertificateDto: RevokeCertificateDto,
    @Req() req: Request,
  ): Promise<ApiResponseDto<void>> {
    // Implementation will be added in service task
    return this.certificatesService.revokeCertificate(
      certificateId,
      revokeCertificateDto,
      req
    );
  }

  // ============================================================================
  // USER CERTIFICATES LISTING ENDPOINT
  // ============================================================================

  /**
   * List user certificates
   * 
   * Authenticated endpoint for listing certificates belonging to a user.
   * Users can only list their own certificates unless they are admin.
   * 
   * @param userId - UUID of user whose certificates to list
   * @param req - Express request object for authorization
   * @returns Promise with list of user certificates
   * 
   * @example
   * GET /certificates/user/123e4567-e89b-12d3-a456-426614174000
   * Authorization: Bearer <jwt-token>
   * 
   * Response:
   * {
   *   "success": true,
   *   "data": [
   *     {
   *       "id": "cert-uuid-1",
   *       "course_name": "TypeScript Fundamentals",
   *       "issued_date": "2024-01-10T10:00:00.000Z",
   *       "revoked": false
   *     },
   *     {
   *       "id": "cert-uuid-2",
   *       "course_name": "Advanced Node.js",
   *       "issued_date": "2024-01-15T14:30:00.000Z",
   *       "revoked": false
   *     }
   *   ]
   * }
   */
  @Get('user/:userId')
  @UseGuards(JwtAuthGuard)
  async getUserCertificates(
    @Param('userId', ParseUUIDPipe) userId: string,
    @Req() req: Request,
  ): Promise<ApiResponseDto<CertificateResponseDto[]>> {
    // Implementation will be added in service task
    return this.certificatesService.getUserCertificates(userId, req);
  }
}