import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';

// Local imports
import { CertificatesController } from './certificates.controller';
import { CertificatesService } from './certificates.service';
import { CryptoService } from './services/crypto.service';
import { PdfService } from './services/pdf.service';
import { Certificate } from './entities/certificate.entity';
import { User } from '../auth/entities/user.entity';
import { MinioModule } from '../common/modules/minio.module';
import { CommonModule } from '../common/modules/common.module';

/**
 * Certificates Module
 * 
 * Provides digital certificate functionality for post-course certification.
 * Handles certificate generation, verification, and management using
 * cryptographic signatures without blockchain technology.
 * 
 * Features:
 * - Certificate generation with digital signatures
 * - Public certificate verification
 * - Certificate download and management
 * - Certificate revocation system
 * - Integration with existing MinIO and audit services
 * 
 * Dependencies:
 * - TypeOrmModule: For Certificate entity persistence
 * - ConfigModule: For cryptographic key configuration
 * - MinioModule: For certificate file storage
 * - CommonModule: For audit logging and shared services
 * 
 * Security:
 * - RSA/ECDSA digital signatures for authenticity
 * - Secure key management via ConfigService
 * - Role-based access control for administrative functions
 * - Comprehensive audit logging for all operations
 */
@Module({
  imports: [
    // Database integration
    TypeOrmModule.forFeature([Certificate, User]),
    
    // Configuration for key management
    ConfigModule,
    
    // File storage integration
    MinioModule,
    
    // Common services (audit, etc.)
    CommonModule,
  ],
  
  controllers: [
    CertificatesController,
  ],
  
  providers: [
    CertificatesService,
    CryptoService,
    PdfService,
  ],
  
  exports: [
    CertificatesService,
    CryptoService,
    PdfService,
  ],
})
export class CertificatesModule {}