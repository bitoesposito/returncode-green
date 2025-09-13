import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// Local imports
import { 
  KeyAlgorithm, 
  SignatureParams, 
  VerificationParams,
  CryptographicKey 
} from '../interfaces/certificate.interface';

/**
 * Crypto Service
 * 
 * Handles all cryptographic operations for the certificate system including
 * hash calculation, digital signature generation, and signature verification.
 * Supports both RSA and ECDSA algorithms with secure key management.
 * 
 * Features:
 * - SHA256 hash calculation for file integrity
 * - RSA and ECDSA digital signature generation
 * - Signature verification with public keys
 * - Secure key loading and management
 * - Key rotation support with multiple key identifiers
 * 
 * Security:
 * - Uses Node.js crypto module for cryptographic operations
 * - Supports RSA-PSS and ECDSA signature algorithms
 * - Secure key storage with proper file permissions
 * - Key validation and error handling
 * - Audit logging for key usage
 * 
 * Key Management:
 * - Private keys for signature generation
 * - Public keys for signature verification
 * - Key rotation with version identifiers
 * - Environment-based key configuration
 */
@Injectable()
export class CryptoService {
  private readonly logger = new Logger(CryptoService.name);
  private readonly keysDirectory: string;
  private readonly currentKeyId: string;

  constructor(private readonly configService: ConfigService) {
    // Initialize key management configuration
    this.keysDirectory = path.resolve(
      this.configService.get<string>('CRYPTO_KEYS_PATH') || 'keys'
    );
    this.currentKeyId = this.configService.get<string>('CRYPTO_CURRENT_KEY_ID') || 'rsa-2024-01';
    
    this.logger.log(`Crypto service initialized with keys directory: ${this.keysDirectory}`);
    this.logger.log(`Current key ID: ${this.currentKeyId}`);
    
    // Ensure keys directory exists
    this.ensureKeysDirectory();
  }

  // ============================================================================
  // HASH CALCULATION METHODS
  // ============================================================================

  /**
   * Calculate SHA256 hash of buffer content
   * 
   * Generates a SHA256 hash of the provided buffer for file integrity
   * verification and digital signature generation.
   * 
   * @param buffer - Buffer containing data to hash
   * @returns SHA256 hash as hexadecimal string
   * 
   * @throws Error if hash calculation fails
   * 
   * @example
   * const fileBuffer = fs.readFileSync('certificate.pdf');
   * const hash = this.calculateSHA256(fileBuffer);
   * // Returns: "a1b2c3d4e5f6..."
   */
  calculateSHA256(buffer: Buffer): string {
    try {
      const hash = crypto.createHash('sha256');
      hash.update(buffer);
      const result = hash.digest('hex');
      
      this.logger.debug(`SHA256 hash calculated successfully, length: ${result.length}`);
      return result;
    } catch (error) {
      this.logger.error('Failed to calculate SHA256 hash', error);
      throw new Error(`Hash calculation failed: ${error.message}`);
    }
  }

  // ============================================================================
  // DIGITAL SIGNATURE METHODS
  // ============================================================================

  /**
   * Generate digital signature for hash
   * 
   * Creates a digital signature for the provided hash using the current
   * private key. Supports both RSA and ECDSA algorithms.
   * 
   * @param hash - SHA256 hash to sign
   * @param keyId - Optional key identifier (uses current if not provided)
   * @returns Base64-encoded digital signature
   * 
   * @throws Error if signature generation fails
   * 
   * @example
   * const hash = "a1b2c3d4e5f6...";
   * const signature = await this.signHash(hash);
   * // Returns: "MEUCIQDx1y2z3..."
   */
  async signHash(hash: string, keyId?: string): Promise<string> {
    try {
      const activeKeyId = keyId || this.currentKeyId;
      const privateKey = await this.loadPrivateKey(activeKeyId);
      const algorithm = this.getKeyAlgorithm(activeKeyId);
      
      this.logger.debug(`Signing hash with key ID: ${activeKeyId}, algorithm: ${algorithm}`);
      
      const signatureParams: SignatureParams = {
        hash,
        private_key: privateKey,
        algorithm,
        key_id: activeKeyId,
      };
      
      const signature = this.generateSignature(signatureParams);
      
      this.logger.debug('Digital signature generated successfully');
      return signature;
    } catch (error) {
      this.logger.error('Failed to generate digital signature', error);
      throw new Error(`Signature generation failed: ${error.message}`);
    }
  }

  /**
   * Verify digital signature
   * 
   * Verifies a digital signature against the original hash using the
   * corresponding public key. Supports both RSA and ECDSA algorithms.
   * 
   * @param hash - Original SHA256 hash
   * @param signature - Base64-encoded signature to verify
   * @param keyId - Key identifier for public key lookup
   * @returns True if signature is valid, false otherwise
   * 
   * @throws Error if verification process fails
   * 
   * @example
   * const isValid = await this.verifySignature(hash, signature, "rsa-2024-01");
   * // Returns: true or false
   */
  async verifySignature(hash: string, signature: string, keyId: string): Promise<boolean> {
    try {
      const publicKey = await this.loadPublicKey(keyId);
      const algorithm = this.getKeyAlgorithm(keyId);
      
      this.logger.debug(`Verifying signature with key ID: ${keyId}, algorithm: ${algorithm}`);
      
      const verificationParams: VerificationParams = {
        hash,
        signature,
        public_key: publicKey,
        algorithm,
      };
      
      const isValid = this.performSignatureVerification(verificationParams);
      
      this.logger.debug(`Signature verification result: ${isValid}`);
      return isValid;
    } catch (error) {
      this.logger.error('Failed to verify digital signature', error);
      throw new Error(`Signature verification failed: ${error.message}`);
    }
  }

  // ============================================================================
  // KEY MANAGEMENT METHODS
  // ============================================================================

  /**
   * Load private key from file system
   * 
   * Loads the private key for the specified key identifier from secure storage.
   * Used for digital signature generation.
   * 
   * @param keyId - Key identifier
   * @returns Private key in PEM format
   * 
   * @throws Error if key loading fails
   */
  async loadPrivateKey(keyId: string): Promise<string> {
    try {
      const keyPath = path.join(this.keysDirectory, 'private', `${keyId}.pem`);
      
      if (!fs.existsSync(keyPath)) {
        throw new Error(`Private key not found: ${keyPath}`);
      }
      
      const privateKey = fs.readFileSync(keyPath, 'utf8');
      
      // Validate key format
      if (!privateKey.includes('BEGIN PRIVATE KEY') && !privateKey.includes('BEGIN RSA PRIVATE KEY')) {
        throw new Error('Invalid private key format');
      }
      
      this.logger.debug(`Private key loaded successfully for key ID: ${keyId}`);
      return privateKey;
    } catch (error) {
      this.logger.error(`Failed to load private key for key ID: ${keyId}`, error);
      throw new Error(`Private key loading failed: ${error.message}`);
    }
  }

  /**
   * Load public key from file system
   * 
   * Loads the public key for the specified key identifier from storage.
   * Used for digital signature verification.
   * 
   * @param keyId - Key identifier
   * @returns Public key in PEM format
   * 
   * @throws Error if key loading fails
   */
  async loadPublicKey(keyId: string): Promise<string> {
    try {
      const keyPath = path.join(this.keysDirectory, 'public', `${keyId}.pub`);
      
      if (!fs.existsSync(keyPath)) {
        throw new Error(`Public key not found: ${keyPath}`);
      }
      
      const publicKey = fs.readFileSync(keyPath, 'utf8');
      
      // Validate key format
      if (!publicKey.includes('BEGIN PUBLIC KEY') && !publicKey.includes('BEGIN RSA PUBLIC KEY')) {
        throw new Error('Invalid public key format');
      }
      
      this.logger.debug(`Public key loaded successfully for key ID: ${keyId}`);
      return publicKey;
    } catch (error) {
      this.logger.error(`Failed to load public key for key ID: ${keyId}`, error);
      throw new Error(`Public key loading failed: ${error.message}`);
    }
  }

  /**
   * Get current active key identifier
   * 
   * @returns Current key ID used for new signatures
   */
  getCurrentKeyId(): string {
    return this.currentKeyId;
  }

  /**
   * List available key identifiers
   * 
   * @returns Array of available key IDs
   */
  async getAvailableKeyIds(): Promise<string[]> {
    try {
      const publicKeysPath = path.join(this.keysDirectory, 'public');
      
      if (!fs.existsSync(publicKeysPath)) {
        return [];
      }
      
      const files = fs.readdirSync(publicKeysPath);
      const keyIds = files
        .filter(file => file.endsWith('.pub'))
        .map(file => file.replace('.pub', ''));
      
      this.logger.debug(`Available key IDs: ${keyIds.join(', ')}`);
      return keyIds;
    } catch (error) {
      this.logger.error('Failed to list available key IDs', error);
      return [];
    }
  }

  // ============================================================================
  // PRIVATE HELPER METHODS
  // ============================================================================

  /**
   * Generate signature using specified parameters
   * 
   * @param params - Signature generation parameters
   * @returns Base64-encoded signature
   */
  private generateSignature(params: SignatureParams): string {
    const { hash, private_key, algorithm } = params;
    
    let signature: Buffer;
    
    if (algorithm === KeyAlgorithm.RSA) {
      // Use RSA-PSS for RSA keys
      const sign = crypto.createSign('RSA-SHA256');
      sign.update(hash, 'hex');
      signature = sign.sign({
        key: private_key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      });
    } else if (algorithm === KeyAlgorithm.ECDSA) {
      // Use ECDSA for elliptic curve keys
      const sign = crypto.createSign('SHA256');
      sign.update(hash, 'hex');
      signature = sign.sign(private_key);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    return signature.toString('base64');
  }

  /**
   * Perform signature verification using specified parameters
   * 
   * @param params - Verification parameters
   * @returns True if signature is valid
   */
  private performSignatureVerification(params: VerificationParams): boolean {
    const { hash, signature, public_key, algorithm } = params;
    
    const signatureBuffer = Buffer.from(signature, 'base64');
    
    if (algorithm === KeyAlgorithm.RSA) {
      // Verify RSA-PSS signature
      const verify = crypto.createVerify('RSA-SHA256');
      verify.update(hash, 'hex');
      return verify.verify({
        key: public_key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      }, signatureBuffer);
    } else if (algorithm === KeyAlgorithm.ECDSA) {
      // Verify ECDSA signature
      const verify = crypto.createVerify('SHA256');
      verify.update(hash, 'hex');
      return verify.verify(public_key, signatureBuffer);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * Determine key algorithm from key identifier
   * 
   * @param keyId - Key identifier
   * @returns Key algorithm
   */
  private getKeyAlgorithm(keyId: string): KeyAlgorithm {
    if (keyId.startsWith('rsa-')) {
      return KeyAlgorithm.RSA;
    } else if (keyId.startsWith('ecdsa-')) {
      return KeyAlgorithm.ECDSA;
    } else {
      // Default to RSA for backward compatibility
      return KeyAlgorithm.RSA;
    }
  }

  /**
   * Ensure keys directory structure exists
   */
  private ensureKeysDirectory(): void {
    try {
      const privateKeysPath = path.join(this.keysDirectory, 'private');
      const publicKeysPath = path.join(this.keysDirectory, 'public');
      
      if (!fs.existsSync(this.keysDirectory)) {
        fs.mkdirSync(this.keysDirectory, { recursive: true });
        this.logger.log(`Created keys directory: ${this.keysDirectory}`);
      }
      
      if (!fs.existsSync(privateKeysPath)) {
        fs.mkdirSync(privateKeysPath, { recursive: true });
        this.logger.log(`Created private keys directory: ${privateKeysPath}`);
      }
      
      if (!fs.existsSync(publicKeysPath)) {
        fs.mkdirSync(publicKeysPath, { recursive: true });
        this.logger.log(`Created public keys directory: ${publicKeysPath}`);
      }
    } catch (error) {
      this.logger.error('Failed to create keys directory structure', error);
      throw new Error(`Keys directory setup failed: ${error.message}`);
    }
  }
}