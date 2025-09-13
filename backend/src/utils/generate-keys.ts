#!/usr/bin/env ts-node

/**
 * Key Generation Script for Digital Certificate System
 * 
 * This TypeScript script generates RSA and ECDSA key pairs for the digital certificate
 * system. It creates both private and public keys with proper naming and
 * directory structure for development and production use.
 * 
 * Usage:
 *   npx ts-node src/utils/generate-keys.ts [key-type] [key-id]
 * 
 * Examples:
 *   npx ts-node src/utils/generate-keys.ts rsa rsa-2024-01
 *   npx ts-node src/utils/generate-keys.ts ecdsa ecdsa-2024-01
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// Configuration
const KEYS_BASE_DIR = path.join(__dirname, '..', '..', 'keys');
const PRIVATE_KEYS_DIR = path.join(KEYS_BASE_DIR, 'private');
const PUBLIC_KEYS_DIR = path.join(KEYS_BASE_DIR, 'public');

// Default values
const DEFAULT_KEY_TYPE = 'rsa';
const DEFAULT_KEY_ID = `rsa-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;

/**
 * Create directory structure for keys
 */
function createDirectories(): void {
  console.log('Creating key directories...');
  
  // Create base keys directory
  if (!fs.existsSync(KEYS_BASE_DIR)) {
    fs.mkdirSync(KEYS_BASE_DIR, { recursive: true });
    console.log(`✓ Created directory: ${KEYS_BASE_DIR}`);
  }
  
  // Create private keys directory
  if (!fs.existsSync(PRIVATE_KEYS_DIR)) {
    fs.mkdirSync(PRIVATE_KEYS_DIR, { recursive: true });
    console.log(`✓ Created directory: ${PRIVATE_KEYS_DIR}`);
  }
  
  // Create public keys directory
  if (!fs.existsSync(PUBLIC_KEYS_DIR)) {
    fs.mkdirSync(PUBLIC_KEYS_DIR, { recursive: true });
    console.log(`✓ Created directory: ${PUBLIC_KEYS_DIR}`);
  }
}

/**
 * Generate RSA key pair
 */
function generateRSAKeyPair(keyId: string): { publicKey: string; privateKey: string } {
  console.log(`Generating RSA 2048-bit key pair for ID: ${keyId}`);
  
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  return { publicKey, privateKey };
}

/**
 * Generate ECDSA key pair
 */
function generateECDSAKeyPair(keyId: string): { publicKey: string; privateKey: string } {
  console.log(`Generating ECDSA P-256 key pair for ID: ${keyId}`);
  
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // P-256
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  return { publicKey, privateKey };
}

/**
 * Save key pair to files
 */
function saveKeyPair(keyId: string, publicKey: string, privateKey: string): void {
  const privateKeyPath = path.join(PRIVATE_KEYS_DIR, `${keyId}.pem`);
  const publicKeyPath = path.join(PUBLIC_KEYS_DIR, `${keyId}.pub`);
  
  // Check if keys already exist
  if (fs.existsSync(privateKeyPath) || fs.existsSync(publicKeyPath)) {
    console.error(`❌ Error: Keys for ID '${keyId}' already exist!`);
    console.error(`   Private key: ${privateKeyPath}`);
    console.error(`   Public key: ${publicKeyPath}`);
    console.error('   Use a different key ID or remove existing keys first.');
    process.exit(1);
  }
  
  // Save private key with restricted permissions
  fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
  console.log(`✓ Private key saved: ${privateKeyPath} (permissions: 600)`);
  
  // Save public key with readable permissions
  fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });
  console.log(`✓ Public key saved: ${publicKeyPath} (permissions: 644)`);
}

/**
 * Generate key information file
 */
function generateKeyInfo(keyId: string, keyType: string): void {
  const keyInfo = {
    key_id: keyId,
    algorithm: keyType.toUpperCase(),
    key_size: keyType === 'rsa' ? 2048 : 256,
    created_at: new Date().toISOString(),
    active: true,
    description: `${keyType.toUpperCase()} key pair generated for digital certificate signing`,
    usage: 'Digital certificate signing and verification'
  };
  
  const infoPath = path.join(KEYS_BASE_DIR, `${keyId}.json`);
  fs.writeFileSync(infoPath, JSON.stringify(keyInfo, null, 2));
  console.log(`✓ Key information saved: ${infoPath}`);
}

/**
 * Main function
 */
function main(): void {
  const args = process.argv.slice(2);
  
  // Parse arguments
  const keyType = args[0] || DEFAULT_KEY_TYPE;
  const keyId = args[1] || DEFAULT_KEY_ID;
  
  // Validate key type
  if (!['rsa', 'ecdsa'].includes(keyType.toLowerCase())) {
    console.error(`❌ Error: Invalid key type '${keyType}'. Must be 'rsa' or 'ecdsa'.`);
    process.exit(1);
  }
  
  // Validate key ID format
  if (!/^[a-zA-Z0-9\-_]+$/.test(keyId)) {
    console.error(`❌ Error: Invalid key ID '${keyId}'. Must contain only letters, numbers, hyphens, and underscores.`);
    process.exit(1);
  }
  
  console.log('🔐 Digital Certificate Key Generation');
  console.log('=====================================');
  console.log(`Key Type: ${keyType.toUpperCase()}`);
  console.log(`Key ID: ${keyId}`);
  console.log('');
  
  try {
    // Create directory structure
    createDirectories();
    
    // Generate key pair
    let keyPair: { publicKey: string; privateKey: string };
    if (keyType.toLowerCase() === 'rsa') {
      keyPair = generateRSAKeyPair(keyId);
    } else {
      keyPair = generateECDSAKeyPair(keyId);
    }
    
    // Save keys to files
    saveKeyPair(keyId, keyPair.publicKey, keyPair.privateKey);
    
    // Generate key information file
    generateKeyInfo(keyId, keyType);
    
    console.log('');
    console.log('✅ Key generation completed successfully!');
    console.log('');
    console.log('Next steps:');
    console.log(`1. Set CRYPTO_CURRENT_KEY_ID=${keyId} in your environment variables`);
    console.log('2. Ensure proper file permissions are maintained');
    console.log('3. Back up your private key securely');
    console.log('4. Test the keys with the certificate system');
    console.log('');
    console.log('⚠️  Security reminders:');
    console.log('- Never commit private keys to version control');
    console.log('- Store private keys in secure, encrypted storage');
    console.log('- Regularly rotate keys according to your security policy');
    console.log('- Monitor key usage through audit logs');
    
  } catch (error) {
    console.error('❌ Error generating keys:', error.message);
    process.exit(1);
  }
}

// Run the script
if (require.main === module) {
  main();
}