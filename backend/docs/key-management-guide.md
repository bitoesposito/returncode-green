# Digital Certificate System - Key Management Guide

## Overview

This guide covers the secure generation, storage, and management of cryptographic keys for the Digital Certificate System. Proper key management is critical for maintaining the security and integrity of the certificate system.

## Table of Contents

1. [Key Generation](#key-generation)
2. [Key Storage](#key-storage)
3. [Key Rotation](#key-rotation)
4. [Security Best Practices](#security-best-practices)
5. [Production Deployment](#production-deployment)
6. [Backup and Recovery](#backup-and-recovery)
7. [Monitoring and Auditing](#monitoring-and-auditing)
8. [Troubleshooting](#troubleshooting)

---

## Key Generation

### Development Environment

For development and testing, use the built-in key generation utility:

```bash
# Generate RSA 2048-bit key pair
npm run generate-keys rsa rsa-2024-01

# Generate ECDSA P-256 key pair
npm run generate-keys ecdsa ecdsa-2024-01

# Generate with default settings (RSA with current date)
npm run generate-keys
```

### Production Environment

For production, generate keys using secure methods:

#### Option 1: OpenSSL (Recommended)

```bash
# Create keys directory
mkdir -p keys/private keys/public

# Generate RSA 2048-bit private key
openssl genpkey -algorithm RSA -pkcs8 -out keys/private/rsa-prod-2024-01.pem -pkcs8 -aes256

# Extract public key
openssl pkey -in keys/private/rsa-prod-2024-01.pem -pubout -out keys/public/rsa-prod-2024-01.pub

# Generate ECDSA P-256 private key
openssl genpkey -algorithm EC -pkcs8 -out keys/private/ecdsa-prod-2024-01.pem -pkcs8 -aes256 -param_enc named_curve -pkeyopt ec_paramgen_curve:prime256v1

# Extract ECDSA public key
openssl pkey -in keys/private/ecdsa-prod-2024-01.pem -pubout -out keys/public/ecdsa-prod-2024-01.pub
```

#### Option 2: Hardware Security Module (HSM)

For maximum security, use an HSM:

```bash
# Example with AWS CloudHSM
aws cloudhsmv2 create-cluster --hsm-type hsm1.medium

# Example with Azure Key Vault
az keyvault key create --vault-name MyKeyVault --name certificate-signing-key --kty RSA --size 2048

# Example with Google Cloud KMS
gcloud kms keys create certificate-signing-key --location global --keyring certificate-keyring --purpose asymmetric-signing --default-algorithm rsa-sign-pss-2048-sha256
```

### Key Requirements

#### RSA Keys
- **Minimum size**: 2048 bits
- **Recommended size**: 3072 bits or 4096 bits for high security
- **Algorithm**: RSA-PSS with SHA-256
- **Format**: PKCS#8 (private), SPKI (public)

#### ECDSA Keys
- **Curve**: P-256 (prime256v1) minimum
- **Recommended curves**: P-384 or P-521 for high security
- **Algorithm**: ECDSA with SHA-256
- **Format**: PKCS#8 (private), SPKI (public)

---

## Key Storage

### File System Storage (Development)

```bash
# Directory structure
keys/
├── private/
│   ├── rsa-2024-01.pem      # Private key (600 permissions)
│   └── ecdsa-2024-01.pem    # Private key (600 permissions)
├── public/
│   ├── rsa-2024-01.pub      # Public key (644 permissions)
│   └── ecdsa-2024-01.pub    # Public key (644 permissions)
└── rsa-2024-01.json         # Key metadata

# Set proper permissions
chmod 600 keys/private/*.pem
chmod 644 keys/public/*.pub
chmod 755 keys/
```

### Secure Storage (Production)

#### Option 1: Encrypted File System

```bash
# Create encrypted partition
cryptsetup luksFormat /dev/sdb1
cryptsetup luksOpen /dev/sdb1 secure-keys

# Mount encrypted filesystem
mkfs.ext4 /dev/mapper/secure-keys
mount /dev/mapper/secure-keys /opt/certificate-keys

# Set ownership and permissions
chown -R certificate-app:certificate-app /opt/certificate-keys
chmod 700 /opt/certificate-keys
```

#### Option 2: Key Management Service (KMS)

**AWS KMS Integration:**
```typescript
// Example KMS integration
import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';

const kmsClient = new KMSClient({ region: 'us-east-1' });

async function signWithKMS(keyId: string, message: Buffer): Promise<string> {
  const command = new SignCommand({
    KeyId: keyId,
    Message: message,
    SigningAlgorithm: 'RSASSA_PSS_SHA_256'
  });
  
  const response = await kmsClient.send(command);
  return Buffer.from(response.Signature!).toString('base64');
}
```

**Azure Key Vault Integration:**
```typescript
// Example Azure Key Vault integration
import { CryptographyClient } from '@azure/keyvault-keys';

const cryptoClient = new CryptographyClient(keyVaultKey, credential);

async function signWithKeyVault(data: Buffer): Promise<string> {
  const signResult = await cryptoClient.sign('PS256', data);
  return Buffer.from(signResult.result).toString('base64');
}
```

### Environment Configuration

```bash
# Development
CRYPTO_KEYS_PATH=keys
CRYPTO_CURRENT_KEY_ID=rsa-2024-01

# Production with file system
CRYPTO_KEYS_PATH=/opt/certificate-keys
CRYPTO_CURRENT_KEY_ID=rsa-prod-2024-01

# Production with KMS
CRYPTO_USE_KMS=true
CRYPTO_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
CRYPTO_KMS_REGION=us-east-1
```

---

## Key Rotation

### Rotation Schedule

- **Development**: Every 6 months
- **Production**: Every 12 months or as required by security policy
- **Emergency**: Immediately upon suspected compromise

### Rotation Process

#### 1. Generate New Key Pair

```bash
# Generate new key with incremented version
npm run generate-keys rsa rsa-2024-02

# Or for production
openssl genpkey -algorithm RSA -pkcs8 -out keys/private/rsa-2024-02.pem -pkcs8 -aes256
openssl pkey -in keys/private/rsa-2024-02.pem -pubout -out keys/public/rsa-2024-02.pub
```

#### 2. Update Configuration

```bash
# Update environment variable
CRYPTO_CURRENT_KEY_ID=rsa-2024-02
```

#### 3. Deploy New Configuration

```bash
# Restart application with new key
systemctl restart certificate-service

# Verify new key is active
curl -X GET http://localhost:3000/certificates/health
```

#### 4. Maintain Old Keys

Keep old keys for verification of existing certificates:

```bash
# Keep old keys for verification
# DO NOT DELETE old public keys
# Old private keys can be archived securely
```

#### 5. Update Documentation

```bash
# Update key inventory
echo "rsa-2024-02,RSA,2048,$(date),active" >> keys/key-inventory.csv
echo "rsa-2024-01,RSA,2048,$(date -d '1 year ago'),archived" >> keys/key-inventory.csv
```

### Automated Rotation

```bash
#!/bin/bash
# automated-key-rotation.sh

# Configuration
CURRENT_DATE=$(date +%Y-%m)
NEW_KEY_ID="rsa-${CURRENT_DATE}"
KEYS_PATH="/opt/certificate-keys"

# Generate new key pair
openssl genpkey -algorithm RSA -pkcs8 -out "${KEYS_PATH}/private/${NEW_KEY_ID}.pem" -pkcs8
openssl pkey -in "${KEYS_PATH}/private/${NEW_KEY_ID}.pem" -pubout -out "${KEYS_PATH}/public/${NEW_KEY_ID}.pub"

# Set permissions
chmod 600 "${KEYS_PATH}/private/${NEW_KEY_ID}.pem"
chmod 644 "${KEYS_PATH}/public/${NEW_KEY_ID}.pub"

# Update configuration
sed -i "s/CRYPTO_CURRENT_KEY_ID=.*/CRYPTO_CURRENT_KEY_ID=${NEW_KEY_ID}/" /etc/certificate-service/.env

# Restart service
systemctl restart certificate-service

# Verify rotation
if systemctl is-active --quiet certificate-service; then
    echo "Key rotation successful: ${NEW_KEY_ID}"
    # Send notification
    curl -X POST https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK \
         -H 'Content-type: application/json' \
         --data "{\"text\":\"Certificate key rotation completed: ${NEW_KEY_ID}\"}"
else
    echo "Key rotation failed"
    exit 1
fi
```

---

## Security Best Practices

### Key Generation Security

1. **Use Cryptographically Secure Random Number Generators**
   ```bash
   # Ensure sufficient entropy
   cat /proc/sys/kernel/random/entropy_avail
   # Should be > 1000
   ```

2. **Generate Keys on Secure Systems**
   - Use air-gapped systems for production key generation
   - Verify system integrity before key generation
   - Use hardware random number generators when available

3. **Key Strength Requirements**
   - RSA: Minimum 2048 bits, recommended 3072+ bits
   - ECDSA: Minimum P-256, recommended P-384+ curves
   - Regular security assessment and algorithm updates

### Key Storage Security

1. **File System Permissions**
   ```bash
   # Private keys: Owner read/write only
   chmod 600 keys/private/*.pem
   
   # Public keys: World readable
   chmod 644 keys/public/*.pub
   
   # Keys directory: Owner access only
   chmod 700 keys/
   ```

2. **Encryption at Rest**
   ```bash
   # Encrypt private keys with strong passphrases
   openssl rsa -in private-key.pem -aes256 -out private-key-encrypted.pem
   ```

3. **Access Control**
   ```bash
   # Create dedicated user for certificate service
   useradd -r -s /bin/false certificate-service
   chown -R certificate-service:certificate-service /opt/certificate-keys
   ```

### Network Security

1. **Secure Key Distribution**
   - Use secure channels (SSH, HTTPS) for key distribution
   - Verify key integrity using checksums
   - Implement key escrow for disaster recovery

2. **API Security**
   - Use HTTPS for all certificate operations
   - Implement proper authentication and authorization
   - Rate limiting and DDoS protection

### Operational Security

1. **Key Lifecycle Management**
   - Document all key operations
   - Implement approval workflows for key changes
   - Regular security audits and penetration testing

2. **Incident Response**
   - Prepare key compromise response procedures
   - Implement emergency key rotation capabilities
   - Maintain secure communication channels

---

## Production Deployment

### Infrastructure Requirements

#### Minimum Requirements
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 100GB SSD (encrypted)
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04 LTS or RHEL 8+

#### Recommended Requirements
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 500GB+ SSD (encrypted)
- **Network**: 10Gbps connection
- **Redundancy**: Multi-AZ deployment

### Deployment Steps

#### 1. System Preparation

```bash
# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y nodejs npm postgresql-client redis-tools openssl

# Create application user
useradd -r -m -s /bin/bash certificate-service
```

#### 2. Application Deployment

```bash
# Clone application
git clone https://github.com/your-org/certificate-system.git
cd certificate-system/backend

# Install dependencies
npm ci --production

# Build application
npm run build
```

#### 3. Key Setup

```bash
# Create secure keys directory
mkdir -p /opt/certificate-keys/{private,public}
chown -R certificate-service:certificate-service /opt/certificate-keys
chmod 700 /opt/certificate-keys

# Generate production keys
sudo -u certificate-service npm run generate-keys rsa rsa-prod-2024-01
```

#### 4. Configuration

```bash
# Create environment file
cat > /etc/certificate-service/.env << EOF
NODE_ENV=production
CRYPTO_KEYS_PATH=/opt/certificate-keys
CRYPTO_CURRENT_KEY_ID=rsa-prod-2024-01
# ... other configuration
EOF

# Set secure permissions
chmod 600 /etc/certificate-service/.env
chown certificate-service:certificate-service /etc/certificate-service/.env
```

#### 5. Service Configuration

```bash
# Create systemd service
cat > /etc/systemd/system/certificate-service.service << EOF
[Unit]
Description=Digital Certificate Service
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=certificate-service
WorkingDirectory=/opt/certificate-system/backend
EnvironmentFile=/etc/certificate-service/.env
ExecStart=/usr/bin/node dist/main.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl enable certificate-service
systemctl start certificate-service
```

### High Availability Setup

#### Load Balancer Configuration

```nginx
# nginx.conf
upstream certificate_backend {
    server 10.0.1.10:3000;
    server 10.0.1.11:3000;
    server 10.0.1.12:3000;
}

server {
    listen 443 ssl http2;
    server_name certificates.example.com;
    
    ssl_certificate /etc/ssl/certs/certificate.pem;
    ssl_certificate_key /etc/ssl/private/certificate.key;
    
    location / {
        proxy_pass http://certificate_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Database Clustering

```bash
# PostgreSQL cluster setup
# Primary node
postgresql-setup initdb
systemctl enable postgresql
systemctl start postgresql

# Configure replication
echo "wal_level = replica" >> /var/lib/pgsql/data/postgresql.conf
echo "max_wal_senders = 3" >> /var/lib/pgsql/data/postgresql.conf
echo "wal_keep_segments = 64" >> /var/lib/pgsql/data/postgresql.conf
```

---

## Backup and Recovery

### Key Backup Strategy

#### 1. Regular Backups

```bash
#!/bin/bash
# backup-keys.sh

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups/certificate-keys"
KEYS_DIR="/opt/certificate-keys"

# Create backup directory
mkdir -p "${BACKUP_DIR}/${BACKUP_DATE}"

# Backup keys with encryption
tar -czf - -C "${KEYS_DIR}" . | \
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
    --output "${BACKUP_DIR}/${BACKUP_DATE}/keys-backup.tar.gz.gpg"

# Backup key metadata
cp "${KEYS_DIR}"/*.json "${BACKUP_DIR}/${BACKUP_DATE}/"

# Upload to secure storage
aws s3 cp "${BACKUP_DIR}/${BACKUP_DATE}" \
    s3://certificate-backups/keys/${BACKUP_DATE}/ --recursive

echo "Backup completed: ${BACKUP_DATE}"
```

#### 2. Disaster Recovery

```bash
#!/bin/bash
# restore-keys.sh

RESTORE_DATE=$1
BACKUP_DIR="/opt/backups/certificate-keys"
KEYS_DIR="/opt/certificate-keys"

if [ -z "$RESTORE_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    exit 1
fi

# Download backup from secure storage
aws s3 cp "s3://certificate-backups/keys/${RESTORE_DATE}/" \
    "${BACKUP_DIR}/${RESTORE_DATE}/" --recursive

# Decrypt and restore keys
gpg --decrypt "${BACKUP_DIR}/${RESTORE_DATE}/keys-backup.tar.gz.gpg" | \
tar -xzf - -C "${KEYS_DIR}"

# Set proper permissions
chmod 700 "${KEYS_DIR}"
chmod 600 "${KEYS_DIR}/private"/*.pem
chmod 644 "${KEYS_DIR}/public"/*.pub

# Restart service
systemctl restart certificate-service

echo "Keys restored from backup: ${RESTORE_DATE}"
```

### Recovery Testing

```bash
#!/bin/bash
# test-recovery.sh

# Create test environment
docker run -d --name test-recovery \
    -v /opt/certificate-keys:/keys:ro \
    certificate-service:latest

# Test key loading
docker exec test-recovery npm run test:keys

# Test certificate generation
docker exec test-recovery npm run test:generate

# Cleanup
docker stop test-recovery
docker rm test-recovery
```

---

## Monitoring and Auditing

### Key Usage Monitoring

```bash
# Monitor key access
auditctl -w /opt/certificate-keys -p rwxa -k certificate-keys

# Monitor service logs
journalctl -u certificate-service -f | grep -E "(KEY_USED|SIGNATURE_GENERATED|VERIFICATION_PERFORMED)"
```

### Health Checks

```bash
#!/bin/bash
# health-check.sh

# Check key files exist
if [ ! -f "/opt/certificate-keys/private/${CRYPTO_CURRENT_KEY_ID}.pem" ]; then
    echo "ERROR: Private key not found"
    exit 1
fi

if [ ! -f "/opt/certificate-keys/public/${CRYPTO_CURRENT_KEY_ID}.pub" ]; then
    echo "ERROR: Public key not found"
    exit 1
fi

# Check key permissions
PRIVATE_PERMS=$(stat -c "%a" "/opt/certificate-keys/private/${CRYPTO_CURRENT_KEY_ID}.pem")
if [ "$PRIVATE_PERMS" != "600" ]; then
    echo "ERROR: Private key has incorrect permissions: $PRIVATE_PERMS"
    exit 1
fi

# Test key loading
if ! openssl rsa -in "/opt/certificate-keys/private/${CRYPTO_CURRENT_KEY_ID}.pem" -check -noout; then
    echo "ERROR: Private key is invalid"
    exit 1
fi

echo "Key health check passed"
```

### Audit Logging

```typescript
// audit-logger.ts
export class KeyAuditLogger {
  async logKeyUsage(keyId: string, operation: string, userId?: string) {
    const auditEvent = {
      timestamp: new Date().toISOString(),
      event_type: 'KEY_USAGE',
      key_id: keyId,
      operation: operation,
      user_id: userId,
      ip_address: this.getClientIp(),
      user_agent: this.getUserAgent()
    };
    
    // Log to secure audit system
    await this.auditService.log(auditEvent);
    
    // Alert on suspicious activity
    if (this.isSuspiciousActivity(auditEvent)) {
      await this.alertService.sendAlert(auditEvent);
    }
  }
}
```

---

## Troubleshooting

### Common Issues

#### 1. Key Loading Errors

**Problem**: `Error: Private key not found`
```bash
# Check key path
ls -la /opt/certificate-keys/private/

# Check environment variable
echo $CRYPTO_CURRENT_KEY_ID

# Verify key format
openssl rsa -in /opt/certificate-keys/private/rsa-2024-01.pem -check -noout
```

#### 2. Permission Errors

**Problem**: `Error: EACCES: permission denied`
```bash
# Check file permissions
ls -la /opt/certificate-keys/private/

# Fix permissions
chmod 600 /opt/certificate-keys/private/*.pem
chown certificate-service:certificate-service /opt/certificate-keys/private/*.pem
```

#### 3. Signature Verification Failures

**Problem**: `Signature verification failed`
```bash
# Check public key availability
ls -la /opt/certificate-keys/public/

# Verify key pair match
openssl rsa -in private/rsa-2024-01.pem -pubout | \
openssl md5 && \
openssl rsa -pubin -in public/rsa-2024-01.pub | \
openssl md5
```

### Diagnostic Commands

```bash
# Check service status
systemctl status certificate-service

# View service logs
journalctl -u certificate-service -n 100

# Test key generation
npm run generate-keys rsa test-key-$(date +%s)

# Test certificate verification
curl -X GET http://localhost:3000/certificates/test-cert-id/verify

# Check database connectivity
psql -h localhost -U certificate_user -d certificate_db -c "SELECT COUNT(*) FROM certificates;"
```

### Emergency Procedures

#### Key Compromise Response

1. **Immediate Actions**
   ```bash
   # Disable compromised key
   mv /opt/certificate-keys/private/compromised-key.pem /opt/certificate-keys/private/compromised-key.pem.disabled
   
   # Generate new key immediately
   npm run generate-keys rsa emergency-$(date +%s)
   
   # Update configuration
   export CRYPTO_CURRENT_KEY_ID=emergency-$(date +%s)
   
   # Restart service
   systemctl restart certificate-service
   ```

2. **Notification**
   ```bash
   # Send security alert
   curl -X POST https://hooks.slack.com/services/YOUR/SECURITY/WEBHOOK \
        -H 'Content-type: application/json' \
        --data '{"text":"SECURITY ALERT: Certificate signing key compromised. Emergency rotation initiated."}'
   ```

3. **Investigation**
   ```bash
   # Collect audit logs
   journalctl -u certificate-service --since "24 hours ago" > /tmp/security-incident-logs.txt
   
   # Check file access logs
   ausearch -k certificate-keys --start recent
   ```

---

## Compliance and Standards

### Industry Standards

- **FIPS 140-2**: Federal Information Processing Standard for cryptographic modules
- **Common Criteria**: International standard for computer security certification
- **NIST SP 800-57**: Recommendations for Key Management
- **RFC 3647**: Internet X.509 Public Key Infrastructure Certificate Policy and Certification Practices Framework

### Compliance Checklist

- [ ] Key generation uses approved algorithms and key sizes
- [ ] Private keys are stored securely with proper access controls
- [ ] Key rotation procedures are documented and tested
- [ ] Audit logging captures all key operations
- [ ] Backup and recovery procedures are tested regularly
- [ ] Security assessments are performed annually
- [ ] Incident response procedures are documented
- [ ] Staff training on key management procedures is current

### Documentation Requirements

Maintain the following documentation:
- Key generation procedures
- Key storage and access policies
- Key rotation schedules and procedures
- Incident response plans
- Audit log retention policies
- Staff training records
- Security assessment reports
- Compliance certification documents

---

This guide provides comprehensive coverage of key management for the Digital Certificate System. Regular review and updates of these procedures are essential to maintain security and compliance with evolving standards and threats.