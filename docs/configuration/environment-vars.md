# 🔧 Environment Variables

## 📋 Overview

**Pandom Stack** uses environment variables to configure all aspects of the application. This documentation provides a complete guide for all available variables, their default values, and recommended configurations for different environments.

## 🏗️ **.env File Structure**

The `.env` file is organized in logical sections to facilitate configuration:

```env
# ============================================================================
# BASE CONFIGURATION
# ============================================================================

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

# ============================================================================
# SERVER CONFIGURATION
# ============================================================================

# ============================================================================
# FRONTEND CONFIGURATION
# ============================================================================

# ============================================================================
# ADMIN USER CONFIGURATION
# ============================================================================

# ============================================================================
# JWT AND SESSIONS CONFIGURATION
# ============================================================================

# ============================================================================
# EMAIL CONFIGURATION
# ============================================================================

# ============================================================================
# MINIO CONFIGURATION
# ============================================================================

# ============================================================================
# SECURITY AND COOKIE CONFIGURATION
# ============================================================================

# ============================================================================
# MONITORING CONFIGURATION
# ============================================================================
```

## 🌐 **Base Configuration**

### **URL**
```env
# Main application domain
URL=localhost
```
- **Type**: String
- **Default**: `localhost`
- **Description**: Main domain used to generate absolute URLs
- **Example**: `yourdomain.com`, `app.example.com`

## 🗄️ **Database Configuration**

### **PostgreSQL Configuration**

```env
# PostgreSQL database host
DB_HOST=postgres

# PostgreSQL credentials
POSTGRES_USER=pandom_user
POSTGRES_PASSWORD=secure_password_123
POSTGRES_DB=pandom_db

# PostgreSQL port
POSTGRES_PORT=5432

# Database connection URL
DATABASE_URL=postgres://pandom_user:secure_password_123@postgres:5432/pandom_db
DB_URL=postgres://pandom_user:secure_password_123@postgres:5432/pandom_db
```

#### **DB_HOST**
- **Type**: String
- **Default**: `postgres`
- **Description**: PostgreSQL server host
- **Docker Environment**: `postgres` (service name)
- **External Environment**: `your-db-host.com`

#### **POSTGRES_USER**
- **Type**: String
- **Default**: `pandom_user`
- **Description**: Username for database connection
- **Security**: Use a specific username for the application

#### **POSTGRES_PASSWORD**
- **Type**: String
- **Default**: `secure_password_123`
- **Description**: Password for database connection
- **Security**: Use a strong and unique password
- **Generation**: `openssl rand -base64 32`

#### **POSTGRES_DB**
- **Type**: String
- **Default**: `pandom_db`
- **Description**: Database name
- **Convention**: Use a descriptive name for the application

#### **POSTGRES_PORT**
- **Type**: Number
- **Default**: `5432`
- **Description**: PostgreSQL server port
- **Standard**: `5432` (standard PostgreSQL port)

#### **DATABASE_URL / DB_URL**
- **Type**: String
- **Default**: `postgres://pandom_user:secure_password_123@postgres:5432/pandom_db`
- **Description**: Complete database connection URL
- **Format**: `postgres://username:password@host:port/database`

## 🖥️ **Server Configuration**

### **Backend Configuration**

```env
# Backend port
BE_PORT=3000

# Backend URL
BE_URL=http://localhost:3000

# Node.js mode
NODE_ENV=development
```

#### **BE_PORT**
- **Type**: Number
- **Default**: `3000`
- **Description**: Port on which the backend server listens
- **Range**: `1024-65535`
- **Conflicts**: Avoid ports already in use (80, 443, 8080)

#### **BE_URL**
- **Type**: String
- **Default**: `http://localhost:3000`
- **Description**: Complete backend URL
- **Format**: `http://host:port` or `https://host:port`

#### **NODE_ENV**
- **Type**: String
- **Default**: `development`
- **Values**: `development`, `staging`, `production`
- **Description**: Node.js execution environment

## 🎨 **Frontend Configuration**

### **Angular Configuration**

```env
# Frontend port
FE_PORT=4200

# Frontend URL
FE_URL=http://localhost:4200

# Production mode
PRODUCTION=false
```

#### **FE_PORT**
- **Type**: Number
- **Default**: `4200`
- **Description**: Port on which the frontend server listens
- **Range**: `1024-65535`
- **Conflicts**: Avoid ports already in use

#### **FE_URL**
- **Type**: String
- **Default**: `http://localhost:4200`
- **Description**: Complete frontend URL
- **Format**: `http://host:port` or `https://host:port`

#### **PRODUCTION**
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable production mode
- **Effects**: Disables debug, enables optimizations

## 👤 **Admin User Configuration**

### **Admin User Setup**

```env
# Admin email
ADMIN_EMAIL=admin@pandom.com

# Admin role
ADMIN_ROLE=admin

# Admin password (plain text)
ADMIN_PASSWORD=admin123

# Admin password (hashed)
ADMIN_HASHED_PASSWORD=
```

#### **ADMIN_EMAIL**
- **Type**: String
- **Default**: `admin@pandom.com`
- **Description**: Administrator user email
- **Format**: Valid email
- **Security**: Use a real email to receive notifications

#### **ADMIN_ROLE**
- **Type**: String
- **Default**: `admin`
- **Description**: Administrator user role
- **Values**: `admin`, `super_admin`
- **Permissions**: Full system access

#### **ADMIN_PASSWORD**
- **Type**: String
- **Default**: `admin123`
- **Description**: Plain text password for administrator
- **Security**: Change immediately after installation
- **Requirements**: Minimum 8 characters, uppercase, numbers, symbols

#### **ADMIN_HASHED_PASSWORD**
- **Type**: String
- **Default**: `''`
- **Description**: Hashed password for administrator
- **Generation**: `npm run generate-password-hash`
- **Security**: Takes priority over ADMIN_PASSWORD if present

## 🔐 **JWT and Sessions Configuration**

### **JWT Authentication**

```env
# JWT secret key
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# JWT token expiration
JWT_EXPIRATION=15m

# Refresh token expiration
JWT_REFRESH_EXPIRATION=7d

# Cookie Configuration
COOKIE_SECRET=your-cookie-secret-here
COOKIE_DOMAIN=yourdomain.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict

# Session Configuration
SESSION_TIMEOUT=3600000
SESSION_CLEANUP_INTERVAL=300000
```

#### **JWT_SECRET**
- **Type**: String
- **Default**: `your-super-secret-jwt-key-change-this-in-production`
- **Description**: Secret key for signing JWT tokens
- **Security**: **CHANGE IN PRODUCTION**
- **Generation**: `openssl rand -base64 64`
- **Length**: Minimum 32 characters

#### **JWT_EXPIRATION**
- **Type**: String
- **Default**: `15m`
- **Description**: JWT token expiration time
- **Format**: `Xs` (seconds), `Xm` (minutes), `Xh` (hours), `Xd` (days)
- **Examples**: `15m`, `1h`, `7d`
- **Security**: Short to reduce risks

#### **JWT_REFRESH_EXPIRATION**
- **Type**: String
- **Default**: `7d`
- **Description**: Refresh token expiration time
- **Format**: `Xs` (seconds), `Xm` (minutes), `Xh` (hours), `Xd` (days)
- **Examples**: `7d`, `30d`
- **Security**: Longer than access token

#### **COOKIE_SECRET**
- **Type**: String
- **Default**: `your-cookie-secret-here`
- **Description**: Secret key for signing cookies
- **Security**: Different from JWT_SECRET
- **Generation**: `openssl rand -base64 32`

#### **COOKIE_DOMAIN**
- **Type**: String
- **Default**: `yourdomain.com`
- **Description**: Domain for cookies
- **Development**: `localhost`
- **Production**: Real domain

#### **COOKIE_SECURE**
- **Type**: Boolean
- **Default**: `true`
- **Description**: Cookies only on HTTPS
- **Development**: `false`
- **Production**: `true`

#### **COOKIE_SAME_SITE**
- **Type**: String
- **Default**: `strict`
- **Description**: CSRF protection
- **Values**: `strict`, `lax`, `none`
- **Security**: `strict` for maximum protection

#### **SESSION_TIMEOUT**
- **Type**: Number
- **Default**: `3600000` (1 hour)
- **Description**: Session timeout in milliseconds
- **Security**: Short to reduce risks

#### **SESSION_CLEANUP_INTERVAL**
- **Type**: Number
- **Default**: `300000` (5 minutes)
- **Description**: Expired session cleanup interval
- **Performance**: Prevents session accumulation

## 📧 **Email Configuration**

### **SMTP Configuration**

```env
# SMTP host
SMTP_HOST=smtp.gmail.com

# SMTP port
SMTP_PORT=587

# SMTP user
SMTP_USER=your-email@gmail.com

# SMTP password
SMTP_PASS=your-app-password

# Sender email
SMTP_FROM=noreply@pandom.com

# Enable email
SMTP_ENABLED=false
```

#### **SMTP_HOST**
- **Type**: String
- **Default**: `smtp.gmail.com`
- **Description**: SMTP server host
- **Common providers**:
  - Gmail: `smtp.gmail.com`
  - Outlook: `smtp-mail.outlook.com`
  - SendGrid: `smtp.sendgrid.net`
  - AWS SES: `email-smtp.us-east-1.amazonaws.com`

#### **SMTP_PORT**
- **Type**: Number
- **Default**: `587`
- **Description**: SMTP server port
- **Common ports**:
  - `587`: STARTTLS (recommended)
  - `465`: SSL/TLS
  - `25`: Insecure (not recommended)

#### **SMTP_USER**
- **Type**: String
- **Default**: `your-email@gmail.com`
- **Description**: Username for SMTP authentication
- **Gmail**: Complete email
- **SendGrid**: `apikey`

#### **SMTP_PASS**
- **Type**: String
- **Default**: `your-app-password`
- **Description**: Password for SMTP authentication
- **Gmail**: App password (not account password)
- **SendGrid**: API key

#### **SMTP_FROM**
- **Type**: String
- **Default**: `noreply@pandom.com`
- **Description**: Sender email for notifications
- **Format**: Valid email
- **Domain**: Must match configured domain

#### **SMTP_ENABLED**
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable email sending
- **Development**: `false` (disable emails)
- **Production**: `true` (enable emails)

## 📁 **MinIO Configuration**

### **File Storage Configuration**

```env
# MinIO root user
MINIO_ROOT_USER=minioadmin

# MinIO root password
MINIO_ROOT_PASSWORD=minioadmin123

# MinIO endpoint
MINIO_ENDPOINT=http://minio:9000

# MinIO port
MINIO_PORT=9000

# Use SSL for MinIO
MINIO_USE_SSL=false

# MinIO bucket name
MINIO_BUCKET_NAME=pandom-bucket

# Enable MinIO
MINIO_ENABLED=true
```

#### **MINIO_ROOT_USER**
- **Type**: String
- **Default**: `minioadmin`
- **Description**: Root username for MinIO
- **Security**: Change in production
- **Length**: 3-20 characters

#### **MINIO_ROOT_PASSWORD**
- **Type**: String
- **Default**: `minioadmin123`
- **Description**: Root password for MinIO
- **Security**: Change in production
- **Length**: Minimum 8 characters

#### **MINIO_ENDPOINT**
- **Type**: String
- **Default**: `http://minio:9000`
- **Description**: MinIO server endpoint
- **Docker**: `http://minio:9000`
- **External**: `https://your-minio-server.com`

#### **MINIO_PORT**
- **Type**: Number
- **Default**: `9000`
- **Description**: MinIO server port
- **Standard**: `9000` (API), `9001` (Console)

#### **MINIO_USE_SSL**
- **Type**: Boolean
- **Default**: `false`
- **Description**: Use SSL/TLS for MinIO
- **Development**: `false`
- **Production**: `true`

#### **MINIO_BUCKET_NAME**
- **Type**: String
- **Default**: `pandom-bucket`
- **Description**: Bucket name for files
- **Convention**: Descriptive name for the application
- **Format**: Only lowercase letters, numbers, hyphens

#### **MINIO_ENABLED**
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable MinIO service
- **Development**: `true`
- **Production**: `true` (if not using external S3)

## 🛡️ **Security Configuration**

### **Security Settings**

```env
# Enable security headers
SECURITY_HEADERS_ENABLED=false

# Rate limiting window (ms)
RATE_LIMIT_WINDOW=900000

# Rate limiting max requests
RATE_LIMIT_MAX_REQUESTS=100

# Enable HTTPS
HTTPS_ENABLED=false

# SSL certificate path
SSL_CERT_PATH=/path/to/cert.pem

# SSL key path
SSL_KEY_PATH=/path/to/key.pem

# Enable CORS
CORS_ENABLED=true

# Allowed CORS origins
CORS_ORIGINS=http://localhost:4200,http://localhost:3000
```

#### **SECURITY_HEADERS_ENABLED**
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable HTTP security headers
- **Development**: `false` (for debugging)
- **Production**: `true` (mandatory)

#### **RATE_LIMIT_WINDOW**
- **Type**: Number
- **Default**: `900000` (15 minutes)
- **Description**: Time window for rate limiting
- **Unit**: Milliseconds
- **Examples**: `60000` (1 min), `300000` (5 min)

#### **RATE_LIMIT_MAX_REQUESTS**
- **Type**: Number
- **Default**: `100`
- **Description**: Maximum number of requests per window
- **Development**: `1000` (more permissive)
- **Production**: `50` (more restrictive)

#### **HTTPS_ENABLED**
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable HTTPS
- **Development**: `false`
- **Production**: `true` (mandatory)

#### **SSL_CERT_PATH**
- **Type**: String
- **Default**: `/path/to/cert.pem`
- **Description**: SSL certificate path
- **Format**: `.pem` or `.crt` file
- **Generation**: Let's Encrypt or commercial certificate

#### **SSL_KEY_PATH**
- **Type**: String
- **Default**: `/path/to/key.pem`
- **Description**: SSL private key path
- **Format**: `.pem` or `.key` file
- **Security**: Keep private and secure

#### **CORS_ENABLED**
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable CORS for cross-origin requests
- **Development**: `true`
- **Production**: Configure specifically

#### **CORS_ORIGINS**
- **Type**: String
- **Default**: `http://localhost:4200,http://localhost:3000`
- **Description**: Allowed origins for CORS
- **Format**: Comma-separated list
- **Examples**: `https://yourdomain.com,https://app.yourdomain.com`

## 📊 **Monitoring Configuration**

### **Monitoring Settings**

```env
# Enable health checks
HEALTH_CHECKS_ENABLED=true

# Enable metrics
METRICS_ENABLED=true

# Enable audit logging
AUDIT_LOGGING_ENABLED=true

# Log level
LOG_LEVEL=info

# Enable debug mode
DEBUG_MODE=false
```

#### **HEALTH_CHECKS_ENABLED**
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable health checks
- **Endpoint**: `/health`
- **Monitoring**: Container orchestration

#### **METRICS_ENABLED**
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable metrics collection
- **Endpoint**: `/metrics`
- **Monitoring**: Prometheus, Grafana

#### **AUDIT_LOGGING_ENABLED**
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable audit logging
- **Compliance**: GDPR, SOX, HIPAA
- **Storage**: Database + file system

#### **LOG_LEVEL**
- **Type**: String
- **Default**: `info`
- **Description**: Log detail level
- **Values**: `error`, `warn`, `info`, `debug`, `verbose`
- **Development**: `debug`
- **Production**: `info`

#### **DEBUG_MODE**
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable debug mode
- **Development**: `true`
- **Production**: `false` (security)

## 🔄 **Environment-Specific Configurations**

### **Development Environment**

```env
# Development Configuration
NODE_ENV=development
PRODUCTION=false
DEBUG_MODE=true
LOG_LEVEL=debug
SECURITY_HEADERS_ENABLED=false
HTTPS_ENABLED=false
SMTP_ENABLED=false
RATE_LIMIT_MAX_REQUESTS=1000
```

### **Staging Environment**

```env
# Staging Configuration
NODE_ENV=staging
PRODUCTION=false
DEBUG_MODE=false
LOG_LEVEL=info
SECURITY_HEADERS_ENABLED=true
HTTPS_ENABLED=true
SMTP_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=100
```

### **Production Environment**

```env
# Production Configuration
NODE_ENV=production
PRODUCTION=true
DEBUG_MODE=false
LOG_LEVEL=warn
SECURITY_HEADERS_ENABLED=true
HTTPS_ENABLED=true
SMTP_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=50
JWT_EXPIRATION=30m
```

## 🔧 **Configuration Utilities**

### **Generate Secure Passwords**

```bash
# Generate secure password
openssl rand -base64 32

# Generate JWT secret
openssl rand -base64 64

# Generate salt for bcrypt
openssl rand -base64 16
```

### **Configuration Validation**

```bash
# Validate .env file
docker-compose config

# Test database connection
docker-compose exec postgres pg_isready -U $POSTGRES_USER -d $POSTGRES_DB

# Test MinIO connection
curl $MINIO_ENDPOINT/minio/health/live
```

### **Configuration Backup**

```bash
# Backup configuration
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)

# Restore configuration
cp .env.backup.20240101_120000 .env
```

## 🚨 **Best Practices**

### **Security**

1. **Always change default credentials**
2. **Use strong and unique passwords**
3. **Enable HTTPS in production**
4. **Configure security headers**
5. **Limit CORS origins**

### **Performance**

1. **Configure connection pooling**
2. **Optimize rate limiting**
3. **Use appropriate caching**
4. **Monitor metrics**

### **Maintainability**

1. **Document configurations**
2. **Use separate environment variables**
3. **Version configurations**
4. **Test in staging**

---

**Pandom Stack** - Flexible and secure configuration for every environment.
