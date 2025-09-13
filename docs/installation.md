# 🚀 Installation Guide

> **Complete step-by-step guide to install and configure Pandom Stack for development and production environments.**

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Installation](#quick-installation)
- [Detailed Setup](#detailed-setup)
- [Environment Configuration](#environment-configuration)
- [Security Setup](#security-setup)
- [Production Setup](#production-setup)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

## ✅ Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Node.js** | 18.x | 20.x LTS |
| **npm** | 9.x | 10.x |
| **Docker** | 20.x | 24.x |
| **Docker Compose** | 2.x | 2.x |
| **RAM** | 4GB | 8GB+ |
| **Storage** | 10GB | 20GB+ |
| **OS** | Windows 10, macOS 10.15, Ubuntu 20.04 | Latest LTS |

### Required Software

```bash
# Check Node.js version
node --version  # Should be >= 18.x

# Check npm version
npm --version   # Should be >= 9.x

# Check Docker version
docker --version  # Should be >= 20.x

# Check Docker Compose version
docker-compose --version  # Should be >= 2.x
```

### Port Requirements

| Service | Port | Description |
|---------|------|-------------|
| **Frontend** | 4200 | Angular development server |
| **Backend** | 3000 | NestJS API server |
| **Database** | 5432 | PostgreSQL database |

| **MinIO** | 9000 | Object storage API |
| **MinIO Console** | 9001 | Object storage web UI |


## ⚡ Quick Installation

### 1. Clone Repository

```bash
# Clone the repository
git clone <repository-url>
cd pandom-stack

# Check the structure
ls -la
```

### 2. Environment Setup

```bash
# Copy environment template
cp demo.env .env

# Edit environment variables
nano .env  # or use your preferred editor
```

### 3. Start with Docker

```bash
# Build and start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 4. Verify Installation

```bash
# Check if services are running
curl http://localhost:3000/health
curl http://localhost:4200

# Access MinIO console
open http://localhost:9001
```

## 🔧 Detailed Setup

### Step 1: Repository Setup

```bash
# Clone the repository
git clone <repository-url>
cd pandom-stack


```

### Step 2: Backend Setup

```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install

# Copy environment file
cp ../demo.env .env

# Configure environment variables
nano .env
```

### Step 3: Frontend Setup

```bash
# Navigate to frontend directory
cd ../frontend

# Install dependencies
npm install

# Copy environment file
cp ../demo.env .env

# Configure environment variables
nano .env
```

### Step 4: Database Setup

```bash
# Start database services
docker-compose up -d postgres minio

# Wait for services to be ready
sleep 30

# Run database migrations
cd backend
npm run migration:run

# Seed initial data
npm run seed:admin
```

### Step 5: Service Startup

```bash
# Start all services
docker-compose up -d

# Monitor startup
docker-compose logs -f
```

## ⚙️ Environment Configuration

### Core Configuration

```bash
# Application settings
APP_NAME=Pandom Stack
APP_VERSION=1.0.0
NODE_ENV=development
PORT=3000

# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=pandom_user
DB_PASSWORD=secure_password
DB_DATABASE=pandom_db
DATABASE_URL=postgres://pandom_user:secure_password@localhost:5432/pandom_db

# JWT and Session configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# Cookie configuration
COOKIE_SECRET=your-cookie-secret-here
COOKIE_DOMAIN=localhost
COOKIE_SECURE=false
COOKIE_SAME_SITE=strict

# Session configuration
SESSION_TIMEOUT=3600000
SESSION_CLEANUP_INTERVAL=300000

# Email configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=noreply@pandom.com

# MinIO configuration
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_BUCKET=pandom-storage
```

### Security Configuration

```bash
# Security settings
ENCRYPTION_KEY=your-32-character-encryption-key
CORS_ORIGIN=http://localhost:4200

# GDPR settings
GDPR_ENABLED=true
DATA_RETENTION_DAYS=730
AUDIT_LOG_ENABLED=true

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_ATTEMPTS=5

# Security headers
SECURITY_HEADERS_ENABLED=true
HTTPS_ENABLED=false
```

### Development Configuration

```bash
# Development settings
DEBUG=true
LOG_LEVEL=debug
SECURITY_HEADERS_ENABLED=false
HTTPS_ENABLED=false
SMTP_ENABLED=false
RATE_LIMIT_MAX_REQUESTS=1000
```

## 🔐 **Security Setup**

### **1. Generate Secure Keys**

```bash
# Generate JWT secret
openssl rand -base64 64

# Generate cookie secret
openssl rand -base64 32

# Generate encryption key
openssl rand -base64 32
```

### **2. Configure httpOnly Cookies**

```bash
# Development (localhost)
COOKIE_DOMAIN=localhost
COOKIE_SECURE=false
COOKIE_SAME_SITE=strict

# Production
COOKIE_DOMAIN=yourdomain.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict
```

### **3. Setup Session Management**

```bash
# Session timeout (1 hour)
SESSION_TIMEOUT=3600000

# Cleanup interval (5 minutes)
SESSION_CLEANUP_INTERVAL=300000
```

### **4. Configure Rate Limiting**

```bash
# Rate limiting for authentication
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_ATTEMPTS=5    # 5 attempts per window
```

## 🛡️ **Security Best Practices**

### **1. Environment Variables**

- ✅ **Never commit secrets** to version control
- ✅ **Use strong passwords** (min 32 characters)
- ✅ **Rotate secrets regularly** in production
- ✅ **Use different secrets** for each environment

### **2. Database Security**

- ✅ **Use strong database passwords**
- ✅ **Enable SSL connections** in production
- ✅ **Restrict database access** to application only
- ✅ **Regular security updates** for PostgreSQL

### **3. Cookie Security**

- ✅ **httpOnly cookies** prevent XSS attacks
- ✅ **Secure flag** for HTTPS only
- ✅ **SameSite=Strict** prevents CSRF
- ✅ **Short expiration times** reduce risk

### **4. Network Security**

- ✅ **HTTPS in production** (required for secure cookies)
- ✅ **CORS properly configured**
- ✅ **Security headers enabled**
- ✅ **Rate limiting active**
LOG_LEVEL=debug
HOT_RELOAD=true
AUTO_MIGRATION=true

# Testing settings
TEST_DB_HOST=localhost
TEST_DB_PORT=5432
TEST_DB_DATABASE=pandom_test
```

## 🏭 Production Setup

### Production Environment Variables

```bash
# Production settings
NODE_ENV=production
PORT=3000
LOG_LEVEL=info
DEBUG=false

# Production database
DB_HOST=production-db-host
DB_PORT=5432
DB_USERNAME=prod_user
DB_PASSWORD=strong_production_password
DB_DATABASE=pandom_prod



# Production MinIO
MINIO_ENDPOINT=production-minio-host
MINIO_PORT=9000
MINIO_ROOT_USER=production_access_key
MINIO_ROOT_PASSWORD=production_secret_key

# Production security
JWT_SECRET=very-long-production-jwt-secret
ENCRYPTION_KEY=32-character-production-encryption-key
CORS_ORIGIN=https://yourdomain.com
```

### Production Docker Setup

```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Start production services
docker-compose -f docker-compose.prod.yml up -d

# Check production status
docker-compose -f docker-compose.prod.yml ps
```

### SSL/HTTPS Configuration

```bash

```

## 🔄 Development Workflow

### Local Development

```bash
# Start development environment
docker-compose up -d

# Backend development (with hot reload)
cd backend
npm run start:dev

# Frontend development (with hot reload)
cd frontend
npm start
```

### Database Management

```bash
# Create new migration
cd backend
npm run migration:generate -- src/database/migrations/NewMigration

# Run migrations
npm run migration:run

# Revert migration
npm run migration:revert

# Seed database
npm run seed:admin
```

### Testing

```bash
# Run backend tests
cd backend
npm run test
npm run test:e2e

# Run frontend tests
cd frontend
npm run test
npm run test:e2e
```

### Code Quality

```bash
# Backend linting
cd backend
npm run lint
npm run lint:fix

# Frontend linting
cd frontend
npm run lint
npm run lint:fix

# Format code
npm run format
```

## 🔍 Monitoring & Health Checks

### Health Check Endpoints

```bash
# Application health
curl http://localhost:3000/health

# Database health
curl http://localhost:3000/health/database



# MinIO health
curl http://localhost:3000/health/storage
```

### Log Monitoring

```bash
# View application logs
docker-compose logs -f backend

# View database logs
docker-compose logs -f postgres



# View MinIO logs
docker-compose logs -f minio
```

### Metrics Collection

```bash
# Application metrics
curl http://localhost:3000/metrics

# System metrics
docker stats

# Database metrics
docker exec -it pandom-stack-postgres-1 psql -U pandom_user -d pandom_db -c "SELECT * FROM pg_stat_database;"
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Port Conflicts

```bash
# Check port usage
netstat -tulpn | grep :3000
netstat -tulpn | grep :4200

# Kill process using port
sudo kill -9 <PID>
```

#### 2. Database Connection Issues

```bash
# Check database status
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Reset database
docker-compose down
docker volume rm pandom-stack_postgres_data
docker-compose up -d postgres
```

#### 3. Docker Issues

```bash
# Clean Docker resources
docker system prune -a

# Rebuild images
docker-compose build --no-cache

# Reset containers
docker-compose down -v
docker-compose up -d
```

#### 4. Environment Variables

```bash
# Validate environment file
cd backend
npm run validate:env

# Check environment variables
docker-compose config
```

### Performance Issues

#### 1. Memory Issues

```bash
# Check memory usage
docker stats

# Increase Docker memory limit
# Edit Docker Desktop settings
```

#### 2. Database Performance

```bash
# Check database performance
docker exec -it pandom-stack-postgres-1 psql -U pandom_user -d pandom_db -c "SELECT * FROM pg_stat_activity;"

# Optimize database
docker exec -it pandom-stack-postgres-1 psql -U pandom_user -d pandom_db -c "VACUUM ANALYZE;"
```

#### 3. Network Issues

```bash
# Check network connectivity
docker network ls
docker network inspect pandom-stack_default

# Test service communication
docker exec -it pandom-stack-backend-1 ping postgres
```

### Security Issues

#### 1. JWT Issues

```bash
# Regenerate JWT secret
openssl rand -base64 32

# Update environment variable
# JWT_SECRET=new-generated-secret
```

#### 2. Encryption Issues

```bash
# Generate encryption key
openssl rand -base64 32

# Update environment variable
# ENCRYPTION_KEY=new-generated-key
```

#### 3. SSL Issues

```bash
# Check SSL certificate
openssl x509 -in /path/to/certificate.crt -text -noout

# Test SSL connection
openssl s_client -connect yourdomain.com:443
```

## 📚 Additional Resources

### Documentation
- [Application Overview](./overview.md)
- [API Reference](./api/api-reference.md)
- [Security Guide](./security/security-overview.md)
- [Docker Deployment](./configuration/docker-deployment.md)

### Support

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Complete guides and references
- **Community**: Join discussions and get help

## 📚 Related Documentation

### 🚀 **Getting Started**
- [**Application Overview**](./overview.md) - General overview and architecture
- [**Environment Configuration**](./configuration/environment-vars.md) - Environment variables and configurations

### 🏗️ **Architecture & Design**
- [**System Architecture**](./architecture/system-architecture.md) - Detailed system architecture
- [**Database Design**](./architecture/database-design.md) - Database schema and management

### 🐳 **Deployment & Configuration**
- [**Docker Deployment**](./configuration/docker-deployment.md) - Docker configuration and deployment
- [**Production Deployment**](./deployment/production-deployment-guide.md) - Production deployment guide

### 🔒 **Security & Compliance**
- [**Security Overview**](./security/security-overview.md) - Security framework and features
- [**Security Implementation Guide**](./security/security-implementation-guide.md) - Complete security implementation guide

### 🛠️ **Development & API**
- [**API Reference**](./api/api-reference.md) - Complete API documentation
- [**Postman Collection**](./api/pandom-postman-collection.json) - Complete Postman collection
- [**Postman Setup Guide**](./api/postman-setup-guide.md) - Postman configuration guide

---

**Pandom Stack** is now ready for development and production use! 🎉 