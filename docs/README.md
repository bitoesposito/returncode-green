# 🛡️ Pandom Stack - Security-First Application Boilerplate

> **A complete boilerplate for modern web applications focused on security, with cookie-based authentication and GDPR compliance.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![Angular](https://img.shields.io/badge/Angular-19+-red.svg)](https://angular.io/)
[![NestJS](https://img.shields.io/badge/NestJS-11+-red.svg)](https://nestjs.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17+-blue.svg)](https://www.postgresql.org/)

## 📋 Documentation Index

### 🚀 **Getting Started**
- [**Application Overview**](./overview.md) - General overview and architecture
- [**Installation Guide**](./installation.md) - Complete setup step-by-step
- [**Environment Configuration**](./configuration/environment-vars.md) - Environment variables and configurations

### 🏗️ **Architecture & Design**
- [**System Architecture**](./architecture/system-architecture.md) - System architecture overview
- [**Database Design**](./architecture/database-design.md) - Database schema and management

### 🐳 **Deployment & Configuration**
- [**Docker Deployment**](./configuration/docker-deployment.md) - Docker configuration and deployment
- [**Production Deployment**](./deployment/production-deployment-guide.md) - Production deployment guide

### 🔒 **Security & Compliance**
- [**Security Overview**](./security/security-overview.md) - Security framework and features
- [**Security Implementation Guide**](./security/security-implementation-guide.md) - Complete security implementation guide

### 📱 **PWA Features**
- [**PWA Architecture**](./architecture/system-architecture.md#pwa-architecture) - Progressive Web App design and features

### 🛠️ **Development & API**
- [**API Reference**](./api/api-reference.md) - Complete API documentation
- [**Postman Collection**](./api/pandom-postman-collection.json) - Complete Postman collection
- [**Postman Environment**](./api/pandom-postman-environment.json) - Postman environment
- [**Postman Setup Guide**](./api/postman-setup-guide.md) - Postman configuration guide

## 🎯 **Key Features**

### 🔒 **Advanced Security**
- **Cookie-based Authentication** with httpOnly cookies
- **JWT tokens** managed securely on server-side
- **Role-based authorization** (RBAC)
- **Complete audit logging** for compliance
- **Configured security headers** (HSTS, CSP, X-Frame-Options)
- **Integrated GDPR compliance**

### 📱 **PWA Capabilities**
- **Progressive Web App** ready structure
- **Theme switching** (light/dark mode)
- **Internationalization** (English/Italian)
- **Responsive design** for all devices
- **Cookie-based authentication** with automatic refresh

### 🏗️ **Modern Architecture**
- **NestJS 11+ backend** with TypeScript
- **Angular 19+ frontend** with PWA
- **PostgreSQL 17+ database** with TypeORM
- **Complete Docker containerization**
- **Well-documented REST APIs**
- **Microservices ready**

### 📊 **Monitoring & Operations**
- **Automatic health checks**
- **Real-time metrics**
- **Structured logging**
- **Automatic backups**
- **Performance monitoring**
- **Alerting system**

## 🚀 **Quick Start**

```bash
# Clone the repository
git clone <repository-url>
cd pandom-stack

# Setup with Docker
cp demo.env .env
# Configure environment variables in .env

# Start the application
docker-compose up -d

# The application will be available at:
# Frontend: http://localhost:4200
# Backend: http://localhost:3000
# MinIO Console: http://localhost:9001
```

## 📖 **Detailed Documentation**

To get started, check the [**Application Overview**](./overview.md) for a complete overview, or go directly to the [**Installation Guide**](./installation.md) to start immediately.

## 🤝 **Contributions**

This project is open source and accepts contributions!

## 📄 **License**

This project is released under the MIT license.

---

**Pandom Stack** - Build secure, modern, and scalable applications with this complete boilerplate. 