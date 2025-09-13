# 🏗️ Pandom Stack - Application Overview

> **A comprehensive security-first boilerplate for modern web applications with cookie-based authentication and GDPR compliance.**

## 📋 Table of Contents

- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Key Features](#key-features)
- [Security Framework](#security-framework)
- [Development Workflow](#development-workflow)
- [Deployment Strategy](#deployment-strategy)
- [Documentation Links](#documentation-links)

## 🏛️ System Architecture

Pandom Stack follows a **layered architecture** pattern with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Angular   │  │   PWA/SW    │  │   Cookie    │        │
│  │   Frontend  │  │   Caching   │  │   Auth      │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   GATEWAY LAYER                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Reverse   │  │   Rate      │  │   Security  │        │
│  │   Proxy     │  │  Limiting   │  │   Headers   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                APPLICATION LAYER                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   NestJS    │  │   Auth      │  │   Business  │        │
│  │   Backend   │  │  Services   │  │   Logic     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   SERVICE LAYER                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Email     │  │   File      │  │   Session   │        │
│  │  Service    │  │  Storage    │  │  Service    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    DATA LAYER                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ PostgreSQL  │  │   MinIO     │                          │
│  │  Database   │  │   Cache     │  │   Storage   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Components | Responsibilities |
|-------|------------|------------------|
| **Client** | Angular 19, PWA, Cookie Auth | UI rendering, secure authentication, user interaction |
| **Gateway** | API Gateway, Security | Security, traffic control |
| **Application** | NestJS 11, Auth, Business Logic | API endpoints, authentication, business rules |
| **Service** | Email, File Storage, Session | External services integration |
| **Data** | PostgreSQL 17, MinIO | Data persistence, file storage |

## 🛠️ Technology Stack

### Frontend
- **Angular 19** - Modern reactive framework with standalone components
- **TypeScript** - Type-safe development
- **PWA (Progressive Web App)** - App-like experience (PWA-ready structure)
- **Cookie-based Authentication** - Secure httpOnly cookies for XSS protection
- **PrimeNG 19** - UI component library with PrimeFlex
- **ngx-translate** - Internationalization (English/Italian)
- **Theme Service** - Light/Dark mode with system preference detection

### Backend
- **NestJS 11** - Enterprise-grade Node.js framework
- **TypeScript** - Type-safe backend development
- **TypeORM** - Database ORM with migrations
- **JWT** - Server-side token management with httpOnly cookies
- **Passport.js** - Authentication strategies
- **bcrypt** - Password hashing (12 rounds)
- **Rate Limiting** - DDoS protection

### Database & Storage
- **PostgreSQL 17** - Primary relational database
- **MinIO** - S3-compatible object storage
- **TypeORM** - Database migrations and seeding
- **Connection Pooling** - Optimized database connections

### Security & Monitoring
- **Security Headers** - Via interceptors (HSTS, CSP, X-Frame-Options)
- **Audit Logging** - Compliance tracking with correlation IDs
- **Health Checks** - System monitoring endpoints
- **Metrics Collection** - Performance monitoring and analytics
- **Session Management** - Secure session handling with device tracking

### DevOps & Deployment
- **Docker** - Containerization
- **Docker Compose** - Multi-service orchestration
- **Environment-based Configuration** - Flexible deployment
- **Health Monitoring** - Built-in health check endpoints

## 🎯 Key Features

### 🔒 **Advanced Security Framework**

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Network   │  │   Transport │  │ Application │        │
│  │   Security  │  │   Security  │  │   Security  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│         │                │                │               │
│    Security Headers JWT Tokens      Input Validation      │
│    HTTPS/TLS        XSS Prevention                         │
│    CORS Policy      SQL Injection                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   DATA SECURITY                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Cookie    │  │   Audit     │  │   GDPR      │        │
│  │   Auth      │  │  Logging    │  │ Compliance  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

- **Multi-layer security** with defense-in-depth strategy
- **Cookie-based authentication** with httpOnly cookies for XSS protection
- **JWT tokens** managed securely on server-side with automatic refresh
- **Role-based access control** (RBAC) with admin and user roles
- **Complete audit logging** for compliance and security monitoring
- **GDPR compliance** with data protection and user rights
- **Security headers** (HSTS, CSP, X-Frame-Options, etc.)
- **Input validation** and sanitization
- **CSRF protection** with secure cookies
- **Session management** with device tracking and automatic cleanup

### 🏗️ **Modern Development Experience**

- **TypeScript** throughout the stack for type safety
- **Modular architecture** with clear separation of concerns
- **Code quality** with ESLint and Prettier
- **Hot reload** for development efficiency
- **Standalone components** in Angular 19

### 📱 **Progressive Web App Features**

- **App-like experience** with responsive design
- **Theme switching** between light and dark modes
- **Internationalization** with English and Italian support
- **Performance optimization** with lazy loading
- **Web App Manifest** for install prompts
- **PWA-ready structure** for future service worker implementation

### 📊 **Monitoring & Operations**

```
┌─────────────────────────────────────────────────────────────┐
│                   MONITORING STACK                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Health    │  │   Metrics   │  │   Logging   │        │
│  │   Checks    │  │ Collection  │  │   System    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

- **Health checks** for system monitoring
- **Real-time metrics** collection and analysis
- **Structured logging** with correlation IDs
- **Performance monitoring** and alerting
- **Audit trail** for security compliance
- **User activity tracking** and analytics

### 🔄 **Authentication Flow**

```
┌─────────────────────────────────────────────────────────────┐
│                   AUTHENTICATION FLOW                       │
├─────────────────────────────────────────────────────────────┤
│  1. User Login → 2. Server Validation → 3. JWT Generation  │
│     ↓              ↓                    ↓                  │
│  Credentials    Password Check      httpOnly Cookies       │
│     ↓              ↓                    ↓                  │
│  4. Cookie Set → 5. Session Create → 6. Audit Log          │
│     ↓              ↓                    ↓                  │
│  Secure Storage  Device Tracking    Security Monitoring    │
└─────────────────────────────────────────────────────────────┘
```

- **Secure login** with bcrypt password hashing
- **httpOnly cookies** for token storage (XSS protection)
- **Automatic token refresh** with rotation
- **Session management** with device tracking
- **Audit logging** for security compliance
- **Role-based access** control

### 🌐 **Internationalization & Theming**

- **Multi-language support** (English/Italian)
- **Dynamic language switching** with persistence
- **Theme management** (light/dark mode)
- **System preference detection** for theme
- **Flag icons** for language selection
- **Localized content** throughout the application

## 🔄 Development Workflow

### Frontend Development
1. **Component Development** - Standalone Angular components
2. **Service Integration** - Cookie-based authentication
3. **PWA Configuration** - Web App Manifest and PWA-ready structure
4. **Theme Integration** - Light/dark mode switching
5. **Internationalization** - Multi-language support

### Backend Development
1. **API Development** - RESTful endpoints with validation
2. **Authentication** - JWT with httpOnly cookies
3. **Database Operations** - TypeORM with migrations
4. **Security Implementation** - Headers, rate limiting, audit
5. **File Storage** - MinIO integration

### Testing & Quality
1. **Unit Testing** - Component and service testing
2. **Integration Testing** - API endpoint testing
3. **Security Testing** - Authentication and authorization
4. **Performance Testing** - Load and stress testing

## 🚀 Deployment Strategy

### Development Environment
- **Docker Compose** for local development
- **Hot reload** for frontend and backend
- **Database seeding** for development data
- **MinIO** for file storage testing

### Production Environment
- **Container orchestration** with Docker
- **Environment-based configuration**
- **Health monitoring** and alerting
- **Backup strategies** for data protection
- **SSL/TLS** configuration for security

### Monitoring & Maintenance
- **Health check endpoints** for all services
- **Metrics collection** for performance monitoring
- **Audit logging** for security compliance
- **Automated backups** for data protection
- **Error tracking** and alerting

## 📚 Documentation Links

### 🚀 **Getting Started**
- [**Installation Guide**](./installation.md) - Complete setup step-by-step
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