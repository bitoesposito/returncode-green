# 📚 API Reference

## 📋 API Overview

**Pandom Stack** provides a complete and well-documented REST API for all application features. The API is designed following REST best practices and includes **httpOnly cookie-based authentication**, input validation, and standardized error handling.

## 🔐 **Authentication**

### **httpOnly Cookies Authentication**

The application uses an **httpOnly cookie-based authentication** system for maximum security:

- **Access Token**: `access_token` cookie (15 minutes)
- **Refresh Token**: `refresh_token` cookie (7-30 days)
- **Automatic Refresh**: Automatic refresh token management
- **CSRF Protection**: Built-in protection against CSRF attacks

### **Getting a Token**

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "rememberMe": false
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Login successful",
  "data": {
    "session_id": "session-uuid-123",
    "expires_in": 900,
    "user": {
      "uuid": "user-uuid",
      "email": "user@example.com",
      "role": "user",
      "is_verified": true,
      "is_active": true,
      "created_at": "2024-01-15T10:30:00.000Z",
      "updated_at": "2024-01-15T10:30:00.000Z",
      "last_login_at": "2024-01-15T10:30:00.000Z"
    },
    "profile": {
      "uuid": "profile-uuid",
      "tags": ["user"],
      "metadata": {}
    }
  }
}
```

**Cookies automatically set:**
```
Set-Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Strict; Max-Age=900
Set-Cookie: refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
```

## 📊 **Standard Response Format**

All APIs follow a standardized response format:

```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    // Endpoint-specific data
  },
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 100,
    "total_pages": 10
  }
}
```

## 🚨 **Error Handling**

### **Error Format**

```json
{
  "http_status_code": 400,
  "success": false,
  "message": "Validation failed",
  "errors": [
    {
      "field": "email",
      "message": "Email is required"
    }
  ]
}
```

### **HTTP Status Codes**

| Code | Description |
|------|-------------|
| `200` | Success |
| `201` | Created |
| `400` | Bad Request |
| `401` | Unauthorized |
| `403` | Forbidden |
| `404` | Not Found |
| `422` | Validation Error |
| `429` | Rate Limited |
| `500` | Internal Server Error |

## 🔐 **Authentication Endpoints**

### **POST /auth/register**

Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "confirmPassword": "password123"
}
```

**Response:**
```json
{
  "http_status_code": 201,
  "success": true,
  "message": "User registered successfully. Please check your email for verification.",
  "data": {
    "user": {
      "uuid": "user-uuid",
      "email": "user@example.com",
      "role": "user",
      "is_verified": false,
      "is_active": true,
      "created_at": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

### **POST /auth/login**

Authenticate an existing user. Automatically sets httpOnly cookies.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "rememberMe": false
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Login successful",
  "data": {
    "session_id": "session-uuid-123",
    "expires_in": 900,
    "user": {
      "uuid": "user-uuid",
      "email": "user@example.com",
      "role": "user",
      "is_verified": true,
      "is_active": true,
      "created_at": "2024-01-15T10:30:00.000Z",
      "updated_at": "2024-01-15T10:30:00.000Z",
      "last_login_at": "2024-01-15T10:30:00.000Z"
    },
    "profile": {
      "uuid": "profile-uuid",
      "tags": ["user"],
      "metadata": {}
    }
  }
}
```

### **POST /auth/refresh**

Automatically refresh tokens using httpOnly cookies.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "session_id": "session-uuid-123",
    "expires_in": 900
  }
}
```

### **GET /auth/me**

Get current user data. Automatically uses cookies for authentication.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "User data retrieved successfully",
  "data": {
    "user": {
      "uuid": "user-uuid",
      "email": "user@example.com",
      "role": "user",
      "is_verified": true,
      "is_active": true,
      "created_at": "2024-01-15T10:30:00.000Z",
      "updated_at": "2024-01-15T10:30:00.000Z",
      "last_login_at": "2024-01-15T10:30:00.000Z"
    },
    "profile": {
      "uuid": "profile-uuid",
      "tags": ["user"],
      "metadata": {},
      "created_at": "2024-01-15T10:30:00.000Z",
      "updated_at": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

### **POST /auth/verify**

Verify user email.

**Request:**
```json
{
  "token": "verification-token"
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Email verified successfully",
  "data": {
    "user": {
      "uuid": "user-uuid",
      "email": "user@example.com",
      "is_verified": true
    }
  }
}
```

### **POST /auth/forgot-password**

Request password reset.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Password reset email sent successfully",
  "data": {
    "email": "user@example.com"
  }
}
```

### **POST /auth/reset-password**

Reset password with OTP.

**Request:**
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "newPassword": "newpassword123",
  "confirmPassword": "newpassword123"
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Password reset successfully",
  "data": {
    "user": {
      "uuid": "user-uuid",
      "email": "user@example.com"
    }
  }
}
```

### **POST /auth/resend-verification**

Resend verification email.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Verification email resent successfully",
  "data": {
    "email": "user@example.com"
  }
}
```

### **POST /auth/logout**

Logout user. Automatically invalidates cookies.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Logout successful",
  "data": null
}
```

## 👤 **User Profile Endpoints**

### **GET /profile**

Get current user profile.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "uuid": "profile-uuid",
    "tags": ["developer", "backend"],
    "metadata": {
      "role": "admin",
      "preferences": {
        "theme": "dark",
        "language": "en"
      }
    },
    "created_at": "2024-01-15T10:30:00.000Z",
    "updated_at": "2024-01-15T10:30:00.000Z"
  }
}
```

### **PUT /profile**

Update user profile.

**Request:**
```json
{
  "tags": ["developer", "fullstack", "typescript"],
  "metadata": {
    "role": "admin",
    "preferences": {
      "theme": "dark",
      "language": "en",
      "notifications": true
    }
  }
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "uuid": "profile-uuid",
    "tags": ["developer", "fullstack", "typescript"],
    "metadata": {
      "role": "admin",
      "preferences": {
        "theme": "dark",
        "language": "en",
        "notifications": true
      }
    },
    "created_at": "2024-01-15T10:30:00.000Z",
    "updated_at": "2024-01-15T11:45:00.000Z"
  }
}
```

## 🛡️ **Security Endpoints**

### **GET /security/logs**

Get user security logs.

**Query Parameters:**
- `page` (number): Page number (default: 1)
- `limit` (number): Items per page (default: 10)

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Security logs retrieved successfully",
  "data": {
    "logs": [
      {
        "id": "log-uuid",
        "eventType": "USER_LOGIN_SUCCESS",
        "severity": "INFO",
        "userEmail": "user@example.com",
        "ipAddress": "192.168.1.100",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "timestamp": "2024-01-15T10:30:00.000Z",
        "details": {
          "device": "Desktop",
          "browser": "Chrome",
          "sessionId": "session-uuid-123"
        },
        "metadata": {}
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 150,
      "totalPages": 15
    }
  }
}
```

### **GET /security/sessions**

Get user active sessions.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Sessions retrieved successfully",
  "data": {
    "sessions": [
      {
        "id": "session-uuid",
        "eventType": "CREATED",
        "user": {
          "uuid": "user-uuid",
          "email": "user@example.com"
        },
        "sessionTokenHash": "hashed-token",
        "refreshTokenHash": "hashed-refresh-token",
        "deviceInfo": "Desktop - Chrome",
        "ipAddress": "192.168.1.100",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "timestamp": "2024-01-15T10:30:00.000Z",
        "details": {
          "sessionId": "session-uuid",
          "userId": "user-uuid",
          "rememberMe": false,
          "expiresAt": "2024-01-22T10:30:00.000Z"
        }
      }
    ]
  }
}
```

### **DELETE /security/sessions/{sessionId}**

Terminate a specific session.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Session terminated successfully",
  "data": {
    "sessionId": "session-uuid"
  }
}
```

### **DELETE /security/sessions/all**

Terminate all sessions except the current one.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "All sessions terminated successfully",
  "data": {
    "terminatedCount": 3
  }
}
```

### **GET /security/download-data**

Request user data export (GDPR).

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Data export initiated successfully",
  "data": {
    "downloadUrl": "https://api.pandom.com/security/downloads/user-data-user-uuid-timestamp.json",
    "expiresAt": "2024-01-16T10:30:00.000Z",
    "fileSize": "2.5 MB",
    "includes": [
      "personal_data",
      "usage_data",
      "security_logs",
      "preferences"
    ]
  }
}
```

### **DELETE /security/delete-account**

Delete user account (GDPR Right to Erasure).

**Request:**
```json
{
  "confirmation": "DELETE_MY_ACCOUNT",
  "reason": "No longer need the service"
}
```

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Account deletion initiated successfully",
  "data": {
    "deletionScheduled": "2024-01-22T10:30:00.000Z",
    "confirmationEmail": "user@example.com"
  }
}
```

## 👨‍💼 **Admin Endpoints**

### **GET /admin/users**

Get user list (admin only).

**Query Parameters:**
- `page` (number): Page number (default: 1)
- `limit` (number): Items per page (default: 10)
- `search` (string): Search by email

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Users retrieved successfully",
  "data": {
    "users": [
      {
        "uuid": "user-uuid",
        "email": "user@example.com",
        "role": "user",
        "is_verified": true,
        "is_active": true,
        "created_at": "2024-01-15T10:30:00.000Z",
        "updated_at": "2024-01-15T10:30:00.000Z",
        "last_login_at": "2024-01-15T10:30:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 150,
      "totalPages": 15
    }
  }
}
```

### **DELETE /admin/users/{uuid}**

Delete a user (admin only).

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "User deleted successfully",
  "data": {
    "uuid": "user-uuid",
    "email": "user@example.com"
  }
}
```

### **GET /admin/metrics**

Get system metrics.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "System metrics retrieved successfully",
  "data": {
    "users": {
      "total": 1500,
      "active": 1200,
      "newThisPeriod": 50,
      "growth": 3.5
    },
    "security": {
      "loginAttempts": 2500,
      "failedLogins": 150,
      "suspiciousActivities": 5,
      "dataExports": 25
    },
    "performance": {
      "averageResponseTime": 150,
      "uptime": 99.9,
      "errorRate": 0.1
    }
  }
}
```

### **GET /admin/metrics/detailed**

Get detailed system metrics.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Detailed metrics retrieved successfully",
  "data": {
    "totalRequests": 15000,
    "successfulRequests": 14850,
    "failedRequests": 150,
    "avgResponseTime": 150,
    "topEndpoints": [
      {
        "endpoint": "/auth/me",
        "requests": 5000,
        "avgResponseTime": 120
      }
    ],
    "errorBreakdown": [
      {
        "statusCode": 400,
        "count": 100,
        "percentage": 0.67
      }
    ]
  }
}
```

### **GET /admin/audit-logs**

Get system audit logs.

**Query Parameters:**
- `page` (number): Page number (default: 1)
- `limit` (number): Items per page (default: 50)

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Audit logs retrieved successfully",
  "data": {
    "logs": [
      {
        "id": "audit-uuid",
        "eventType": "USER_LOGIN_SUCCESS",
        "status": "SUCCESS",
        "user": {
          "uuid": "user-uuid",
          "email": "user@example.com"
        },
        "sessionId": "session-uuid-123",
        "ipAddress": "192.168.1.100",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "resource": "/auth/login",
        "action": "POST",
        "timestamp": "2024-01-15T10:30:00.000Z",
        "details": {
          "device": "Desktop",
          "browser": "Chrome"
        }
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 5000,
      "totalPages": 100
    }
  }
}
```

## 🔧 **Resilience Endpoints**

### **GET /resilience/status**

Check system status.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "System status retrieved successfully",
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "version": "1.0.0",
    "uptime": 86400,
    "services": {
      "database": "healthy",
      "storage": "healthy",
      "email": "degraded"
    }
  }
}
```

### **POST /resilience/backup**

Create system backup.

**Response:**
```json
{
  "http_status_code": 201,
  "success": true,
  "message": "System backup created and uploaded to MinIO successfully",
  "data": {
    "backup_id": "2024-01-15T10-30-00-000Z",
    "backup_file": "backup-2024-01-15T10-30-00-000Z.sql",
    "backup_size": 1048576,
    "created_at": "2024-01-15T10:30:00.000Z",
    "status": "completed"
  }
}
```

### **GET /resilience/backup**

List available backups.

**Query Parameters:**
- `page` (number): Page number (default: 1)
- `limit` (number): Items per page (default: 10)

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Backups retrieved successfully",
  "data": {
    "backups": [
      {
        "backup_id": "2024-01-15T10-30-00-000Z",
        "backup_file": "backup-2024-01-15T10-30-00-000Z.sql",
        "backup_size": 1048576,
        "created_at": "2024-01-15T10:30:00.000Z",
        "status": "completed"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 25,
      "totalPages": 3
    }
  }
}
```

### **POST /resilience/backup/{backupId}/restore**

Restore system from backup.

**Response:**
```json
{
  "http_status_code": 200,
  "success": true,
  "message": "System restored from backup successfully",
  "data": {
    "backup_id": "2024-01-15T10-30-00-000Z",
    "restored_at": "2024-01-15T11:00:00.000Z",
    "status": "completed"
  }
}
```

## 🔄 **Rate Limiting**

The API implements rate limiting to protect against abuse:

### **Standard Limits**
- **Authentication**: 5 attempts per 15 minutes
- **General API**: 100 requests per 15 minutes
- **Upload**: 10 files per hour
- **Export**: 5 exports per day

### **Rate Limiting Headers**

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640998800
```

## 📝 **Input Validation**

All endpoints validate input according to these schemas:

### **Email**
- Valid email format
- Maximum length: 255 characters

### **Password**
- Minimum length: 8 characters
- Must contain: uppercase, lowercase, numbers, symbols

### **UUID**
- Valid UUID v4 format

### **Date**
- ISO 8601 format: `YYYY-MM-DDTHH:mm:ss.sssZ`

## 🔍 **Search and Filters**

Many endpoints support search and filters:

### **Text Search**
```http
GET /admin/users?search=john
```

### **Filters**
```http
GET /admin/users?role=user&status=active
```

### **Sorting**
```http
GET /admin/users?sort=createdAt&order=desc
```

### **Pagination**
```http
GET /admin/users?page=2&limit=20
```

## 🔒 **Security**

### **httpOnly Cookies**
- Tokens are stored in httpOnly cookies to prevent XSS attacks
- Cookies are marked as Secure and SameSite=Strict
- Automatic token refresh

### **CSRF Protection**
- Built-in protection against CSRF attacks
- CSRF token validation for sensitive operations

### **Audit Logging**
- All operations are logged in audit logs
- IP and User Agent tracking
- Security logs for important events

### **Session Management**
- Advanced session management
- Ability to terminate specific sessions
- Active session monitoring

---

**Pandom Stack API** - Complete, secure, and well-documented REST API for enterprise applications with httpOnly cookie-based authentication.
