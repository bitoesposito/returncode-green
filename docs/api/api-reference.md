# 📚 API Reference

## 📋 Panoramica API

**Pandom Stack** fornisce un'API REST completa e ben documentata per tutte le funzionalità dell'applicazione. L'API è progettata seguendo le best practices REST e include autenticazione basata su **httpOnly cookies**, validazione input, e gestione errori standardizzata.

## 🔐 **Autenticazione**

### **httpOnly Cookies Authentication**

L'applicazione utilizza un sistema di autenticazione basato su **httpOnly cookies** per massima sicurezza:

- **Access Token**: Cookie `access_token` (15 minuti)
- **Refresh Token**: Cookie `refresh_token` (7-30 giorni)
- **Automatic Refresh**: Gestione automatica del refresh token
- **CSRF Protection**: Protezione integrata contro attacchi CSRF

### **Ottenere un Token**

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

**Cookies impostati automaticamente:**
```
Set-Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Strict; Max-Age=900
Set-Cookie: refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
```

## 📊 **Formato Response Standard**

Tutte le API seguono un formato di response standardizzato:

```json
{
  "http_status_code": 200,
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    // Dati specifici dell'endpoint
  },
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 100,
    "total_pages": 10
  }
}
```

## 🚨 **Gestione Errori**

### **Formato Errori**

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

### **Codici di Stato HTTP**

| Codice | Descrizione |
|--------|-------------|
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

Registra un nuovo utente.

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

Autentica un utente esistente. Imposta automaticamente i cookie httpOnly.

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

Rinnova automaticamente i token usando i cookie httpOnly.

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

Ottiene i dati dell'utente corrente. Utilizza automaticamente i cookie per l'autenticazione.

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

Verifica l'email dell'utente.

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

Richiede il reset della password.

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

Resetta la password con OTP.

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

Rinvia l'email di verifica.

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

Effettua il logout dell'utente. Invalida i cookie automaticamente.

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

Ottiene il profilo dell'utente corrente.

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

Aggiorna il profilo dell'utente.

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

Ottiene i log di sicurezza dell'utente.

**Query Parameters:**
- `page` (number): Numero di pagina (default: 1)
- `limit` (number): Elementi per pagina (default: 10)

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

Ottiene le sessioni attive dell'utente.

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

Termina una sessione specifica.

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

Termina tutte le sessioni tranne quella corrente.

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

Richiede l'export dei dati utente (GDPR).

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

Elimina l'account utente (GDPR Right to Erasure).

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

Ottiene la lista degli utenti (solo admin).

**Query Parameters:**
- `page` (number): Numero di pagina (default: 1)
- `limit` (number): Elementi per pagina (default: 10)
- `search` (string): Ricerca per email

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

Elimina un utente (solo admin).

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

Ottiene le metriche del sistema.

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

Ottiene metriche dettagliate del sistema.

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

Ottiene i log di audit del sistema.

**Query Parameters:**
- `page` (number): Numero di pagina (default: 1)
- `limit` (number): Elementi per pagina (default: 50)

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

Verifica lo stato del sistema.

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

Crea un backup del sistema.

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

Lista i backup disponibili.

**Query Parameters:**
- `page` (number): Numero di pagina (default: 1)
- `limit` (number): Elementi per pagina (default: 10)

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

Ripristina il sistema da un backup.

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

L'API implementa rate limiting per proteggere da abusi:

### **Limiti Standard**
- **Autenticazione**: 5 tentativi per 15 minuti
- **API Generali**: 100 richieste per 15 minuti
- **Upload**: 10 file per ora
- **Export**: 5 export per giorno

### **Headers di Rate Limiting**

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640998800
```

## 📝 **Validazione Input**

Tutti gli endpoint validano l'input secondo questi schemi:

### **Email**
- Formato email valido
- Lunghezza massima: 255 caratteri

### **Password**
- Lunghezza minima: 8 caratteri
- Deve contenere: maiuscole, minuscole, numeri, simboli

### **UUID**
- Formato UUID v4 valido

### **Date**
- Formato ISO 8601: `YYYY-MM-DDTHH:mm:ss.sssZ`

## 🔍 **Ricerca e Filtri**

Molti endpoint supportano ricerca e filtri:

### **Ricerca Testuale**
```http
GET /admin/users?search=john
```

### **Filtri**
```http
GET /admin/users?role=user&status=active
```

### **Ordinamento**
```http
GET /admin/users?sort=createdAt&order=desc
```

### **Paginazione**
```http
GET /admin/users?page=2&limit=20
```

## 🔒 **Sicurezza**

### **httpOnly Cookies**
- I token sono memorizzati in cookie httpOnly per prevenire attacchi XSS
- I cookie sono marcati come Secure e SameSite=Strict
- Refresh automatico dei token

### **CSRF Protection**
- Protezione integrata contro attacchi CSRF
- Validazione dei token CSRF per operazioni sensibili

### **Audit Logging**
- Tutte le operazioni sono registrate nei log di audit
- Tracciamento IP e User Agent
- Log di sicurezza per eventi importanti

### **Session Management**
- Gestione avanzata delle sessioni
- Possibilità di terminare sessioni specifiche
- Monitoraggio delle sessioni attive

---

**Pandom Stack API** - API REST completa, sicura e ben documentata per applicazioni enterprise con autenticazione basata su httpOnly cookies.