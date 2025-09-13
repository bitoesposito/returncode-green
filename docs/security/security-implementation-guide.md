# 🔒 Security Implementation Guide

## 📋 Panoramica Sicurezza

**Pandom Stack** implementa un sistema di sicurezza robusto e moderno basato su **httpOnly cookies**, JWT tokens, e best practices di sicurezza enterprise. Questa guida fornisce una panoramica completa dell'implementazione di sicurezza.

## 🔐 **Sistema di Autenticazione**

### **httpOnly Cookies Authentication**

Il sistema utilizza cookie httpOnly per massima sicurezza:

```typescript
// Backend - Impostazione cookie
response.cookie('access_token', session.token, {
  httpOnly: true,        // Previene accesso JavaScript
  secure: true,          // Solo HTTPS
  sameSite: 'strict',    // Protezione CSRF
  maxAge: 15 * 60 * 1000 // 15 minuti
});

response.cookie('refresh_token', session.refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 giorni
});
```

### **Frontend - Gestione Automatica**

```typescript
// CookieAuthService - Gestione automatica
@Injectable()
export class CookieAuthService {
  // I cookie vengono inviati automaticamente
  // Non è necessario gestire manualmente i token
}
```

### **Vantaggi httpOnly Cookies**

- ✅ **XSS Protection**: I token non sono accessibili via JavaScript
- ✅ **Automatic Management**: I browser gestiscono automaticamente i cookie
- ✅ **CSRF Protection**: SameSite=Strict previene attacchi CSRF
- ✅ **Secure Transport**: Solo HTTPS in produzione

## 🛡️ **Architettura di Sicurezza**

### **Backend Security Stack**

```typescript
// 1. Guards per protezione endpoint
@UseGuards(CookieAuthGuard, RolesGuard)
@Roles(UserRole.admin)
export class AdminController {}

// 2. Interceptors per logging
@Injectable()
export class SecurityHeadersInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    const response = context.switchToHttp().getResponse();
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('X-XSS-Protection', '1; mode=block');
    return next.handle();
  }
}

// 3. Audit logging automatico
@Injectable()
export class AuditService {
  async logLoginSuccess(userId: string, userEmail: string, ipAddress: string) {
    // Log automatico di tutti gli eventi di sicurezza
  }
}
```

### **Frontend Security Stack**

```typescript
// 1. Interceptors per gestione automatica
@Injectable()
export class CookieAuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler) {
    // I cookie vengono inviati automaticamente
    return next.handle(req);
  }
}

// 2. Guards per protezione route
@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(route: ActivatedRouteSnapshot): boolean {
    return this.cookieAuthService.isAuthenticated();
  }
}
```

## 🔑 **Gestione Token e Sessioni**

### **Token Lifecycle**

```typescript
// 1. Login - Creazione sessioni
async login(loginDto: LoginDto, response: Response) {
  // Crea sessione
  const session = await this.sessionService.createSession({
    userId: user.uuid,
    deviceInfo,
    ipAddress,
    userAgent,
    rememberMe: loginDto.rememberMe
  });

  // Imposta cookie
  response.cookie('access_token', session.token, cookieOptions);
  response.cookie('refresh_token', session.refreshToken, cookieOptions);
}

// 2. Refresh automatico
async refreshToken(request: Request) {
  const refreshToken = request.cookies.refresh_token;
  // Valida e crea nuovo access token
  const newToken = this.jwtService.sign(payload);
  return { access_token: newToken };
}

// 3. Logout - Pulizia
async logout(response: Response) {
  response.clearCookie('access_token');
  response.clearCookie('refresh_token');
}
```

### **Session Management**

```typescript
// SessionService - Gestione avanzata sessioni
@Injectable()
export class SessionService {
  // Creazione sessione con metadati
  async createSession(options: CreateSessionOptions): Promise<Session> {
    const session = {
      id: crypto.randomUUID(),
      userId: options.userId,
      token: this.jwtService.sign(payload),
      refreshToken: this.jwtService.sign(refreshPayload),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      deviceInfo: options.deviceInfo,
      ipAddress: options.ipAddress,
      userAgent: options.userAgent,
      isActive: true
    };

    // Salva in memoria e database
    this.sessions.set(session.id, session);
    await this.sessionLogRepository.save(sessionLog);
    
    return session;
  }
}
```

## 📊 **Audit Logging e Monitoring**

### **Security Logs**

```typescript
// SecurityLog Entity
@Entity('security_logs')
export class SecurityLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'event_type' })
  eventType: string; // USER_LOGIN_SUCCESS, BRUTE_FORCE_ATTEMPT, etc.

  @Column({ name: 'severity' })
  severity: string; // INFO, WARNING, ERROR, CRITICAL

  @ManyToOne(() => User, { nullable: true })
  user: User;

  @Column({ name: 'ip_address' })
  ipAddress: string;

  @Column({ name: 'user_agent' })
  userAgent: string;

  @Column({ name: 'details', type: 'jsonb' })
  details: Record<string, any>;
}
```

### **Audit Logs**

```typescript
// AuditLog Entity
@Entity('audit_logs')
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'event_type' })
  eventType: string; // USER_LOGIN_SUCCESS, DATA_ACCESS, etc.

  @Column({ name: 'status' })
  status: string; // SUCCESS, FAILED, WARNING

  @ManyToOne(() => User, { nullable: true })
  user: User;

  @Column({ name: 'session_id' })
  sessionId: string;

  @Column({ name: 'resource' })
  resource: string; // /auth/login, /admin/users, etc.

  @Column({ name: 'action' })
  action: string; // GET, POST, PUT, DELETE
}
```

### **Logging Automatico**

```typescript
// Interceptor per logging automatico
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    
    return next.handle().pipe(
      tap(() => {
        // Log automatico di tutte le richieste
        this.auditService.log({
          eventType: this.getEventType(request),
          status: response.statusCode < 400 ? 'SUCCESS' : 'FAILED',
          user: request.user,
          sessionId: request.user?.sessionId,
          resource: request.url,
          action: request.method,
          ipAddress: this.getClientIp(request),
          userAgent: request.headers['user-agent']
        });
      })
    );
  }
}
```

## 🔒 **Protezione Endpoint**

### **Guards Implementation**

```typescript
// CookieAuthGuard - Verifica autenticazione
@Injectable()
export class CookieAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.cookies.access_token;

    if (!token) {
      throw new UnauthorizedException('No access token provided');
    }

    try {
      const payload = this.jwtService.verify(token);
      request.user = payload;
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}

// RolesGuard - Controllo ruoli
@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
    const user = context.switchToHttp().getRequest().user;

    if (!requiredRoles) {
      return true;
    }

    return requiredRoles.some(role => user.role === role);
  }
}
```

### **Protezione Route Frontend**

```typescript
// AuthGuard - Protezione route
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private cookieAuthService: CookieAuthService) {}

  canActivate(route: ActivatedRouteSnapshot): boolean {
    if (this.cookieAuthService.isAuthenticated()) {
      return true;
    }
    
    this.router.navigate(['/auth/login']);
    return false;
  }
}

// RoleGuard - Controllo ruoli
@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private cookieAuthService: CookieAuthService,
    private router: Router
  ) {}

  canActivate(route: ActivatedRouteSnapshot): boolean {
    const requiredRoles = route.data['roles'] as string[];
    const userRole = this.cookieAuthService.getUserRole();

    if (requiredRoles && !requiredRoles.includes(userRole)) {
      this.router.navigate(['/unauthorized']);
      return false;
    }

    return true;
  }
}
```

## 🛡️ **Sicurezza Headers**

### **Security Headers Interceptor**

```typescript
@Injectable()
export class SecurityHeadersInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    const response = context.switchToHttp().getResponse();
    
    // Security headers
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('X-XSS-Protection', '1; mode=block');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    // CSP Header
    response.setHeader('Content-Security-Policy', 
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https:; " +
      "connect-src 'self'"
    );

    return next.handle();
  }
}
```

## 🔐 **Password Security**

### **Password Hashing**

```typescript
// AuthService - Hashing sicuro
async hashPassword(password: string): Promise<string> {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

async validatePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### **Password Validation**

```typescript
// DTO Validation
export class RegisterDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain uppercase, lowercase, number and special character'
  })
  password: string;
}
```

## 🚨 **Rate Limiting**

### **Rate Limiting Implementation**

```typescript
// Rate limiting per endpoint
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly attempts = new Map<string, number[]>();

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const ip = this.getClientIp(request);
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minuti
    const maxAttempts = 5;

    const attempts = this.attempts.get(ip) || [];
    const recentAttempts = attempts.filter(time => now - time < windowMs);

    if (recentAttempts.length >= maxAttempts) {
      throw new TooManyRequestsException('Too many login attempts');
    }

    recentAttempts.push(now);
    this.attempts.set(ip, recentAttempts);

    return true;
  }
}
```

## 🔍 **Security Monitoring**

### **Suspicious Activity Detection**

```typescript
@Injectable()
export class SecurityService {
  async detectSuspiciousActivity(userId: string, ipAddress: string, userAgent: string) {
    // Controlla login da IP diversi
    const recentLogins = await this.getRecentLogins(userId, 24); // ultime 24h
    const uniqueIPs = new Set(recentLogins.map(login => login.ipAddress));
    
    if (uniqueIPs.size > 3) {
      await this.logSecurityEvent({
        eventType: 'SUSPICIOUS_ACTIVITY',
        severity: 'WARNING',
        userId,
        ipAddress,
        userAgent,
        details: { reason: 'Multiple IP addresses in 24h' }
      });
    }

    // Controlla user agent sospetti
    if (this.isSuspiciousUserAgent(userAgent)) {
      await this.logSecurityEvent({
        eventType: 'SUSPICIOUS_ACTIVITY',
        severity: 'WARNING',
        userId,
        ipAddress,
        userAgent,
        details: { reason: 'Suspicious user agent' }
      });
    }
  }
}
```

## 📱 **GDPR Compliance**

### **Data Export**

```typescript
@Injectable()
export class SecurityService {
  async downloadUserData(userId: string) {
    const user = await this.userRepository.findOne({ where: { uuid: userId } });
    const profile = await this.profileRepository.findOne({ where: { user_uuid: userId } });
    const securityLogs = await this.getUserSecurityLogs(userId);
    const auditLogs = await this.getUserAuditLogs(userId);

    const exportData = {
      user: {
        uuid: user.uuid,
        email: user.email,
        role: user.role,
        created_at: user.created_at,
        last_login_at: user.last_login_at
      },
      profile: profile,
      security_logs: securityLogs,
      audit_logs: auditLogs,
      export_info: {
        exported_at: new Date().toISOString(),
        requested_by: userId,
        format: 'JSON'
      }
    };

    return exportData;
  }
}
```

### **Account Deletion**

```typescript
@Injectable()
export class SecurityService {
  async deleteUserAccount(userId: string, reason: string) {
    // Log della richiesta
    await this.auditService.log({
      eventType: 'USER_ACCOUNT_DELETION',
      status: 'SUCCESS',
      userId,
      details: { reason }
    });

    // Elimina dati utente
    await this.userRepository.delete({ uuid: userId });
    await this.profileRepository.delete({ user_uuid: userId });
    
    // Elimina sessioni
    await this.sessionService.invalidateAllUserSessions(userId);
    
    // Elimina log (opzionale, per compliance)
    // await this.deleteUserLogs(userId);
  }
}
```

## 🔧 **Configurazione Sicurezza**

### **Environment Variables**

```bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# Cookie Configuration
COOKIE_SECRET=your-cookie-secret-here
COOKIE_DOMAIN=yourdomain.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_ATTEMPTS=5

# Security
BCRYPT_ROUNDS=12
SESSION_TIMEOUT=3600000
```

### **Production Security Checklist**

- ✅ **HTTPS Only**: Tutti i cookie e token solo su HTTPS
- ✅ **Secure Headers**: Headers di sicurezza configurati
- ✅ **Rate Limiting**: Protezione contro brute force
- ✅ **Audit Logging**: Log di tutte le operazioni
- ✅ **Session Management**: Gestione avanzata sessioni
- ✅ **Password Security**: Hashing sicuro con bcrypt
- ✅ **Input Validation**: Validazione di tutti gli input
- ✅ **CORS Configuration**: CORS configurato correttamente
- ✅ **Error Handling**: Gestione errori senza leak di informazioni

## 🚀 **Deployment Security**

### **Docker Security**

```dockerfile
# Backend Dockerfile
FROM node:18-alpine

# Crea utente non-root
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Copia e installa dipendenze
COPY package*.json ./
RUN npm ci --only=production

# Copia codice
COPY --chown=nestjs:nodejs . .

# Cambia utente
USER nestjs

# Esponi porta
EXPOSE 3000

# Avvia applicazione
CMD ["node", "dist/main"]
```

### **Nginx Security Configuration**

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Proxy to backend
    location /api {
        proxy_pass http://backend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

**Pandom Stack Security** - Sistema di sicurezza enterprise-grade con autenticazione httpOnly cookies, audit logging completo, e compliance GDPR.
