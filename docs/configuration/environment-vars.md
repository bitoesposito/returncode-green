# 🔧 Environment Variables

## 📋 Overview

**Pandom Stack** uses environment variables to configure all aspects of the application. This documentation provides a complete guide for all available variables, their default values, and recommended configurations for different environments.

## 🏗️ **.env File Structure**

The `.env` file is organized in logical sections to facilitate configuration:

```env
# ============================================================================
# CONFIGURAZIONE BASE
# ============================================================================

# ============================================================================
# CONFIGURAZIONE DATABASE
# ============================================================================

# ============================================================================
# CONFIGURAZIONE SERVER
# ============================================================================

# ============================================================================
# CONFIGURAZIONE FRONTEND
# ============================================================================

# ============================================================================
# CONFIGURAZIONE UTENTE AMMINISTRATORE
# ============================================================================

# ============================================================================
# CONFIGURAZIONE JWT E SESSIONI
# ============================================================================

# ============================================================================
# CONFIGURAZIONE EMAIL
# ============================================================================

# ============================================================================
# CONFIGURAZIONE MINIO
# ============================================================================

# ============================================================================
# CONFIGURAZIONE SICUREZZA E COOKIE
# ============================================================================

# ============================================================================
# CONFIGURAZIONE MONITORING
# ============================================================================
```

## 🌐 **Configurazione Base**

### **URL**
```env
# Dominio principale dell'applicazione
URL=localhost
```
- **Tipo**: String
- **Default**: `localhost`
- **Descrizione**: Dominio principale utilizzato per generare URL assoluti
- **Esempio**: `yourdomain.com`, `app.example.com`

## 🗄️ **Configurazione Database**

### **PostgreSQL Configuration**

```env
# Host del database PostgreSQL
DB_HOST=postgres

# Credenziali PostgreSQL
POSTGRES_USER=pandom_user
POSTGRES_PASSWORD=secure_password_123
POSTGRES_DB=pandom_db

# Porta PostgreSQL
POSTGRES_PORT=5432

# URL di connessione database
DATABASE_URL=postgres://pandom_user:secure_password_123@postgres:5432/pandom_db
DB_URL=postgres://pandom_user:secure_password_123@postgres:5432/pandom_db
```

#### **DB_HOST**
- **Tipo**: String
- **Default**: `postgres`
- **Descrizione**: Host del server PostgreSQL
- **Ambiente Docker**: `postgres` (nome del servizio)
- **Ambiente Esterno**: `your-db-host.com`

#### **POSTGRES_USER**
- **Tipo**: String
- **Default**: `pandom_user`
- **Descrizione**: Username per la connessione al database
- **Sicurezza**: Usa un username specifico per l'applicazione

#### **POSTGRES_PASSWORD**
- **Tipo**: String
- **Default**: `secure_password_123`
- **Descrizione**: Password per la connessione al database
- **Sicurezza**: Usa una password forte e unica
- **Generazione**: `openssl rand -base64 32`

#### **POSTGRES_DB**
- **Tipo**: String
- **Default**: `pandom_db`
- **Descrizione**: Nome del database
- **Convenzione**: Usa un nome descrittivo per l'applicazione

#### **POSTGRES_PORT**
- **Tipo**: Number
- **Default**: `5432`
- **Descrizione**: Porta del server PostgreSQL
- **Standard**: `5432` (porta standard PostgreSQL)

#### **DATABASE_URL / DB_URL**
- **Tipo**: String
- **Default**: `postgres://pandom_user:secure_password_123@postgres:5432/pandom_db`
- **Descrizione**: URL completo di connessione al database
- **Formato**: `postgres://username:password@host:port/database`

## 🖥️ **Configurazione Server**

### **Backend Configuration**

```env
# Porta del backend
BE_PORT=3000

# URL del backend
BE_URL=http://localhost:3000

# Modalità Node.js
NODE_ENV=development
```

#### **BE_PORT**
- **Tipo**: Number
- **Default**: `3000`
- **Descrizione**: Porta su cui il server backend ascolta
- **Range**: `1024-65535`
- **Conflitti**: Evita porte già in uso (80, 443, 8080)

#### **BE_URL**
- **Tipo**: String
- **Default**: `http://localhost:3000`
- **Descrizione**: URL completo del backend
- **Formato**: `http://host:port` o `https://host:port`

#### **NODE_ENV**
- **Tipo**: String
- **Default**: `development`
- **Valori**: `development`, `staging`, `production`
- **Descrizione**: Ambiente di esecuzione Node.js

## 🎨 **Configurazione Frontend**

### **Angular Configuration**

```env
# Porta del frontend
FE_PORT=4200

# URL del frontend
FE_URL=http://localhost:4200

# Modalità produzione
PRODUCTION=false
```

#### **FE_PORT**
- **Tipo**: Number
- **Default**: `4200`
- **Descrizione**: Porta su cui il server frontend ascolta
- **Range**: `1024-65535`
- **Conflitti**: Evita porte già in uso

#### **FE_URL**
- **Tipo**: String
- **Default**: `http://localhost:4200`
- **Descrizione**: URL completo del frontend
- **Formato**: `http://host:port` o `https://host:port`

#### **PRODUCTION**
- **Tipo**: Boolean
- **Default**: `false`
- **Descrizione**: Abilita modalità produzione
- **Effetti**: Disabilita debug, abilita ottimizzazioni

## 👤 **Configurazione Utente Amministratore**

### **Admin User Setup**

```env
# Email amministratore
ADMIN_EMAIL=admin@pandom.com

# Ruolo amministratore
ADMIN_ROLE=admin

# Password amministratore (in chiaro)
ADMIN_PASSWORD=admin123

# Password amministratore (hashata)
ADMIN_HASHED_PASSWORD=
```

#### **ADMIN_EMAIL**
- **Tipo**: String
- **Default**: `admin@pandom.com`
- **Descrizione**: Email dell'utente amministratore
- **Formato**: Email valida
- **Sicurezza**: Usa un email reale per ricevere notifiche

#### **ADMIN_ROLE**
- **Tipo**: String
- **Default**: `admin`
- **Descrizione**: Ruolo dell'utente amministratore
- **Valori**: `admin`, `super_admin`
- **Permessi**: Accesso completo al sistema

#### **ADMIN_PASSWORD**
- **Tipo**: String
- **Default**: `admin123`
- **Descrizione**: Password in chiaro per l'amministratore
- **Sicurezza**: Cambia immediatamente dopo l'installazione
- **Requisiti**: Minimo 8 caratteri, maiuscole, numeri, simboli

#### **ADMIN_HASHED_PASSWORD**
- **Tipo**: String
- **Default**: `''`
- **Descrizione**: Password hashata per l'amministratore
- **Generazione**: `npm run generate-password-hash`
- **Sicurezza**: Priorità su ADMIN_PASSWORD se presente

## 🔐 **Configurazione JWT e Sessioni**

### **JWT Authentication**

```env
# Chiave segreta JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Scadenza token JWT
JWT_EXPIRATION=15m

# Scadenza refresh token
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
- **Tipo**: String
- **Default**: `your-super-secret-jwt-key-change-this-in-production`
- **Descrizione**: Chiave segreta per firmare i token JWT
- **Sicurezza**: **CAMBIARE IN PRODUZIONE**
- **Generazione**: `openssl rand -base64 64`
- **Lunghezza**: Minimo 32 caratteri

#### **JWT_EXPIRATION**
- **Tipo**: String
- **Default**: `15m`
- **Descrizione**: Tempo di scadenza dei token JWT
- **Formato**: `Xs` (secondi), `Xm` (minuti), `Xh` (ore), `Xd` (giorni)
- **Esempi**: `15m`, `1h`, `7d`
- **Sicurezza**: Breve per ridurre i rischi

#### **JWT_REFRESH_EXPIRATION**
- **Tipo**: String
- **Default**: `7d`
- **Descrizione**: Tempo di scadenza dei refresh token
- **Formato**: `Xs` (secondi), `Xm` (minuti), `Xh` (ore), `Xd` (giorni)
- **Esempi**: `7d`, `30d`
- **Sicurezza**: Più lungo del token di accesso

#### **COOKIE_SECRET**
- **Tipo**: String
- **Default**: `your-cookie-secret-here`
- **Descrizione**: Chiave segreta per firmare i cookie
- **Sicurezza**: Diversa da JWT_SECRET
- **Generazione**: `openssl rand -base64 32`

#### **COOKIE_DOMAIN**
- **Tipo**: String
- **Default**: `yourdomain.com`
- **Descrizione**: Dominio per i cookie
- **Sviluppo**: `localhost`
- **Produzione**: Dominio reale

#### **COOKIE_SECURE**
- **Tipo**: Boolean
- **Default**: `true`
- **Descrizione**: Cookie solo su HTTPS
- **Sviluppo**: `false`
- **Produzione**: `true`

#### **COOKIE_SAME_SITE**
- **Tipo**: String
- **Default**: `strict`
- **Descrizione**: Protezione CSRF
- **Valori**: `strict`, `lax`, `none`
- **Sicurezza**: `strict` per massima protezione

#### **SESSION_TIMEOUT**
- **Tipo**: Number
- **Default**: `3600000` (1 ora)
- **Descrizione**: Timeout sessione in millisecondi
- **Sicurezza**: Breve per ridurre i rischi

#### **SESSION_CLEANUP_INTERVAL**
- **Tipo**: Number
- **Default**: `300000` (5 minuti)
- **Descrizione**: Intervallo pulizia sessioni scadute
- **Performance**: Evita accumulo sessioni

## 📧 **Configurazione Email**

### **SMTP Configuration**

```env
# Host SMTP
SMTP_HOST=smtp.gmail.com

# Porta SMTP
SMTP_PORT=587

# Utente SMTP
SMTP_USER=your-email@gmail.com

# Password SMTP
SMTP_PASS=your-app-password

# Email mittente
SMTP_FROM=noreply@pandom.com

# Abilita email
SMTP_ENABLED=false
```

#### **SMTP_HOST**
- **Tipo**: String
- **Default**: `smtp.gmail.com`
- **Descrizione**: Host del server SMTP
- **Provider comuni**:
  - Gmail: `smtp.gmail.com`
  - Outlook: `smtp-mail.outlook.com`
  - SendGrid: `smtp.sendgrid.net`
  - AWS SES: `email-smtp.us-east-1.amazonaws.com`

#### **SMTP_PORT**
- **Tipo**: Number
- **Default**: `587`
- **Descrizione**: Porta del server SMTP
- **Porte comuni**:
  - `587`: STARTTLS (raccomandato)
  - `465`: SSL/TLS
  - `25`: Non sicuro (non raccomandato)

#### **SMTP_USER**
- **Tipo**: String
- **Default**: `your-email@gmail.com`
- **Descrizione**: Username per l'autenticazione SMTP
- **Gmail**: Email completa
- **SendGrid**: `apikey`

#### **SMTP_PASS**
- **Tipo**: String
- **Default**: `your-app-password`
- **Descrizione**: Password per l'autenticazione SMTP
- **Gmail**: Password app (non password account)
- **SendGrid**: API key

#### **SMTP_FROM**
- **Tipo**: String
- **Default**: `noreply@pandom.com`
- **Descrizione**: Email mittente per le notifiche
- **Formato**: Email valida
- **Dominio**: Deve corrispondere al dominio configurato

#### **SMTP_ENABLED**
- **Tipo**: Boolean
- **Default**: `false`
- **Descrizione**: Abilita l'invio di email
- **Sviluppo**: `false` (disabilita email)
- **Produzione**: `true` (abilita email)

## 📁 **Configurazione MinIO**

### **File Storage Configuration**

```env
# Utente root MinIO
MINIO_ROOT_USER=minioadmin

# Password root MinIO
MINIO_ROOT_PASSWORD=minioadmin123

# Endpoint MinIO
MINIO_ENDPOINT=http://minio:9000

# Porta MinIO
MINIO_PORT=9000

# Usa SSL per MinIO
MINIO_USE_SSL=false

# Nome bucket MinIO
MINIO_BUCKET_NAME=pandom-bucket

# Abilita MinIO
MINIO_ENABLED=true
```

#### **MINIO_ROOT_USER**
- **Tipo**: String
- **Default**: `minioadmin`
- **Descrizione**: Username root per MinIO
- **Sicurezza**: Cambia in produzione
- **Lunghezza**: 3-20 caratteri

#### **MINIO_ROOT_PASSWORD**
- **Tipo**: String
- **Default**: `minioadmin123`
- **Descrizione**: Password root per MinIO
- **Sicurezza**: Cambia in produzione
- **Lunghezza**: Minimo 8 caratteri

#### **MINIO_ENDPOINT**
- **Tipo**: String
- **Default**: `http://minio:9000`
- **Descrizione**: Endpoint del server MinIO
- **Docker**: `http://minio:9000`
- **Esterno**: `https://your-minio-server.com`

#### **MINIO_PORT**
- **Tipo**: Number
- **Default**: `9000`
- **Descrizione**: Porta del server MinIO
- **Standard**: `9000` (API), `9001` (Console)

#### **MINIO_USE_SSL**
- **Tipo**: Boolean
- **Default**: `false`
- **Descrizione**: Usa SSL/TLS per MinIO
- **Sviluppo**: `false`
- **Produzione**: `true`

#### **MINIO_BUCKET_NAME**
- **Tipo**: String
- **Default**: `pandom-bucket`
- **Descrizione**: Nome del bucket per i file
- **Convenzione**: Nome descrittivo per l'applicazione
- **Formato**: Solo lettere minuscole, numeri, trattini

#### **MINIO_ENABLED**
- **Tipo**: Boolean
- **Default**: `true`
- **Descrizione**: Abilita il servizio MinIO
- **Sviluppo**: `true`
- **Produzione**: `true` (se non usi S3 esterno)

## 🛡️ **Configurazione Sicurezza**

### **Security Settings**

```env
# Abilita security headers
SECURITY_HEADERS_ENABLED=false

# Rate limiting window (ms)
RATE_LIMIT_WINDOW=900000

# Rate limiting max requests
RATE_LIMIT_MAX_REQUESTS=100

# Abilita HTTPS
HTTPS_ENABLED=false

# Path certificato SSL
SSL_CERT_PATH=/path/to/cert.pem

# Path chiave SSL
SSL_KEY_PATH=/path/to/key.pem

# Abilita CORS
CORS_ENABLED=true

# Origini CORS permesse
CORS_ORIGINS=http://localhost:4200,http://localhost:3000
```

#### **SECURITY_HEADERS_ENABLED**
- **Tipo**: Boolean
- **Default**: `false`
- **Descrizione**: Abilita gli header di sicurezza HTTP
- **Sviluppo**: `false` (per debugging)
- **Produzione**: `true` (obbligatorio)

#### **RATE_LIMIT_WINDOW**
- **Tipo**: Number
- **Default**: `900000` (15 minuti)
- **Descrizione**: Finestra temporale per il rate limiting
- **Unità**: Millisecondi
- **Esempi**: `60000` (1 min), `300000` (5 min)

#### **RATE_LIMIT_MAX_REQUESTS**
- **Tipo**: Number
- **Default**: `100`
- **Descrizione**: Numero massimo di richieste per finestra
- **Sviluppo**: `1000` (più permissivo)
- **Produzione**: `50` (più restrittivo)

#### **HTTPS_ENABLED**
- **Tipo**: Boolean
- **Default**: `false`
- **Descrizione**: Abilita HTTPS
- **Sviluppo**: `false`
- **Produzione**: `true` (obbligatorio)

#### **SSL_CERT_PATH**
- **Tipo**: String
- **Default**: `/path/to/cert.pem`
- **Descrizione**: Percorso del certificato SSL
- **Formato**: File `.pem` o `.crt`
- **Generazione**: Let's Encrypt o certificato commerciale

#### **SSL_KEY_PATH**
- **Tipo**: String
- **Default**: `/path/to/key.pem`
- **Descrizione**: Percorso della chiave privata SSL
- **Formato**: File `.pem` o `.key`
- **Sicurezza**: Mantieni privata e sicura

#### **CORS_ENABLED**
- **Tipo**: Boolean
- **Default**: `true`
- **Descrizione**: Abilita CORS per richieste cross-origin
- **Sviluppo**: `true`
- **Produzione**: Configura specificamente

#### **CORS_ORIGINS**
- **Tipo**: String
- **Default**: `http://localhost:4200,http://localhost:3000`
- **Descrizione**: Origini permesse per CORS
- **Formato**: Lista separata da virgole
- **Esempi**: `https://yourdomain.com,https://app.yourdomain.com`

## 📊 **Configurazione Monitoring**

### **Monitoring Settings**

```env
# Abilita health checks
HEALTH_CHECKS_ENABLED=true

# Abilita metrics
METRICS_ENABLED=true

# Abilita audit logging
AUDIT_LOGGING_ENABLED=true

# Livello di log
LOG_LEVEL=info

# Abilita debug mode
DEBUG_MODE=false
```

#### **HEALTH_CHECKS_ENABLED**
- **Tipo**: Boolean
- **Default**: `true`
- **Descrizione**: Abilita i controlli di salute
- **Endpoint**: `/health`
- **Monitoraggio**: Container orchestration

#### **METRICS_ENABLED**
- **Tipo**: Boolean
- **Default**: `true`
- **Descrizione**: Abilita la raccolta di metriche
- **Endpoint**: `/metrics`
- **Monitoraggio**: Prometheus, Grafana

#### **AUDIT_LOGGING_ENABLED**
- **Tipo**: Boolean
- **Default**: `true`
- **Descrizione**: Abilita il logging di audit
- **Compliance**: GDPR, SOX, HIPAA
- **Storage**: Database + file system

#### **LOG_LEVEL**
- **Tipo**: String
- **Default**: `info`
- **Descrizione**: Livello di dettaglio dei log
- **Valori**: `error`, `warn`, `info`, `debug`, `verbose`
- **Sviluppo**: `debug`
- **Produzione**: `info`

#### **DEBUG_MODE**
- **Tipo**: Boolean
- **Default**: `false`
- **Descrizione**: Abilita modalità debug
- **Sviluppo**: `true`
- **Produzione**: `false` (sicurezza)

## 🔄 **Configurazioni per Ambiente**

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

## 🔧 **Utilità di Configurazione**

### **Generazione Password Sicure**

```bash
# Genera password sicura
openssl rand -base64 32

# Genera JWT secret
openssl rand -base64 64

# Genera salt per bcrypt
openssl rand -base64 16
```

### **Validazione Configurazione**

```bash
# Valida file .env
docker-compose config

# Test connessione database
docker-compose exec postgres pg_isready -U $POSTGRES_USER -d $POSTGRES_DB

# Test connessione MinIO
curl $MINIO_ENDPOINT/minio/health/live
```

### **Backup Configurazione**

```bash
# Backup configurazione
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)

# Restore configurazione
cp .env.backup.20240101_120000 .env
```

## 🚨 **Best Practices**

### **Sicurezza**

1. **Cambia sempre le credenziali default**
2. **Usa password forti e uniche**
3. **Abilita HTTPS in produzione**
4. **Configura security headers**
5. **Limita le origini CORS**

### **Performance**

1. **Configura connection pooling**
2. **Ottimizza rate limiting**
3. **Usa caching appropriato**
4. **Monitora le metriche**

### **Manutenibilità**

1. **Documenta le configurazioni**
2. **Usa variabili d'ambiente separate**
3. **Versiona le configurazioni**
4. **Testa in staging**

---

**Pandom Stack** - Configurazione flessibile e sicura per ogni ambiente. 