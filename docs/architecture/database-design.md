# 🗄️ Database Design

## 📋 Panoramica

**Pandom Stack** utilizza PostgreSQL come database principale con un design ottimizzato per sicurezza, performance e scalabilità. Il database è progettato seguendo le best practices per applicazioni enterprise con focus su audit logging, sicurezza e compliance GDPR.

## 🏗️ **Architettura Database**

### **Tecnologie Utilizzate**

- **Database**: PostgreSQL 17
- **ORM**: TypeORM
- **Migrazioni**: TypeORM Migrations
- **Backup**: pg_dump + MinIO
- **Monitoring**: Health checks integrati

### **Caratteristiche Principali**

- ✅ **UUID Primary Keys** per sicurezza
- ✅ **Audit Logging** completo
- ✅ **Security Logging** per compliance
- ✅ **Session Management** avanzato
- ✅ **JSONB** per metadati flessibili
- ✅ **Indici ottimizzati** per performance
- ✅ **Foreign Key constraints** per integrità

## 📊 **Schema Database**

### **Diagramma ER**

```mermaid
erDiagram
    AUTH_USERS {
        uuid UUID PK
        email VARCHAR UNIQUE
        password_hash VARCHAR
        role ENUM
        is_verified BOOLEAN
        is_active BOOLEAN
        last_login_at TIMESTAMP
        created_at TIMESTAMP
        updated_at TIMESTAMP
        profile_uuid UUID FK
    }
    
    USER_PROFILES {
        uuid UUID PK
        tags TEXT[]
        metadata JSONB
        created_at TIMESTAMP
        updated_at TIMESTAMP
    }
    
    AUDIT_LOGS {
        id UUID PK
        event_type VARCHAR
        status VARCHAR
        user_uuid UUID FK
        session_id VARCHAR
        ip_address VARCHAR
        user_agent VARCHAR
        resource VARCHAR
        action VARCHAR
        timestamp TIMESTAMP
        details JSONB
    }
    
    SECURITY_LOGS {
        id UUID PK
        event_type VARCHAR
        severity VARCHAR
        user_uuid UUID FK
        ip_address VARCHAR
        user_agent VARCHAR
        timestamp TIMESTAMP
        details JSONB
        metadata JSONB
    }
    
    SESSION_LOGS {
        id UUID PK
        event_type VARCHAR
        user_uuid UUID FK
        session_token_hash VARCHAR
        refresh_token_hash VARCHAR
        device_info VARCHAR
        ip_address VARCHAR
        user_agent VARCHAR
        timestamp TIMESTAMP
        details JSONB
    }
    
    AUTH_USERS ||--|| USER_PROFILES : "has profile"
    AUTH_USERS ||--o{ AUDIT_LOGS : "generates"
    AUTH_USERS ||--o{ SECURITY_LOGS : "generates"
    AUTH_USERS ||--o{ SESSION_LOGS : "generates"
```

## 🗃️ **Entità Database**

### **1. AUTH_USERS**

Tabella principale per l'autenticazione e autorizzazione degli utenti.

```sql
CREATE TABLE auth_users (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role_enum DEFAULT 'user',
    is_verified BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    profile_uuid UUID REFERENCES user_profiles(uuid)
);
```

#### **Campi Principali**

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `uuid` | UUID | Chiave primaria univoca |
| `email` | VARCHAR(255) | Email utente (univoca) |
| `password_hash` | VARCHAR(255) | Hash password bcrypt |
| `role` | ENUM | Ruolo utente (user, admin) |
| `is_verified` | BOOLEAN | Email verificata |
| `is_active` | BOOLEAN | Account attivo |
| `last_login_at` | TIMESTAMP | Ultimo accesso |
| `profile_uuid` | UUID | Riferimento al profilo |

#### **Indici**

```sql
-- Indice per email (univoco)
CREATE UNIQUE INDEX idx_auth_users_email ON auth_users(email);

-- Indice per ruolo
CREATE INDEX idx_auth_users_role ON auth_users(role);

-- Indice per stato attivo
CREATE INDEX idx_auth_users_active ON auth_users(is_active);

-- Indice per ultimo login
CREATE INDEX idx_auth_users_last_login ON auth_users(last_login_at);
```

### **2. USER_PROFILES**

Tabella per informazioni estese del profilo utente.

```sql
CREATE TABLE user_profiles (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### **Campi Principali**

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `uuid` | UUID | Chiave primaria univoca |
| `tags` | TEXT[] | Array di tag utente |
| `metadata` | JSONB | Metadati flessibili |
| `created_at` | TIMESTAMP | Data creazione |
| `updated_at` | TIMESTAMP | Data ultimo aggiornamento |

#### **Indici**

```sql
-- Indice GIN per tags
CREATE INDEX idx_user_profiles_tags ON user_profiles USING GIN(tags);

-- Indice GIN per metadata JSONB
CREATE INDEX idx_user_profiles_metadata ON user_profiles USING GIN(metadata);
```

### **3. AUDIT_LOGS**

Tabella per il logging completo delle operazioni di sistema.

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    user_uuid UUID REFERENCES auth_users(uuid),
    session_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    resource VARCHAR(255),
    action VARCHAR(10),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    details JSONB DEFAULT '{}'
);
```

#### **Campi Principali**

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `id` | UUID | Chiave primaria univoca |
| `event_type` | VARCHAR(100) | Tipo di evento |
| `status` | VARCHAR(20) | Stato operazione |
| `user_uuid` | UUID | Riferimento utente |
| `session_id` | VARCHAR(255) | ID sessione |
| `ip_address` | INET | Indirizzo IP |
| `user_agent` | TEXT | User agent browser |
| `resource` | VARCHAR(255) | Risorsa accessata |
| `action` | VARCHAR(10) | Azione HTTP |
| `details` | JSONB | Dettagli aggiuntivi |

#### **Indici**

```sql
-- Indice per timestamp (per query temporali)
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Indice per utente
CREATE INDEX idx_audit_logs_user ON audit_logs(user_uuid);

-- Indice per tipo evento
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);

-- Indice per status
CREATE INDEX idx_audit_logs_status ON audit_logs(status);

-- Indice composito per query comuni
CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs(user_uuid, timestamp);
```

### **4. SECURITY_LOGS**

Tabella per il logging degli eventi di sicurezza.

```sql
CREATE TABLE security_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_uuid UUID REFERENCES auth_users(uuid),
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    details JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}'
);
```

#### **Campi Principali**

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `id` | UUID | Chiave primaria univoca |
| `event_type` | VARCHAR(100) | Tipo evento sicurezza |
| `severity` | VARCHAR(20) | Livello di gravità |
| `user_uuid` | UUID | Riferimento utente |
| `ip_address` | INET | Indirizzo IP |
| `user_agent` | TEXT | User agent browser |
| `details` | JSONB | Dettagli evento |
| `metadata` | JSONB | Metadati aggiuntivi |

#### **Indici**

```sql
-- Indice per timestamp
CREATE INDEX idx_security_logs_timestamp ON security_logs(timestamp);

-- Indice per severità
CREATE INDEX idx_security_logs_severity ON security_logs(severity);

-- Indice per tipo evento
CREATE INDEX idx_security_logs_event_type ON security_logs(event_type);

-- Indice per utente
CREATE INDEX idx_security_logs_user ON security_logs(user_uuid);

-- Indice composito per alerting
CREATE INDEX idx_security_logs_severity_timestamp ON security_logs(severity, timestamp);
```

### **5. SESSION_LOGS**

Tabella per il tracking delle sessioni utente.

```sql
CREATE TABLE session_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    user_uuid UUID REFERENCES auth_users(uuid),
    session_token_hash VARCHAR(255),
    refresh_token_hash VARCHAR(255),
    device_info VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    details JSONB DEFAULT '{}'
);
```

#### **Campi Principali**

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `id` | UUID | Chiave primaria univoca |
| `event_type` | VARCHAR(100) | Tipo evento sessione |
| `user_uuid` | UUID | Riferimento utente |
| `session_token_hash` | VARCHAR(255) | Hash token sessione |
| `refresh_token_hash` | VARCHAR(255) | Hash refresh token |
| `device_info` | VARCHAR(255) | Info dispositivo |
| `ip_address` | INET | Indirizzo IP |
| `user_agent` | TEXT | User agent browser |
| `details` | JSONB | Dettagli sessione |

#### **Indici**

```sql
-- Indice per timestamp
CREATE INDEX idx_session_logs_timestamp ON session_logs(timestamp);

-- Indice per utente
CREATE INDEX idx_session_logs_user ON session_logs(user_uuid);

-- Indice per tipo evento
CREATE INDEX idx_session_logs_event_type ON session_logs(event_type);

-- Indice per hash token (per lookup sessioni)
CREATE INDEX idx_session_logs_token_hash ON session_logs(session_token_hash);
```

## 🔧 **Enums e Tipi Personalizzati**

### **UserRole Enum**

```sql
CREATE TYPE user_role_enum AS ENUM ('user', 'admin');
```

### **Event Types**

```sql
-- Audit Event Types
CREATE TYPE audit_event_type AS ENUM (
    'USER_LOGIN_SUCCESS',
    'USER_LOGIN_FAILED',
    'USER_LOGOUT',
    'USER_REGISTRATION',
    'USER_EMAIL_VERIFICATION',
    'USER_PASSWORD_RESET',
    'USER_PROFILE_UPDATE',
    'ADMIN_USER_DELETE',
    'ADMIN_USER_UPDATE',
    'SYSTEM_BACKUP_CREATED',
    'SYSTEM_BACKUP_RESTORED'
);

-- Security Event Types
CREATE TYPE security_event_type AS ENUM (
    'USER_LOGIN_SUCCESS',
    'USER_LOGIN_FAILED',
    'BRUTE_FORCE_ATTEMPT',
    'SUSPICIOUS_ACTIVITY',
    'ACCOUNT_LOCKED',
    'PASSWORD_CHANGED',
    'EMAIL_VERIFIED',
    'SESSION_CREATED',
    'SESSION_TERMINATED',
    'DATA_EXPORT_REQUESTED',
    'ACCOUNT_DELETION_REQUESTED'
);

-- Session Event Types
CREATE TYPE session_event_type AS ENUM (
    'CREATED',
    'REFRESHED',
    'TERMINATED',
    'EXPIRED',
    'INVALIDATED'
);
```

## 📈 **Performance e Ottimizzazioni**

### **Indici Compositi**

```sql
-- Indice per query di audit per utente e periodo
CREATE INDEX idx_audit_logs_user_time_range ON audit_logs(user_uuid, timestamp DESC);

-- Indice per query di sicurezza per severità e periodo
CREATE INDEX idx_security_logs_severity_time ON security_logs(severity, timestamp DESC);

-- Indice per sessioni attive
CREATE INDEX idx_session_logs_active_sessions ON session_logs(user_uuid, event_type, timestamp DESC);
```

### **Partitioning (Futuro)**

```sql
-- Partitioning per audit_logs per mese
CREATE TABLE audit_logs_y2024m01 PARTITION OF audit_logs
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Partitioning per security_logs per mese
CREATE TABLE security_logs_y2024m01 PARTITION OF security_logs
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

### **VACUUM e Maintenance**

```sql
-- Configurazione automatica VACUUM
ALTER TABLE audit_logs SET (autovacuum_vacuum_scale_factor = 0.1);
ALTER TABLE security_logs SET (autovacuum_vacuum_scale_factor = 0.1);
ALTER TABLE session_logs SET (autovacuum_vacuum_scale_factor = 0.1);

-- Configurazione per tabelle di log
ALTER TABLE audit_logs SET (fillfactor = 90);
ALTER TABLE security_logs SET (fillfactor = 90);
ALTER TABLE session_logs SET (fillfactor = 90);
```

## 🔒 **Sicurezza Database**

### **Row Level Security (RLS)**

```sql
-- Abilita RLS per audit_logs
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Policy per utenti: possono vedere solo i propri log
CREATE POLICY user_audit_logs_policy ON audit_logs
FOR SELECT TO authenticated_user
USING (user_uuid = current_setting('app.current_user_uuid')::UUID);

-- Policy per admin: possono vedere tutti i log
CREATE POLICY admin_audit_logs_policy ON audit_logs
FOR ALL TO admin_role
USING (true);
```

### **Crittografia**

```sql
-- Estensione per crittografia
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Funzione per hash sicuro
CREATE OR REPLACE FUNCTION secure_hash(input TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(digest(input, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;
```

## 📊 **Monitoring e Health Checks**

### **Health Check Queries**

```sql
-- Controllo connessioni attive
SELECT count(*) as active_connections 
FROM pg_stat_activity 
WHERE state = 'active';

-- Controllo dimensioni tabelle
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Controllo performance query
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;
```

### **Alerting Queries**

```sql
-- Controllo errori recenti
SELECT count(*) as error_count
FROM audit_logs 
WHERE status = 'FAILED' 
AND timestamp > NOW() - INTERVAL '1 hour';

-- Controllo tentativi di login falliti
SELECT count(*) as failed_logins
FROM security_logs 
WHERE event_type = 'USER_LOGIN_FAILED' 
AND timestamp > NOW() - INTERVAL '15 minutes';

-- Controllo sessioni attive
SELECT count(DISTINCT user_uuid) as active_users
FROM session_logs 
WHERE event_type = 'CREATED' 
AND timestamp > NOW() - INTERVAL '1 hour';
```

## 🔄 **Backup e Recovery**

### **Backup Strategy**

```bash
# Backup completo
pg_dump -h localhost -U pandom_user -d pandom_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Backup solo schema
pg_dump -h localhost -U pandom_user -d pandom_db --schema-only > schema_backup.sql

# Backup solo dati
pg_dump -h localhost -U pandom_user -d pandom_db --data-only > data_backup.sql

# Backup compresso
pg_dump -h localhost -U pandom_user -d pandom_db | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

### **Recovery Procedures**

```bash
# Restore completo
psql -h localhost -U pandom_user -d pandom_db < backup_20240115_120000.sql

# Restore da backup compresso
gunzip -c backup_20240115_120000.sql.gz | psql -h localhost -U pandom_user -d pandom_db

# Restore selettivo
psql -h localhost -U pandom_user -d pandom_db -c "DELETE FROM audit_logs WHERE timestamp < '2024-01-01';"
```

## 📋 **Migration Strategy**

### **TypeORM Migrations**

```typescript
// Esempio migrazione
export class CreateAuditLogsTable1234567890123 implements MigrationInterface {
    name = 'CreateAuditLogsTable1234567890123'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.createTable(
            new Table({
                name: 'audit_logs',
                columns: [
                    {
                        name: 'id',
                        type: 'uuid',
                        isPrimary: true,
                        generationStrategy: 'uuid',
                        default: 'gen_random_uuid()',
                    },
                    {
                        name: 'event_type',
                        type: 'varchar',
                        length: '100',
                        isNullable: false,
                    },
                    // ... altri campi
                ],
                indices: [
                    {
                        name: 'idx_audit_logs_timestamp',
                        columnNames: ['timestamp'],
                    },
                ],
            }),
            true
        );
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.dropTable('audit_logs');
    }
}
```

## 🎯 **Best Practices**

### **Design Patterns**

1. **UUID Primary Keys**: Per sicurezza e distribuzione
2. **Soft Deletes**: Per audit trail completo
3. **Audit Logging**: Per compliance e debugging
4. **JSONB**: Per metadati flessibili
5. **Indici Ottimizzati**: Per performance query
6. **Foreign Key Constraints**: Per integrità dati

### **Performance Guidelines**

1. **Indici**: Solo su campi utilizzati nelle query
2. **Partitioning**: Per tabelle di log grandi
3. **VACUUM**: Configurazione automatica
4. **Connection Pooling**: Per gestione connessioni
5. **Query Optimization**: Analisi regolare delle query

### **Security Guidelines**

1. **RLS**: Row Level Security per isolamento dati
2. **Crittografia**: Per dati sensibili
3. **Audit Trail**: Logging completo delle operazioni
4. **Access Control**: Ruoli e permessi granulari
5. **Backup Encryption**: Per backup sicuri

---

**Pandom Stack Database** - Design database enterprise-grade con focus su sicurezza, performance e compliance.