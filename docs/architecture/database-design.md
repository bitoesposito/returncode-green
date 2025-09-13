# 🗄️ Database Design

## 📋 Overview

**Pandom Stack** uses PostgreSQL as the primary database with a design optimized for security, performance, and scalability. The database is designed following best practices for enterprise applications with focus on audit logging, security, and GDPR compliance.

## 🏗️ **Database Architecture**

### **Technologies Used**

- **Database**: PostgreSQL 17
- **ORM**: TypeORM
- **Migrations**: TypeORM Migrations
- **Backup**: pg_dump + MinIO
- **Monitoring**: Integrated health checks

### **Key Features**

- ✅ **UUID Primary Keys** for security
- ✅ **Complete Audit Logging**
- ✅ **Security Logging** for compliance
- ✅ **Advanced Session Management**
- ✅ **JSONB** for flexible metadata
- ✅ **Optimized indexes** for performance
- ✅ **Foreign Key constraints** for integrity

## 📊 **Database Schema**

### **ER Diagram**

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

## 🗃️ **Database Entities**

### **1. AUTH_USERS**

Main table for user authentication and authorization.

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

#### **Main Fields**

| Field | Type | Description |
|-------|------|-------------|
| `uuid` | UUID | Unique primary key |
| `email` | VARCHAR(255) | User email (unique) |
| `password_hash` | VARCHAR(255) | bcrypt password hash |
| `role` | ENUM | User role (user, admin) |
| `is_verified` | BOOLEAN | Email verified |
| `is_active` | BOOLEAN | Account active |
| `last_login_at` | TIMESTAMP | Last login |
| `profile_uuid` | UUID | Profile reference |

#### **Indexes**

```sql
-- Index for email (unique)
CREATE UNIQUE INDEX idx_auth_users_email ON auth_users(email);

-- Index for role
CREATE INDEX idx_auth_users_role ON auth_users(role);

-- Index for active status
CREATE INDEX idx_auth_users_active ON auth_users(is_active);

-- Index for last login
CREATE INDEX idx_auth_users_last_login ON auth_users(last_login_at);
```

### **2. USER_PROFILES**

Table for extended user profile information.

```sql
CREATE TABLE user_profiles (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### **Main Fields**

| Field | Type | Description |
|-------|------|-------------|
| `uuid` | UUID | Unique primary key |
| `tags` | TEXT[] | User tags array |
| `metadata` | JSONB | Flexible metadata |
| `created_at` | TIMESTAMP | Creation date |
| `updated_at` | TIMESTAMP | Last update date |

#### **Indexes**

```sql
-- GIN index for tags
CREATE INDEX idx_user_profiles_tags ON user_profiles USING GIN(tags);

-- GIN index for metadata JSONB
CREATE INDEX idx_user_profiles_metadata ON user_profiles USING GIN(metadata);
```

### **3. AUDIT_LOGS**

Table for comprehensive system operation logging.

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

#### **Main Fields**

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique primary key |
| `event_type` | VARCHAR(100) | Event type |
| `status` | VARCHAR(20) | Operation status |
| `user_uuid` | UUID | User reference |
| `session_id` | VARCHAR(255) | Session ID |
| `ip_address` | INET | IP address |
| `user_agent` | TEXT | Browser user agent |
| `resource` | VARCHAR(255) | Accessed resource |
| `action` | VARCHAR(10) | HTTP action |
| `details` | JSONB | Additional details |

#### **Indexes**

```sql
-- Index for timestamp (for temporal queries)
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Index for user
CREATE INDEX idx_audit_logs_user ON audit_logs(user_uuid);

-- Index for event type
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);

-- Index for status
CREATE INDEX idx_audit_logs_status ON audit_logs(status);

-- Composite index for common queries
CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs(user_uuid, timestamp);
```

### **4. SECURITY_LOGS**

Table for security event logging.

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

#### **Main Fields**

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique primary key |
| `event_type` | VARCHAR(100) | Security event type |
| `severity` | VARCHAR(20) | Severity level |
| `user_uuid` | UUID | User reference |
| `ip_address` | INET | IP address |
| `user_agent` | TEXT | Browser user agent |
| `details` | JSONB | Event details |
| `metadata` | JSONB | Additional metadata |

#### **Indexes**

```sql
-- Index for timestamp
CREATE INDEX idx_security_logs_timestamp ON security_logs(timestamp);

-- Index for severity
CREATE INDEX idx_security_logs_severity ON security_logs(severity);

-- Index for event type
CREATE INDEX idx_security_logs_event_type ON security_logs(event_type);

-- Index for user
CREATE INDEX idx_security_logs_user ON security_logs(user_uuid);

-- Composite index for alerting
CREATE INDEX idx_security_logs_severity_timestamp ON security_logs(severity, timestamp);
```

### **5. SESSION_LOGS**

Table for user session tracking.

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

#### **Main Fields**

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique primary key |
| `event_type` | VARCHAR(100) | Session event type |
| `user_uuid` | UUID | User reference |
| `session_token_hash` | VARCHAR(255) | Session token hash |
| `refresh_token_hash` | VARCHAR(255) | Refresh token hash |
| `device_info` | VARCHAR(255) | Device information |
| `ip_address` | INET | IP address |
| `user_agent` | TEXT | Browser user agent |
| `details` | JSONB | Session details |

#### **Indexes**

```sql
-- Index for timestamp
CREATE INDEX idx_session_logs_timestamp ON session_logs(timestamp);

-- Index for user
CREATE INDEX idx_session_logs_user ON session_logs(user_uuid);

-- Index for event type
CREATE INDEX idx_session_logs_event_type ON session_logs(event_type);

-- Index for token hash (for session lookup)
CREATE INDEX idx_session_logs_token_hash ON session_logs(session_token_hash);
```

## 🔧 **Enums and Custom Types**

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

## 📈 **Performance and Optimizations**

### **Composite Indexes**

```sql
-- Index for audit queries by user and period
CREATE INDEX idx_audit_logs_user_time_range ON audit_logs(user_uuid, timestamp DESC);

-- Index for security queries by severity and period
CREATE INDEX idx_security_logs_severity_time ON security_logs(severity, timestamp DESC);

-- Index for active sessions
CREATE INDEX idx_session_logs_active_sessions ON session_logs(user_uuid, event_type, timestamp DESC);
```

### **Partitioning (Future)**

```sql
-- Partitioning for audit_logs by month
CREATE TABLE audit_logs_y2024m01 PARTITION OF audit_logs
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Partitioning for security_logs by month
CREATE TABLE security_logs_y2024m01 PARTITION OF security_logs
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

### **VACUUM and Maintenance**

```sql
-- Automatic VACUUM configuration
ALTER TABLE audit_logs SET (autovacuum_vacuum_scale_factor = 0.1);
ALTER TABLE security_logs SET (autovacuum_vacuum_scale_factor = 0.1);
ALTER TABLE session_logs SET (autovacuum_vacuum_scale_factor = 0.1);

-- Configuration for log tables
ALTER TABLE audit_logs SET (fillfactor = 90);
ALTER TABLE security_logs SET (fillfactor = 90);
ALTER TABLE session_logs SET (fillfactor = 90);
```

## 🔒 **Database Security**

### **Row Level Security (RLS)**

```sql
-- Enable RLS for audit_logs
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Policy for users: can only see their own logs
CREATE POLICY user_audit_logs_policy ON audit_logs
FOR SELECT TO authenticated_user
USING (user_uuid = current_setting('app.current_user_uuid')::UUID);

-- Policy for admin: can see all logs
CREATE POLICY admin_audit_logs_policy ON audit_logs
FOR ALL TO admin_role
USING (true);
```

### **Encryption**

```sql
-- Extension for encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Function for secure hash
CREATE OR REPLACE FUNCTION secure_hash(input TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(digest(input, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;
```

## 📊 **Monitoring and Health Checks**

### **Health Check Queries**

```sql
-- Check active connections
SELECT count(*) as active_connections 
FROM pg_stat_activity 
WHERE state = 'active';

-- Check table sizes
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check query performance
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
-- Check recent errors
SELECT count(*) as error_count
FROM audit_logs 
WHERE status = 'FAILED' 
AND timestamp > NOW() - INTERVAL '1 hour';

-- Check failed login attempts
SELECT count(*) as failed_logins
FROM security_logs 
WHERE event_type = 'USER_LOGIN_FAILED' 
AND timestamp > NOW() - INTERVAL '15 minutes';

-- Check active sessions
SELECT count(DISTINCT user_uuid) as active_users
FROM session_logs 
WHERE event_type = 'CREATED' 
AND timestamp > NOW() - INTERVAL '1 hour';
```

## 🔄 **Backup and Recovery**

### **Backup Strategy**

```bash
# Complete backup
pg_dump -h localhost -U pandom_user -d pandom_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Schema only backup
pg_dump -h localhost -U pandom_user -d pandom_db --schema-only > schema_backup.sql

# Data only backup
pg_dump -h localhost -U pandom_user -d pandom_db --data-only > data_backup.sql

# Compressed backup
pg_dump -h localhost -U pandom_user -d pandom_db | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

### **Recovery Procedures**

```bash
# Complete restore
psql -h localhost -U pandom_user -d pandom_db < backup_20240115_120000.sql

# Restore from compressed backup
gunzip -c backup_20240115_120000.sql.gz | psql -h localhost -U pandom_user -d pandom_db

# Selective restore
psql -h localhost -U pandom_user -d pandom_db -c "DELETE FROM audit_logs WHERE timestamp < '2024-01-01';"
```

## 📋 **Migration Strategy**

### **TypeORM Migrations**

```typescript
// Example migration
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
                    // ... other fields
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

1. **UUID Primary Keys**: For security and distribution
2. **Soft Deletes**: For complete audit trail
3. **Audit Logging**: For compliance and debugging
4. **JSONB**: For flexible metadata
5. **Optimized Indexes**: For query performance
6. **Foreign Key Constraints**: For data integrity

### **Performance Guidelines**

1. **Indexes**: Only on fields used in queries
2. **Partitioning**: For large log tables
3. **VACUUM**: Automatic configuration
4. **Connection Pooling**: For connection management
5. **Query Optimization**: Regular query analysis

### **Security Guidelines**

1. **RLS**: Row Level Security for data isolation
2. **Encryption**: For sensitive data
3. **Audit Trail**: Complete operation logging
4. **Access Control**: Granular roles and permissions
5. **Backup Encryption**: For secure backups

---

**Pandom Stack Database** - Enterprise-grade database design with focus on security, performance, and compliance.
