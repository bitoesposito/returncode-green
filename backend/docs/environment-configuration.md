# Configurazione Ambiente - Sistema di Certificazione Digitale

## Panoramica

Questo documento descrive tutte le variabili d'ambiente necessarie per configurare il sistema di certificazione digitale. Le variabili sono organizzate per categoria e includono valori di esempio per sviluppo, staging e produzione.

---

## Struttura File .env

Il sistema utilizza un file `.env` nella root del progetto backend per la configurazione. Ecco la struttura completa:

```bash
# =============================================================================
# CONFIGURAZIONE DATABASE
# =============================================================================

# Host del database PostgreSQL
DB_HOST=localhost

# Utente del database
POSTGRES_USER=certificates_user

# Password del database
POSTGRES_PASSWORD=secure_password_here

# Nome del database
POSTGRES_DB=certificates_db

# Porta del database
POSTGRES_PORT=5432

# URL completo di connessione al database
DATABASE_URL=postgres://certificates_user:secure_password_here@localhost:5432/certificates_db

# =============================================================================
# CONFIGURAZIONE JWT
# =============================================================================

# Chiave segreta per firmare i token JWT (minimo 32 caratteri)
JWT_SECRET=your_super_secure_jwt_secret_here_min_32_chars

# Durata dei token JWT
JWT_EXPIRATION=1h

# =============================================================================
# CONFIGURAZIONE SERVER
# =============================================================================

# Porta del server backend
BE_PORT=3000

# URL del backend
BE_URL=localhost:3000

# Porta del frontend
FE_PORT=4200

# URL del frontend
FE_URL=localhost:4200

# Flag per ambiente di produzione
PRODUCTION=false

# =============================================================================
# CONFIGURAZIONE MINIO
# =============================================================================

# Utente root di MinIO
MINIO_ROOT_USER=certificates_admin

# Password root di MinIO
MINIO_ROOT_PASSWORD=secure_minio_password_here

# Endpoint MinIO (interno)
MINIO_ENDPOINT=localhost

# Porta MinIO
MINIO_PORT=9000

# Usa SSL per MinIO
MINIO_USE_SSL=false

# Nome del bucket per i certificati
MINIO_BUCKET_NAME=certificates

# URL pubblico di MinIO
MINIO_URL=localhost:9000

# =============================================================================
# CONFIGURAZIONE SISTEMA CERTIFICAZIONE DIGITALE
# =============================================================================

# Percorso delle chiavi crittografiche
CRYPTO_KEYS_PATH=keys

# ID della chiave corrente per nuovi certificati
CRYPTO_CURRENT_KEY_ID=rsa-2024-01

# Dimensione massima file certificato (in bytes)
CERTIFICATE_MAX_FILE_SIZE=10485760

# Tipi di file consentiti per i certificati
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json,text/json

# Percorso di storage per i certificati
CERTIFICATE_STORAGE_PATH=certificates

# =============================================================================
# CONFIGURAZIONE UTENTE ADMIN
# =============================================================================

# Email dell'amministratore di default
ADMIN_EMAIL=admin@yourdomain.com

# Ruolo dell'amministratore
ADMIN_ROLE=admin

# Password dell'amministratore di default
ADMIN_PASSWORD=secure_admin_password_here

# =============================================================================
# CONFIGURAZIONE EMAIL (OPZIONALE)
# =============================================================================

# Host SMTP
SMTP_HOST=smtp.yourdomain.com

# Porta SMTP
SMTP_PORT=587

# Utente SMTP
SMTP_USER=noreply@yourdomain.com

# Password SMTP
SMTP_PASS=smtp_password_here

# Email mittente
SMTP_FROM=noreply@yourdomain.com
```

---

## Variabili per Ambiente

### Sviluppo (Development)

```bash
# Database locale
DB_HOST=localhost
POSTGRES_USER=dev_user
POSTGRES_PASSWORD=dev_password
POSTGRES_DB=certificates_dev
DATABASE_URL=postgres://dev_user:dev_password@localhost:5432/certificates_dev

# JWT con secret semplice
JWT_SECRET=development_jwt_secret_min_32_characters
JWT_EXPIRATION=24h

# Server locale
BE_PORT=3000
BE_URL=localhost:3000
FE_PORT=4200
FE_URL=localhost:4200
PRODUCTION=false

# MinIO locale
MINIO_ROOT_USER=dev_admin
MINIO_ROOT_PASSWORD=dev_password
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_BUCKET_NAME=certificates-dev
MINIO_URL=localhost:9000

# Certificati - configurazione permissiva per sviluppo
CRYPTO_KEYS_PATH=keys
CRYPTO_CURRENT_KEY_ID=rsa-dev-2024
CERTIFICATE_MAX_FILE_SIZE=10485760
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json,text/json,text/plain
CERTIFICATE_STORAGE_PATH=certificates

# Admin di sviluppo
ADMIN_EMAIL=dev@localhost
ADMIN_PASSWORD=dev123456
```

### Staging

```bash
# Database staging
DB_HOST=staging-db.internal
POSTGRES_USER=staging_user
POSTGRES_PASSWORD=staging_secure_password_123
POSTGRES_DB=certificates_staging
DATABASE_URL=postgres://staging_user:staging_secure_password_123@staging-db.internal:5432/certificates_staging

# JWT con secret sicuro
JWT_SECRET=staging_jwt_secret_very_long_and_secure_string_here
JWT_EXPIRATION=1h

# Server staging
BE_PORT=3000
BE_URL=api-staging.yourdomain.com
FE_PORT=4200
FE_URL=staging.yourdomain.com
PRODUCTION=false

# MinIO staging
MINIO_ROOT_USER=staging_admin
MINIO_ROOT_PASSWORD=staging_minio_secure_password_123
MINIO_ENDPOINT=minio-staging.internal
MINIO_PORT=9000
MINIO_USE_SSL=true
MINIO_BUCKET_NAME=certificates-staging
MINIO_URL=storage-staging.yourdomain.com

# Certificati - configurazione staging
CRYPTO_KEYS_PATH=/app/keys
CRYPTO_CURRENT_KEY_ID=rsa-staging-2024-01
CERTIFICATE_MAX_FILE_SIZE=10485760
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json
CERTIFICATE_STORAGE_PATH=certificates

# Admin staging
ADMIN_EMAIL=admin@staging.yourdomain.com
ADMIN_PASSWORD=staging_admin_secure_password_123

# Email staging
SMTP_HOST=smtp.staging.yourdomain.com
SMTP_PORT=587
SMTP_USER=noreply@staging.yourdomain.com
SMTP_PASS=staging_smtp_password
SMTP_FROM=noreply@staging.yourdomain.com
```

### Produzione

```bash
# Database produzione con SSL
DB_HOST=prod-db-cluster.amazonaws.com
POSTGRES_USER=certificates_prod
POSTGRES_PASSWORD=ultra_secure_production_password_2024
POSTGRES_DB=certificates_production
DATABASE_URL=postgres://certificates_prod:ultra_secure_production_password_2024@prod-db-cluster.amazonaws.com:5432/certificates_production?sslmode=require

# JWT con secret generato crittograficamente
JWT_SECRET=prod_jwt_secret_generated_with_openssl_rand_base64_64_characters_here
JWT_EXPIRATION=1h

# Server produzione
BE_PORT=3000
BE_URL=api.yourdomain.com
FE_PORT=4200
FE_URL=yourdomain.com
PRODUCTION=true

# MinIO produzione con SSL
MINIO_ROOT_USER=certificates_prod_admin
MINIO_ROOT_PASSWORD=ultra_secure_minio_production_password_2024
MINIO_ENDPOINT=storage.yourdomain.com
MINIO_PORT=443
MINIO_USE_SSL=true
MINIO_BUCKET_NAME=certificates-production
MINIO_URL=storage.yourdomain.com

# Certificati - configurazione produzione
CRYPTO_KEYS_PATH=/app/keys
CRYPTO_CURRENT_KEY_ID=rsa-prod-2024-01
CERTIFICATE_MAX_FILE_SIZE=10485760
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json
CERTIFICATE_STORAGE_PATH=certificates

# Admin produzione
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=ultra_secure_admin_production_password_2024

# Email produzione
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=production_smtp_secure_password
SMTP_FROM=noreply@yourdomain.com
```

---

## Descrizione Dettagliata Variabili

### Database Configuration

#### `DB_HOST`
- **Tipo**: String
- **Richiesto**: ✅
- **Default**: `localhost`
- **Descrizione**: Hostname o indirizzo IP del server PostgreSQL
- **Esempi**:
  - Sviluppo: `localhost`
  - Docker: `postgres`
  - Produzione: `db-cluster.amazonaws.com`

#### `POSTGRES_USER`
- **Tipo**: String
- **Richiesto**: ✅
- **Default**: `user`
- **Descrizione**: Nome utente per la connessione al database
- **Sicurezza**: Evita utenti generici come `postgres` in produzione

#### `POSTGRES_PASSWORD`
- **Tipo**: String
- **Richiesto**: ✅
- **Default**: `password`
- **Descrizione**: Password per la connessione al database
- **Sicurezza**: Usa password complesse (min 16 caratteri, mix di caratteri)

#### `POSTGRES_DB`
- **Tipo**: String
- **Richiesto**: ✅
- **Default**: `postgres`
- **Descrizione**: Nome del database da utilizzare

#### `POSTGRES_PORT`
- **Tipo**: Number
- **Richiesto**: ❌
- **Default**: `5432`
- **Descrizione**: Porta del server PostgreSQL

#### `DATABASE_URL`
- **Tipo**: String (URL)
- **Richiesto**: ✅
- **Formato**: `postgres://user:password@host:port/database?options`
- **Descrizione**: URL completo di connessione al database
- **Opzioni SSL**: Aggiungi `?sslmode=require` per produzione

### JWT Configuration

#### `JWT_SECRET`
- **Tipo**: String
- **Richiesto**: ✅
- **Lunghezza minima**: 32 caratteri
- **Descrizione**: Chiave segreta per firmare i token JWT
- **Generazione sicura**:
  ```bash
  # Genera secret sicuro
  openssl rand -base64 64
  ```

#### `JWT_EXPIRATION`
- **Tipo**: String
- **Richiesto**: ❌
- **Default**: `1h`
- **Formati supportati**: `1h`, `30m`, `7d`, `1y`
- **Descrizione**: Durata dei token JWT
- **Raccomandazioni**:
  - Sviluppo: `24h` (per comodità)
  - Produzione: `1h` (per sicurezza)

### Server Configuration

#### `BE_PORT`
- **Tipo**: Number
- **Richiesto**: ❌
- **Default**: `3000`
- **Descrizione**: Porta su cui il server backend ascolta

#### `BE_URL`
- **Tipo**: String
- **Richiesto**: ✅
- **Formato**: `hostname:port` o `domain.com`
- **Descrizione**: URL pubblico del backend per CORS e link

#### `FE_PORT`
- **Tipo**: Number
- **Richiesto**: ❌
- **Default**: `4200`
- **Descrizione**: Porta del frontend (per sviluppo)

#### `FE_URL`
- **Tipo**: String
- **Richiesto**: ✅
- **Descrizione**: URL pubblico del frontend per CORS

#### `PRODUCTION`
- **Tipo**: Boolean
- **Richiesto**: ❌
- **Default**: `false`
- **Valori**: `true`, `false`
- **Descrizione**: Flag per abilitare configurazioni di produzione

### MinIO Configuration

#### `MINIO_ROOT_USER`
- **Tipo**: String
- **Richiesto**: ✅
- **Lunghezza minima**: 3 caratteri
- **Descrizione**: Utente amministratore di MinIO

#### `MINIO_ROOT_PASSWORD`
- **Tipo**: String
- **Richiesto**: ✅
- **Lunghezza minima**: 8 caratteri
- **Descrizione**: Password amministratore di MinIO

#### `MINIO_ENDPOINT`
- **Tipo**: String
- **Richiesto**: ✅
- **Descrizione**: Hostname del server MinIO (senza protocollo)

#### `MINIO_PORT`
- **Tipo**: Number
- **Richiesto**: ❌
- **Default**: `9000`
- **Descrizione**: Porta del server MinIO

#### `MINIO_USE_SSL`
- **Tipo**: Boolean
- **Richiesto**: ❌
- **Default**: `false`
- **Valori**: `true`, `false`
- **Descrizione**: Usa HTTPS per connessioni MinIO

#### `MINIO_BUCKET_NAME`
- **Tipo**: String
- **Richiesto**: ✅
- **Pattern**: `^[a-z0-9][a-z0-9-]*[a-z0-9]$`
- **Descrizione**: Nome del bucket per i certificati

#### `MINIO_URL`
- **Tipo**: String
- **Richiesto**: ✅
- **Descrizione**: URL pubblico di MinIO per accesso ai file

### Digital Certificate System Configuration

#### `CRYPTO_KEYS_PATH`
- **Tipo**: String (Path)
- **Richiesto**: ❌
- **Default**: `keys`
- **Descrizione**: Percorso directory delle chiavi crittografiche
- **Struttura**:
  ```
  keys/
  ├── private/
  │   ├── rsa-2024-01.pem
  │   └── ecdsa-2024-01.pem
  └── public/
      ├── rsa-2024-01.pub
      └── ecdsa-2024-01.pub
  ```

#### `CRYPTO_CURRENT_KEY_ID`
- **Tipo**: String
- **Richiesto**: ✅
- **Pattern**: `^(rsa|ecdsa)-[a-zA-Z0-9-]+$`
- **Descrizione**: ID della chiave corrente per nuovi certificati
- **Esempi**: `rsa-2024-01`, `ecdsa-prod-2024`

#### `CERTIFICATE_MAX_FILE_SIZE`
- **Tipo**: Number (bytes)
- **Richiesto**: ❌
- **Default**: `10485760` (10MB)
- **Descrizione**: Dimensione massima file certificato
- **Conversioni**:
  - 1MB = `1048576`
  - 5MB = `5242880`
  - 10MB = `10485760`

#### `CERTIFICATE_ALLOWED_TYPES`
- **Tipo**: String (comma-separated)
- **Richiesto**: ❌
- **Default**: `application/pdf,application/json,text/json`
- **Descrizione**: Tipi MIME consentiti per i certificati
- **Tipi supportati**:
  - `application/pdf` - File PDF
  - `application/json` - File JSON
  - `text/json` - File JSON (alternativo)
  - `text/plain` - File di testo (solo sviluppo)

#### `CERTIFICATE_STORAGE_PATH`
- **Tipo**: String
- **Richiesto**: ❌
- **Default**: `certificates`
- **Descrizione**: Percorso base nel bucket MinIO per i certificati

### Admin User Configuration

#### `ADMIN_EMAIL`
- **Tipo**: String (email)
- **Richiesto**: ✅
- **Formato**: Email valido
- **Descrizione**: Email dell'utente amministratore di default

#### `ADMIN_ROLE`
- **Tipo**: String
- **Richiesto**: ❌
- **Default**: `admin`
- **Valori**: `admin`, `user`
- **Descrizione**: Ruolo dell'utente amministratore

#### `ADMIN_PASSWORD`
- **Tipo**: String
- **Richiesto**: ✅
- **Lunghezza minima**: 8 caratteri
- **Descrizione**: Password dell'utente amministratore di default
- **Sicurezza**: Cambia immediatamente dopo il primo accesso

### Email Configuration (Opzionale)

#### `SMTP_HOST`
- **Tipo**: String
- **Richiesto**: ❌
- **Descrizione**: Hostname del server SMTP

#### `SMTP_PORT`
- **Tipo**: Number
- **Richiesto**: ❌
- **Default**: `587`
- **Valori comuni**: `25`, `465`, `587`, `2525`
- **Descrizione**: Porta del server SMTP

#### `SMTP_USER`
- **Tipo**: String
- **Richiesto**: ❌
- **Descrizione**: Username per autenticazione SMTP

#### `SMTP_PASS`
- **Tipo**: String
- **Richiesto**: ❌
- **Descrizione**: Password per autenticazione SMTP

#### `SMTP_FROM`
- **Tipo**: String (email)
- **Richiesto**: ❌
- **Descrizione**: Indirizzo email mittente di default

---

## Validazione Configurazione

### Script di Validazione

Crea uno script per validare la configurazione:

```typescript
// validate-config.ts
import { ConfigService } from '@nestjs/config';

export class ConfigValidator {
  static validate(config: ConfigService): string[] {
    const errors: string[] = [];

    // Validazione database
    if (!config.get('DATABASE_URL')) {
      errors.push('DATABASE_URL is required');
    }

    // Validazione JWT
    const jwtSecret = config.get('JWT_SECRET');
    if (!jwtSecret || jwtSecret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters long');
    }

    // Validazione MinIO
    if (!config.get('MINIO_ROOT_USER')) {
      errors.push('MINIO_ROOT_USER is required');
    }

    // Validazione chiavi crypto
    const keyId = config.get('CRYPTO_CURRENT_KEY_ID');
    if (!keyId || !/^(rsa|ecdsa)-[a-zA-Z0-9-]+$/.test(keyId)) {
      errors.push('CRYPTO_CURRENT_KEY_ID has invalid format');
    }

    return errors;
  }
}
```

### Comando di Validazione

```bash
# Aggiungi al package.json
{
  "scripts": {
    "validate:config": "ts-node src/utils/validate-config.ts"
  }
}

# Esegui validazione
npm run validate:config
```

---

## Gestione Segreti

### Sviluppo
- File `.env` locale (non committare)
- Valori semplici per facilità di sviluppo

### Staging/Produzione
- **AWS Secrets Manager**:
  ```bash
  aws secretsmanager create-secret \
    --name "certificates/database" \
    --secret-string '{"username":"user","password":"pass"}'
  ```

- **HashiCorp Vault**:
  ```bash
  vault kv put secret/certificates \
    database_password="secure_password" \
    jwt_secret="secure_jwt_secret"
  ```

- **Kubernetes Secrets**:
  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: certificates-secrets
  type: Opaque
  data:
    database-password: <base64-encoded-password>
    jwt-secret: <base64-encoded-secret>
  ```

- **Docker Secrets**:
  ```bash
  echo "secure_password" | docker secret create db_password -
  ```

---

## Template di Configurazione

### Template .env per Sviluppo

```bash
# Copia questo template e rinomina in .env
# Sostituisci i valori con quelli appropriati per il tuo ambiente

# Database
DB_HOST=localhost
POSTGRES_USER=certificates_dev
POSTGRES_PASSWORD=CHANGE_ME_DEV_PASSWORD
POSTGRES_DB=certificates_dev
POSTGRES_PORT=5432
DATABASE_URL=postgres://certificates_dev:CHANGE_ME_DEV_PASSWORD@localhost:5432/certificates_dev

# JWT
JWT_SECRET=CHANGE_ME_GENERATE_SECURE_JWT_SECRET_MIN_32_CHARS
JWT_EXPIRATION=24h

# Server
BE_PORT=3000
BE_URL=localhost:3000
FE_PORT=4200
FE_URL=localhost:4200
PRODUCTION=false

# MinIO
MINIO_ROOT_USER=certificates_admin
MINIO_ROOT_PASSWORD=CHANGE_ME_MINIO_PASSWORD
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_BUCKET_NAME=certificates-dev
MINIO_URL=localhost:9000

# Certificati
CRYPTO_KEYS_PATH=keys
CRYPTO_CURRENT_KEY_ID=rsa-dev-2024
CERTIFICATE_MAX_FILE_SIZE=10485760
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json,text/json
CERTIFICATE_STORAGE_PATH=certificates

# Admin
ADMIN_EMAIL=admin@localhost
ADMIN_ROLE=admin
ADMIN_PASSWORD=CHANGE_ME_ADMIN_PASSWORD

# Email (opzionale per sviluppo)
# SMTP_HOST=
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASS=
# SMTP_FROM=
```

### Generatore di Configurazione

```bash
#!/bin/bash
# generate-env.sh

ENV_TYPE=${1:-development}
OUTPUT_FILE=".env.${ENV_TYPE}"

echo "Generating ${OUTPUT_FILE} for ${ENV_TYPE} environment..."

# Genera password sicure
DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
JWT_SECRET=$(openssl rand -base64 64 | tr -d "=+/")
MINIO_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

cat > $OUTPUT_FILE << EOF
# Generated configuration for ${ENV_TYPE}
# Generated on: $(date)

# Database
DB_HOST=localhost
POSTGRES_USER=certificates_${ENV_TYPE}
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=certificates_${ENV_TYPE}
POSTGRES_PORT=5432
DATABASE_URL=postgres://certificates_${ENV_TYPE}:${DB_PASSWORD}@localhost:5432/certificates_${ENV_TYPE}

# JWT
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION=1h

# Server
BE_PORT=3000
BE_URL=localhost:3000
FE_PORT=4200
FE_URL=localhost:4200
PRODUCTION=false

# MinIO
MINIO_ROOT_USER=certificates_admin
MINIO_ROOT_PASSWORD=${MINIO_PASSWORD}
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_BUCKET_NAME=certificates-${ENV_TYPE}
MINIO_URL=localhost:9000

# Certificati
CRYPTO_KEYS_PATH=keys
CRYPTO_CURRENT_KEY_ID=rsa-${ENV_TYPE}-2024
CERTIFICATE_MAX_FILE_SIZE=10485760
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json,text/json
CERTIFICATE_STORAGE_PATH=certificates

# Admin
ADMIN_EMAIL=admin@${ENV_TYPE}.local
ADMIN_ROLE=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF

echo "Configuration generated: ${OUTPUT_FILE}"
echo "Please review and customize the values as needed."
```

---

## Troubleshooting Configurazione

### Errori Comuni

#### "Database connection failed"
```bash
# Verifica variabili database
echo $DATABASE_URL
psql $DATABASE_URL -c "SELECT 1;"

# Controlla formato URL
# Corretto: postgres://user:pass@host:port/db
# Sbagliato: postgresql://user:pass@host:port/db (in alcuni casi)
```

#### "JWT secret too short"
```bash
# Genera nuovo secret
openssl rand -base64 64

# Verifica lunghezza
echo $JWT_SECRET | wc -c
```

#### "MinIO connection refused"
```bash
# Verifica stato MinIO
curl http://$MINIO_ENDPOINT:$MINIO_PORT/minio/health/live

# Controlla credenziali
mc alias set test http://$MINIO_ENDPOINT:$MINIO_PORT $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
```

#### "Crypto keys not found"
```bash
# Verifica percorso chiavi
ls -la $CRYPTO_KEYS_PATH/

# Genera chiavi se mancanti
npx ts-node src/utils/generate-keys.ts rsa $CRYPTO_CURRENT_KEY_ID
```

### Debug Configurazione

```typescript
// debug-config.ts
import { ConfigService } from '@nestjs/config';

export function debugConfig(config: ConfigService) {
  console.log('=== Configuration Debug ===');
  
  // Database
  console.log('Database:', {
    host: config.get('DB_HOST'),
    port: config.get('POSTGRES_PORT'),
    database: config.get('POSTGRES_DB'),
    user: config.get('POSTGRES_USER'),
    // Non loggare password in produzione
    hasPassword: !!config.get('POSTGRES_PASSWORD')
  });
  
  // JWT
  console.log('JWT:', {
    hasSecret: !!config.get('JWT_SECRET'),
    secretLength: config.get('JWT_SECRET')?.length || 0,
    expiration: config.get('JWT_EXPIRATION')
  });
  
  // MinIO
  console.log('MinIO:', {
    endpoint: config.get('MINIO_ENDPOINT'),
    port: config.get('MINIO_PORT'),
    ssl: config.get('MINIO_USE_SSL'),
    bucket: config.get('MINIO_BUCKET_NAME')
  });
  
  // Crypto
  console.log('Crypto:', {
    keysPath: config.get('CRYPTO_KEYS_PATH'),
    currentKeyId: config.get('CRYPTO_CURRENT_KEY_ID')
  });
}
```

---

## Checklist Configurazione

### Pre-Deploy
- [ ] Tutte le variabili richieste sono impostate
- [ ] Password e segreti sono sicuri e unici
- [ ] URL e endpoint sono corretti per l'ambiente
- [ ] Chiavi crittografiche sono generate e sicure
- [ ] Database è accessibile con le credenziali fornite
- [ ] MinIO è accessibile e bucket è creato
- [ ] Configurazione email è testata (se usata)

### Post-Deploy
- [ ] Applicazione si avvia senza errori
- [ ] Health check passa
- [ ] Database migrations sono eseguite
- [ ] MinIO bucket è accessibile
- [ ] Chiavi crittografiche sono caricate correttamente
- [ ] Admin user è creato e accessibile
- [ ] Logging funziona correttamente

### Sicurezza
- [ ] File .env non è committato nel repository
- [ ] Password di default sono cambiate
- [ ] Segreti sono gestiti tramite sistema sicuro
- [ ] Accesso database è limitato
- [ ] MinIO ha policy di accesso appropriate
- [ ] Chiavi private hanno permessi corretti (600)

---

## Supporto

Per assistenza con la configurazione:
- **Email**: dev@vitoesposito.it
- **Documentazione**: `/docs/environment-configuration.md`
- **Template**: `/config/templates/`
- **Scripts**: `/scripts/config/`