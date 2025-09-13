# Guida al Deployment - Sistema di Certificazione Digitale

## Panoramica

Questa guida fornisce istruzioni dettagliate per il deployment del sistema di certificazione digitale in ambienti di sviluppo, staging e produzione. Il sistema richiede una configurazione sicura delle chiavi crittografiche e una corretta gestione dell'infrastruttura.

---

## Prerequisiti

### Software Richiesto
- **Node.js**: v18.0.0 o superiore
- **PostgreSQL**: v13.0 o superiore
- **MinIO**: Ultima versione stabile
- **Docker**: v20.0.0 o superiore (opzionale)
- **OpenSSL**: v1.1.1 o superiore (per generazione chiavi)

### Dipendenze Sistema
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nodejs npm postgresql-client openssl

# macOS (con Homebrew)
brew install node postgresql openssl

# Verifica installazioni
node --version
npm --version
psql --version
openssl version
```

---

## Configurazione Ambiente

### 1. Variabili d'Ambiente

Crea il file `.env` nella root del progetto backend:

```bash
# Database Configuration
DB_HOST=localhost
POSTGRES_USER=certificates_user
POSTGRES_PASSWORD=secure_password_here
POSTGRES_DB=certificates_db
POSTGRES_PORT=5432
DATABASE_URL=postgres://certificates_user:secure_password_here@localhost:5432/certificates_db

# JWT Configuration
JWT_SECRET=your_super_secure_jwt_secret_here_min_32_chars
JWT_EXPIRATION=1h

# Server Configuration
BE_PORT=3000
BE_URL=localhost:3000
FE_PORT=4200
FE_URL=localhost:4200
PRODUCTION=false

# MinIO Configuration
MINIO_ROOT_USER=certificates_admin
MINIO_ROOT_PASSWORD=secure_minio_password_here
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_BUCKET_NAME=certificates
MINIO_URL=localhost:9000

# Digital Certificate System Configuration
CRYPTO_KEYS_PATH=keys
CRYPTO_CURRENT_KEY_ID=rsa-2024-01
CERTIFICATE_MAX_FILE_SIZE=10485760
CERTIFICATE_ALLOWED_TYPES=application/pdf,application/json,text/json
CERTIFICATE_STORAGE_PATH=certificates

# Admin User Configuration
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_ROLE=admin
ADMIN_PASSWORD=secure_admin_password_here

# Email Configuration (opzionale)
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=smtp_password_here
SMTP_FROM=noreply@yourdomain.com
```

### 2. Configurazione Sicurezza Produzione

Per ambienti di produzione, modifica le seguenti variabili:

```bash
# Produzione
PRODUCTION=true
BE_URL=your-api-domain.com
FE_URL=your-frontend-domain.com
MINIO_USE_SSL=true
MINIO_ENDPOINT=your-minio-domain.com

# Database (usa connessioni SSL)
DATABASE_URL=postgres://user:pass@db-host:5432/db?sslmode=require

# JWT (genera secret sicuro)
JWT_SECRET=$(openssl rand -base64 64)
```

---

## Gestione Chiavi Crittografiche

### 1. Generazione Chiavi per Sviluppo

```bash
# Naviga nella directory backend
cd backend

# Genera chiavi RSA per sviluppo
npx ts-node src/utils/generate-keys.ts rsa rsa-2024-01

# Oppure genera chiavi ECDSA
npx ts-node src/utils/generate-keys.ts ecdsa ecdsa-2024-01

# Verifica che le chiavi siano state create
ls -la keys/
```

### 2. Generazione Chiavi per Produzione

#### Opzione A: Script Automatico
```bash
# Genera chiavi RSA 2048-bit per produzione
npx ts-node src/utils/generate-keys.ts rsa rsa-prod-$(date +%Y-%m)

# Imposta permessi sicuri
chmod 600 keys/private/*.pem
chmod 644 keys/public/*.pub
chown -R app:app keys/
```

#### Opzione B: OpenSSL Manuale
```bash
# Crea directory per le chiavi
mkdir -p keys/private keys/public

# Genera chiave privata RSA 2048-bit
openssl genpkey -algorithm RSA -pkcs8 -out keys/private/rsa-prod-2024-01.pem -pkcs8 -aes256

# Estrai chiave pubblica
openssl pkey -in keys/private/rsa-prod-2024-01.pem -pubout -out keys/public/rsa-prod-2024-01.pub

# Imposta permessi
chmod 600 keys/private/rsa-prod-2024-01.pem
chmod 644 keys/public/rsa-prod-2024-01.pub
```

#### Opzione C: Hardware Security Module (HSM)
Per ambienti ad alta sicurezza, considera l'uso di HSM:

```bash
# Esempio con AWS CloudHSM
aws cloudhsmv2 create-cluster --hsm-type hsm1.medium

# Configura variabili per HSM
HSM_CLUSTER_ID=cluster-xxxxxxxxx
HSM_USER=crypto_user
HSM_PASSWORD=hsm_password
```

### 3. Rotazione Chiavi

#### Script di Rotazione
```bash
#!/bin/bash
# rotate-keys.sh

OLD_KEY_ID=$1
NEW_KEY_ID=$2

if [ -z "$OLD_KEY_ID" ] || [ -z "$NEW_KEY_ID" ]; then
    echo "Usage: $0 <old-key-id> <new-key-id>"
    exit 1
fi

echo "Rotating keys from $OLD_KEY_ID to $NEW_KEY_ID"

# Genera nuove chiavi
npx ts-node src/utils/generate-keys.ts rsa $NEW_KEY_ID

# Aggiorna configurazione
sed -i "s/CRYPTO_CURRENT_KEY_ID=$OLD_KEY_ID/CRYPTO_CURRENT_KEY_ID=$NEW_KEY_ID/" .env

# Riavvia servizio
systemctl restart certificates-api

echo "Key rotation completed"
```

#### Procedura di Rotazione
1. **Genera nuove chiavi** senza interrompere il servizio
2. **Aggiorna configurazione** per usare le nuove chiavi per nuovi certificati
3. **Mantieni chiavi vecchie** per verificare certificati esistenti
4. **Monitora** che tutto funzioni correttamente
5. **Archivia chiavi vecchie** dopo un periodo di grazia

---

## Setup Database

### 1. Installazione PostgreSQL

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib

# Avvia servizio
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### Docker
```bash
docker run --name certificates-postgres \
  -e POSTGRES_USER=certificates_user \
  -e POSTGRES_PASSWORD=secure_password_here \
  -e POSTGRES_DB=certificates_db \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  -d postgres:13
```

### 2. Configurazione Database

```sql
-- Connetti come superuser
sudo -u postgres psql

-- Crea utente e database
CREATE USER certificates_user WITH PASSWORD 'secure_password_here';
CREATE DATABASE certificates_db OWNER certificates_user;

-- Concedi privilegi
GRANT ALL PRIVILEGES ON DATABASE certificates_db TO certificates_user;

-- Configura estensioni (se necessarie)
\c certificates_db
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

### 3. Migrazione Database

```bash
# Installa dipendenze
npm install

# Esegui migrazioni
npm run migration:run

# Verifica tabelle create
psql -h localhost -U certificates_user -d certificates_db -c "\dt"
```

---

## Setup MinIO

### 1. Installazione MinIO

#### Docker (Raccomandato)
```bash
docker run --name certificates-minio \
  -p 9000:9000 \
  -p 9001:9001 \
  -e MINIO_ROOT_USER=certificates_admin \
  -e MINIO_ROOT_PASSWORD=secure_minio_password_here \
  -v minio_data:/data \
  -d minio/minio server /data --console-address ":9001"
```

#### Installazione Nativa
```bash
# Download MinIO
wget https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
sudo mv minio /usr/local/bin/

# Crea utente e directory
sudo useradd -r minio-user -s /sbin/nologin
sudo mkdir -p /opt/minio/data
sudo chown minio-user:minio-user /opt/minio/data

# Crea file di configurazione
sudo tee /etc/default/minio << EOF
MINIO_ROOT_USER=certificates_admin
MINIO_ROOT_PASSWORD=secure_minio_password_here
MINIO_VOLUMES="/opt/minio/data"
MINIO_OPTS="--console-address :9001"
EOF

# Crea servizio systemd
sudo tee /etc/systemd/system/minio.service << EOF
[Unit]
Description=MinIO
Documentation=https://docs.min.io
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=/usr/local/bin/minio

[Service]
WorkingDirectory=/usr/local/
User=minio-user
Group=minio-user
EnvironmentFile=/etc/default/minio
ExecStartPre=/bin/bash -c "if [ -z \"\${MINIO_VOLUMES}\" ]; then echo \"Variable MINIO_VOLUMES not set in /etc/default/minio\"; exit 1; fi"
ExecStart=/usr/local/bin/minio server \$MINIO_OPTS \$MINIO_VOLUMES
Restart=always
LimitNOFILE=65536
TasksMax=infinity
TimeoutStopSec=infinity
SendSIGKILL=no

[Install]
WantedBy=multi-user.target
EOF

# Avvia servizio
sudo systemctl daemon-reload
sudo systemctl enable minio
sudo systemctl start minio
```

### 2. Configurazione Bucket

```bash
# Installa MinIO Client
wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
sudo mv mc /usr/local/bin/

# Configura alias
mc alias set local http://localhost:9000 certificates_admin secure_minio_password_here

# Crea bucket
mc mb local/certificates

# Imposta policy pubblica per lettura
mc policy set public local/certificates

# Verifica configurazione
mc ls local/
```

---

## Deployment Applicazione

### 1. Build Produzione

```bash
# Backend
cd backend
npm ci --only=production
npm run build

# Frontend
cd ../frontend
npm ci --only=production
npm run build:prod
```

### 2. Deployment con PM2

```bash
# Installa PM2
npm install -g pm2

# Crea file ecosystem
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'certificates-api',
    script: 'dist/main.js',
    cwd: './backend',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true
  }]
};
EOF

# Avvia applicazione
pm2 start ecosystem.config.js

# Salva configurazione PM2
pm2 save
pm2 startup
```

### 3. Deployment con Docker

#### Dockerfile Backend
```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copia package files
COPY package*.json ./
RUN npm ci --only=production

# Copia codice
COPY dist/ ./dist/
COPY keys/ ./keys/

# Crea utente non-root
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001
RUN chown -R nestjs:nodejs /app
USER nestjs

EXPOSE 3000

CMD ["node", "dist/main.js"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  certificates-api:
    build: ./backend
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    env_file:
      - .env
    depends_on:
      - postgres
      - minio
    volumes:
      - ./keys:/app/keys:ro
    restart: unless-stopped

  postgres:
    image: postgres:13
    environment:
      POSTGRES_USER: certificates_user
      POSTGRES_PASSWORD: secure_password_here
      POSTGRES_DB: certificates_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: certificates_admin
      MINIO_ROOT_PASSWORD: secure_minio_password_here
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - certificates-api
    restart: unless-stopped

volumes:
  postgres_data:
  minio_data:
```

---

## Configurazione Nginx

### 1. Configurazione Base

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream api {
        server certificates-api:3000;
    }

    server {
        listen 80;
        server_name your-domain.com;

        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

        # API routes
        location /certificates {
            proxy_pass http://api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # File upload limits
            client_max_body_size 10M;
        }

        # Frontend
        location / {
            root /var/www/html;
            try_files $uri $uri/ /index.html;
        }
    }
}
```

---

## Monitoraggio e Logging

### 1. Configurazione Logging

```typescript
// logger.config.ts
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';

export const loggerConfig = WinstonModule.createLogger({
  transports: [
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});
```

### 2. Health Checks

```typescript
// health.controller.ts
@Controller('health')
export class HealthController {
  @Get()
  async check() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      services: {
        database: await this.checkDatabase(),
        minio: await this.checkMinio(),
        crypto: await this.checkCrypto()
      }
    };
  }
}
```

### 3. Metriche con Prometheus

```typescript
// metrics.service.ts
import { register, Counter, Histogram } from 'prom-client';

export class MetricsService {
  private certificateGenerated = new Counter({
    name: 'certificates_generated_total',
    help: 'Total number of certificates generated'
  });

  private verificationDuration = new Histogram({
    name: 'certificate_verification_duration_seconds',
    help: 'Duration of certificate verification'
  });
}
```

---

## Backup e Recovery

### 1. Backup Database

```bash
#!/bin/bash
# backup-db.sh

BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="certificates_db_$DATE.sql"

mkdir -p $BACKUP_DIR

pg_dump -h localhost -U certificates_user certificates_db > "$BACKUP_DIR/$BACKUP_FILE"

# Comprimi backup
gzip "$BACKUP_DIR/$BACKUP_FILE"

# Rimuovi backup vecchi (mantieni ultimi 30 giorni)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Database backup completed: $BACKUP_FILE.gz"
```

### 2. Backup MinIO

```bash
#!/bin/bash
# backup-minio.sh

BACKUP_DIR="/backups/minio"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup usando MinIO Client
mc mirror local/certificates "$BACKUP_DIR/certificates_$DATE"

# Comprimi backup
tar -czf "$BACKUP_DIR/certificates_$DATE.tar.gz" "$BACKUP_DIR/certificates_$DATE"
rm -rf "$BACKUP_DIR/certificates_$DATE"

echo "MinIO backup completed: certificates_$DATE.tar.gz"
```

### 3. Backup Chiavi Crittografiche

```bash
#!/bin/bash
# backup-keys.sh

BACKUP_DIR="/backups/keys"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup chiavi con crittografia
tar -czf - keys/ | gpg --cipher-algo AES256 --compress-algo 1 --symmetric --output "$BACKUP_DIR/keys_$DATE.tar.gz.gpg"

echo "Keys backup completed: keys_$DATE.tar.gz.gpg"
echo "Remember to store the GPG passphrase securely!"
```

---

## Sicurezza

### 1. Hardening Sistema

```bash
# Aggiorna sistema
sudo apt update && sudo apt upgrade -y

# Configura firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Disabilita servizi non necessari
sudo systemctl disable apache2
sudo systemctl disable sendmail
```

### 2. Sicurezza Database

```sql
-- Configura SSL
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/etc/ssl/certs/server.crt';
ALTER SYSTEM SET ssl_key_file = '/etc/ssl/private/server.key';

-- Limita connessioni
ALTER SYSTEM SET max_connections = 100;
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';

-- Riavvia PostgreSQL
SELECT pg_reload_conf();
```

### 3. Sicurezza MinIO

```bash
# Configura HTTPS per MinIO
mc admin config set local/ api secure_ciphers="ECDHE-RSA-AES128-GCM-SHA256"
mc admin config set local/ api requests_max=1000
mc admin config set local/ api requests_deadline=10s

# Riavvia MinIO
mc admin service restart local/
```

---

## Troubleshooting

### 1. Problemi Comuni

#### Errore: "Key not found"
```bash
# Verifica esistenza chiavi
ls -la keys/private/
ls -la keys/public/

# Controlla permessi
chmod 600 keys/private/*.pem
chmod 644 keys/public/*.pub

# Verifica configurazione
echo $CRYPTO_CURRENT_KEY_ID
```

#### Errore: "MinIO connection failed"
```bash
# Verifica stato MinIO
docker ps | grep minio
curl http://localhost:9000/minio/health/live

# Controlla logs
docker logs certificates-minio
```

#### Errore: "Database connection failed"
```bash
# Verifica connessione
psql -h localhost -U certificates_user -d certificates_db -c "SELECT 1;"

# Controlla logs PostgreSQL
sudo tail -f /var/log/postgresql/postgresql-13-main.log
```

### 2. Debug Mode

```bash
# Avvia in modalità debug
NODE_ENV=development npm run start:debug

# Abilita logging dettagliato
DEBUG=* npm start
```

### 3. Performance Tuning

#### PostgreSQL
```sql
-- Ottimizza per certificati
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
```

#### Node.js
```bash
# Ottimizza memoria V8
export NODE_OPTIONS="--max-old-space-size=2048"

# Abilita clustering
export NODE_ENV=production
export CLUSTER_MODE=true
```

---

## Checklist Deployment

### Pre-Deployment
- [ ] Variabili d'ambiente configurate
- [ ] Chiavi crittografiche generate e sicure
- [ ] Database configurato e migrato
- [ ] MinIO configurato con bucket
- [ ] SSL/TLS certificati installati
- [ ] Backup strategy implementata
- [ ] Monitoring configurato

### Post-Deployment
- [ ] Health checks passano
- [ ] Generazione certificato test
- [ ] Verifica certificato test
- [ ] Download certificato test
- [ ] Revoca certificato test
- [ ] Performance test
- [ ] Security scan
- [ ] Backup test e recovery

### Produzione
- [ ] DNS configurato
- [ ] Load balancer configurato
- [ ] CDN configurato (se necessario)
- [ ] Monitoring alerts attivi
- [ ] Log rotation configurato
- [ ] Disaster recovery testato
- [ ] Documentazione aggiornata

---

## Supporto

Per assistenza con il deployment:
- **Email**: dev@vitoesposito.it
- **Documentazione**: `/docs/deployment-guide.md`
- **Issues**: Repository GitHub del progetto

---

## Appendice

### A. Script di Automazione

Tutti gli script menzionati in questa guida sono disponibili nella directory `scripts/deployment/`:

- `setup-environment.sh` - Setup iniziale ambiente
- `generate-keys.sh` - Generazione chiavi crittografiche
- `backup-system.sh` - Backup completo sistema
- `health-check.sh` - Controllo stato servizi
- `deploy.sh` - Deploy automatico

### B. Template Configurazione

Template di configurazione per diversi ambienti sono disponibili in `config/templates/`:

- `development.env` - Configurazione sviluppo
- `staging.env` - Configurazione staging
- `production.env` - Configurazione produzione

### C. Monitoring Dashboard

Dashboard Grafana pre-configurate disponibili in `monitoring/dashboards/`:

- `certificates-overview.json` - Dashboard generale
- `performance-metrics.json` - Metriche performance
- `security-alerts.json` - Alert sicurezza