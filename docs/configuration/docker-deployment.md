# 🐳 Docker Deployment Guide

## 📋 Panoramica

**Pandom Stack** è progettato per essere deployato facilmente con Docker e Docker Compose. Questa guida fornisce istruzioni complete per il deployment in diversi ambienti con focus su sicurezza e performance.

## 🏗️ **Architettura Docker**

### **Servizi Principali**

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Nginx Reverse Proxy]
    end
    
    subgraph "Application Layer"
        FE[Frontend Angular]
        BE1[Backend Instance 1]
        BE2[Backend Instance 2]
        BE3[Backend Instance 3]
    end
    
    subgraph "Data Layer"
        DB[(PostgreSQL)]
        MINIO[MinIO Storage]
    end
    
    subgraph "Monitoring"
        LOGS[Log Aggregation]
        METRICS[Metrics Collection]
    end
    
    LB --> FE
    LB --> BE1
    LB --> BE2
    LB --> BE3
    
    BE1 --> DB
    BE2 --> DB
    BE3 --> DB
    
    BE1 --> MINIO
    BE2 --> MINIO
    BE3 --> MINIO
    
    BE1 --> LOGS
    BE2 --> LOGS
    BE3 --> LOGS
```

### **Configurazioni Disponibili**

- **Development**: `docker-compose.yml` - Singola istanza per sviluppo
- **Production**: `docker-compose.prod.yml` - Multi-istanza con load balancing
- **Staging**: Configurazione intermedia per testing

## 🚀 **Development Deployment**

### **1. Setup Iniziale**

```bash
# Clone repository
git clone <repository-url>
cd pandom-stack

# Copia file di configurazione
cp demo.env .env

# Configura variabili ambiente
nano .env
```

### **2. Configurazione Environment**

```bash
# .env per development
NODE_ENV=development
DEBUG=true
LOG_LEVEL=debug

# Database
POSTGRES_USER=pandom_user
POSTGRES_PASSWORD=secure_password_123
POSTGRES_DB=pandom_db
DATABASE_URL=postgres://pandom_user:secure_password_123@postgres:5432/pandom_db

# JWT e Sessioni
JWT_SECRET=your-super-secret-jwt-key-change-this
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d
COOKIE_SECRET=your-cookie-secret-here
COOKIE_DOMAIN=localhost
COOKIE_SECURE=false
COOKIE_SAME_SITE=strict

# Server
BE_PORT=3000
BE_URL=http://localhost:3000
FE_PORT=4200
FE_URL=http://localhost:4200

# Admin
ADMIN_EMAIL=admin@pandom.com
ADMIN_PASSWORD=admin123
ADMIN_ROLE=admin

# MinIO
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_ENDPOINT=http://minio:9000
MINIO_BUCKET_NAME=pandom-storage

# Email (opzionale per development)
SMTP_ENABLED=false
```

### **3. Avvio Servizi**

```bash
# Avvia tutti i servizi
docker-compose up -d

# Monitora i log
docker-compose logs -f

# Verifica stato servizi
docker-compose ps
```

### **4. Verifica Installazione**

```bash
# Test backend
curl http://localhost:3000/health

# Test frontend
curl http://localhost:4200

# Test MinIO
curl http://localhost:9001

# Test database
docker-compose exec postgres pg_isready -U pandom_user -d pandom_db
```

## 🏭 **Production Deployment**

### **1. Configurazione Production**

```bash
# .env per production
NODE_ENV=production
DEBUG=false
LOG_LEVEL=info

# Database (usa password forti)
POSTGRES_USER=pandom_prod_user
POSTGRES_PASSWORD=$(openssl rand -base64 32)
POSTGRES_DB=pandom_prod_db
DATABASE_URL=postgres://pandom_prod_user:${POSTGRES_PASSWORD}@postgres:5432/pandom_prod_db

# JWT e Sessioni (usa secret forti)
JWT_SECRET=$(openssl rand -base64 64)
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d
COOKIE_SECRET=$(openssl rand -base64 32)
COOKIE_DOMAIN=yourdomain.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict

# Server
BE_PORT=3000
BE_URL=https://api.yourdomain.com
FE_URL=https://yourdomain.com

# Admin (cambia credenziali)
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=$(openssl rand -base64 16)
ADMIN_ROLE=admin

# MinIO (usa password forti)
MINIO_ROOT_USER=minio_prod_user
MINIO_ROOT_PASSWORD=$(openssl rand -base64 32)
MINIO_ENDPOINT=https://minio.yourdomain.com
MINIO_BUCKET_NAME=pandom-prod-storage

# Email
SMTP_ENABLED=true
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=your-smtp-password
SMTP_FROM=noreply@yourdomain.com

# Sicurezza
SECURITY_HEADERS_ENABLED=true
HTTPS_ENABLED=true
RATE_LIMIT_MAX_ATTEMPTS=5
RATE_LIMIT_WINDOW_MS=900000
```

### **2. Setup SSL/TLS**

```bash
# Crea directory per certificati
mkdir -p nginx/ssl

# Genera certificati SSL (Let's Encrypt raccomandato)
certbot certonly --standalone -d yourdomain.com -d api.yourdomain.com

# Copia certificati
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/
```

### **3. Configurazione Nginx**

```nginx
# nginx/nginx.conf
upstream backend {
    server backend:3000;
    server backend:3000;
    server backend:3000;
}

upstream frontend {
    server frontend:4200;
}

server {
    listen 80;
    server_name yourdomain.com api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### **4. Avvio Production**

```bash
# Usa configurazione production
docker-compose -f docker-compose.prod.yml up -d

# Verifica servizi
docker-compose -f docker-compose.prod.yml ps

# Monitora log
docker-compose -f docker-compose.prod.yml logs -f
```

## 🔧 **Configurazioni Docker**

### **Backend Dockerfile**

```dockerfile
# Multi-stage build per ottimizzazione
FROM node:20-alpine AS base
WORKDIR /src/app

# Installa dipendenze di sistema
RUN apk add --no-cache \
    postgresql-client \
    curl \
    && rm -rf /var/cache/apk/*

# Copia package files
COPY package*.json ./
RUN npm ci --only=production --silent

# Development stage
FROM base AS development
RUN npm install -g @nestjs/cli ts-node
COPY . .
EXPOSE 3000
CMD ["npm", "run", "start:dev"]

# Build stage
FROM base AS build
COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine AS production
WORKDIR /src/app

# Crea utente non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001

# Copia build e dipendenze
COPY --from=build --chown=nestjs:nodejs /src/app/dist ./dist
COPY --from=build --chown=nestjs:nodejs /src/app/node_modules ./node_modules
COPY --from=build --chown=nestjs:nodejs /src/app/package*.json ./

# Cambia utente
USER nestjs

EXPOSE 3000
CMD ["node", "dist/main.js"]
```

### **Frontend Dockerfile**

```dockerfile
# Multi-stage build
FROM node:20-alpine AS base
WORKDIR /frontend

# Development stage
FROM base AS development
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 4200
CMD ["npm", "start"]

# Build stage
FROM base AS build
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine AS production
COPY --from=build /frontend/dist/pandom-stack /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### **Docker Compose Production**

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  nginx:
    build:
      context: ./nginx
      dockerfile: Dockerfile
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - nginx_logs:/var/log/nginx
    depends_on:
      - backend
      - frontend
    restart: unless-stopped

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
      target: production
    environment:
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_URL=${DATABASE_URL}
      - COOKIE_SECRET=${COOKIE_SECRET}
      - COOKIE_DOMAIN=${COOKIE_DOMAIN}
      - COOKIE_SECURE=${COOKIE_SECURE}
      - COOKIE_SAME_SITE=${COOKIE_SAME_SITE}
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      target: production
    depends_on:
      - backend
    restart: unless-stopped

  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    volumes:
      - minio_data:/data
    command: server --console-address ":9001" /data
    restart: unless-stopped

volumes:
  postgres_data:
  minio_data:
  nginx_logs:
```

## 🔒 **Sicurezza Docker**

### **1. Security Best Practices**

```dockerfile
# Usa immagini ufficiali e aggiornate
FROM node:20-alpine

# Crea utente non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001

# Non esporre porte non necessarie
EXPOSE 3000

# Usa health checks
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Cambia utente
USER nestjs
```

### **2. Network Security**

```yaml
# docker-compose.yml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # Isola il network backend

services:
  backend:
    networks:
      - backend
      - frontend
    # Non espone porte direttamente
    expose:
      - "3000"

  postgres:
    networks:
      - backend
    # Solo accesso interno
    expose:
      - "5432"
```

### **3. Secrets Management**

```yaml
# docker-compose.yml
services:
  backend:
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
    secrets:
      - jwt_secret
      - database_password

secrets:
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  database_password:
    file: ./secrets/database_password.txt
```

## 📊 **Monitoring e Logging**

### **1. Health Checks**

```yaml
# docker-compose.yml
services:
  backend:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
```

### **2. Logging Configuration**

```yaml
# docker-compose.yml
services:
  backend:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=backend,environment=production"

  nginx:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=nginx,environment=production"
```

### **3. Resource Limits**

```yaml
# docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

  postgres:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
```

## 🔄 **Backup e Recovery**

### **1. Database Backup**

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="pandom_backup_${DATE}.sql"

# Crea backup
docker-compose exec -T postgres pg_dump \
  -U ${POSTGRES_USER} \
  -d ${POSTGRES_DB} \
  > ${BACKUP_DIR}/${BACKUP_FILE}

# Comprimi backup
gzip ${BACKUP_DIR}/${BACKUP_FILE}

# Rimuovi backup vecchi (più di 30 giorni)
find ${BACKUP_DIR} -name "pandom_backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: ${BACKUP_FILE}.gz"
```

### **2. MinIO Backup**

```bash
#!/bin/bash
# backup-minio.sh

BACKUP_DIR="/backups/minio"
DATE=$(date +%Y%m%d_%H%M%S)

# Crea backup MinIO
docker-compose exec minio mc mirror /data ${BACKUP_DIR}/minio_${DATE}

echo "MinIO backup completed: minio_${DATE}"
```

### **3. Automated Backup**

```yaml
# docker-compose.yml
services:
  backup:
    image: postgres:17-alpine
    volumes:
      - ./backups:/backups
      - ./scripts:/scripts
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    command: >
      sh -c "
        while true; do
          /scripts/backup-database.sh
          sleep 86400  # 24 ore
        done
      "
    depends_on:
      - postgres
```

## 🚀 **Deployment Automation**

### **1. CI/CD Pipeline**

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to server
        uses: appleboy/ssh-action@v0.1.5
        with:
          host: ${{ secrets.HOST }}
          username: ${{ secrets.USERNAME }}
          key: ${{ secrets.SSH_KEY }}
          script: |
            cd /opt/pandom-stack
            git pull origin main
            docker-compose -f docker-compose.prod.yml down
            docker-compose -f docker-compose.prod.yml build
            docker-compose -f docker-compose.prod.yml up -d
```

### **2. Zero-Downtime Deployment**

```bash
#!/bin/bash
# zero-downtime-deploy.sh

# Build nuove immagini
docker-compose -f docker-compose.prod.yml build

# Rolling update backend
docker-compose -f docker-compose.prod.yml up -d --no-deps backend

# Attendi che i nuovi container siano pronti
sleep 30

# Aggiorna frontend
docker-compose -f docker-compose.prod.yml up -d --no-deps frontend

# Pulisci immagini vecchie
docker image prune -f

echo "Deployment completed successfully"
```

## 📋 **Troubleshooting**

### **1. Common Issues**

```bash
# Container non si avvia
docker-compose logs backend

# Database connection issues
docker-compose exec postgres pg_isready -U pandom_user -d pandom_db

# Memory issues
docker stats

# Disk space issues
docker system df
docker system prune -f
```

### **2. Performance Tuning**

```bash
# Ottimizza Docker daemon
echo '{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}' > /etc/docker/daemon.json

# Riavvia Docker
systemctl restart docker
```

---

**Pandom Stack Docker** - Deployment containerizzato enterprise-grade con focus su sicurezza, scalabilità e monitoring.
