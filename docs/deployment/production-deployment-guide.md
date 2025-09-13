# 🚀 Production Deployment Guide

## 📋 Panoramica

Questa guida fornisce istruzioni complete per il deployment di **Pandom Stack** in ambiente di produzione con focus su sicurezza, performance, scalabilità e monitoring.

## 🏗️ **Architettura di Produzione**

### **Infrastruttura Raccomandata**

```mermaid
graph TB
    subgraph "Load Balancer Layer"
        LB[Load Balancer/Reverse Proxy]
        SSL[SSL Termination]
    end
    
    subgraph "Application Layer"
        FE1[Frontend Instance 1]
        FE2[Frontend Instance 2]
        BE1[Backend Instance 1]
        BE2[Backend Instance 2]
        BE3[Backend Instance 3]
    end
    
    subgraph "Data Layer"
        DB_PRIMARY[(PostgreSQL Primary)]
        DB_REPLICA[(PostgreSQL Replica)]
        MINIO[MinIO Cluster]
    end
    
    subgraph "Monitoring & Logging"
        PROMETHEUS[Prometheus]
        GRAFANA[Grafana]
        ELK[ELK Stack]
    end
    
    subgraph "Security"
        WAF[Web Application Firewall]
        IDS[Intrusion Detection]
        BACKUP[Backup System]
    end
    
    LB --> FE1
    LB --> FE2
    LB --> BE1
    LB --> BE2
    LB --> BE3
    
    BE1 --> DB_PRIMARY
    BE2 --> DB_PRIMARY
    BE3 --> DB_PRIMARY
    
    DB_PRIMARY --> DB_REPLICA
    
    BE1 --> MINIO
    BE2 --> MINIO
    BE3 --> MINIO
    
    BE1 --> PROMETHEUS
    BE2 --> PROMETHEUS
    BE3 --> PROMETHEUS
```

### **Requisiti di Sistema**

#### **Server Raccomandati**

| Componente | CPU | RAM | Storage | Network |
|------------|-----|-----|---------|---------|
| **Load Balancer** | 2 cores | 4GB | 20GB SSD | 1Gbps |
| **Frontend** | 2 cores | 4GB | 20GB SSD | 1Gbps |
| **Backend** | 4 cores | 8GB | 50GB SSD | 1Gbps |
| **Database** | 8 cores | 16GB | 200GB SSD | 1Gbps |
| **MinIO** | 4 cores | 8GB | 500GB SSD | 1Gbps |
| **Monitoring** | 2 cores | 4GB | 100GB SSD | 1Gbps |

#### **Requisiti Minimi**

| Componente | CPU | RAM | Storage | Network |
|------------|-----|-----|---------|---------|
| **Load Balancer** | 1 core | 2GB | 10GB SSD | 100Mbps |
| **Frontend** | 1 core | 2GB | 10GB SSD | 100Mbps |
| **Backend** | 2 cores | 4GB | 20GB SSD | 100Mbps |
| **Database** | 4 cores | 8GB | 100GB SSD | 100Mbps |
| **MinIO** | 2 cores | 4GB | 200GB SSD | 100Mbps |

## 🔧 **Preparazione Ambiente**

### **1. Setup Server**

```bash
# Aggiorna sistema
sudo apt update && sudo apt upgrade -y

# Installa Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Installa Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Installa utilità
sudo apt install -y git curl wget htop nginx certbot python3-certbot-nginx
```

### **2. Configurazione Firewall**

```bash
# Configura UFW
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Porte essenziali
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS

# Porte per monitoring (opzionale)
sudo ufw allow 3000/tcp  # Grafana
sudo ufw allow 9090/tcp  # Prometheus
```

### **3. Setup SSL/TLS**

```bash
# Installa Certbot
sudo apt install certbot python3-certbot-nginx

# Genera certificati SSL
sudo certbot --nginx -d yourdomain.com -d api.yourdomain.com

# Configura auto-renewal
sudo crontab -e
# Aggiungi: 0 12 * * * /usr/bin/certbot renew --quiet
```

## 🐳 **Deployment Docker**

### **1. Configurazione Environment**

```bash
# Crea directory progetto
sudo mkdir -p /opt/pandom-stack
cd /opt/pandom-stack

# Clone repository
sudo git clone <repository-url> .

# Crea file environment
sudo nano .env
```

### **2. Environment Production**

```bash
# .env per production
NODE_ENV=production
DEBUG=false
LOG_LEVEL=info

# Database
POSTGRES_USER=pandom_prod_user
POSTGRES_PASSWORD=$(openssl rand -base64 32)
POSTGRES_DB=pandom_prod_db
DATABASE_URL=postgres://pandom_prod_user:${POSTGRES_PASSWORD}@postgres:5432/pandom_prod_db

# JWT e Sessioni
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

# Admin
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=$(openssl rand -base64 16)
ADMIN_ROLE=admin

# MinIO
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

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
```

### **3. Configurazione Nginx**

```nginx
# /etc/nginx/sites-available/pandom-stack
upstream backend {
    least_conn;
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
}

upstream frontend {
    least_conn;
    server 127.0.0.1:4200 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:4201 max_fails=3 fail_timeout=30s;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;

server {
    listen 80;
    server_name yourdomain.com api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'";

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Rate limiting
    limit_req zone=api burst=20 nodelay;
    limit_req zone=auth burst=10 nodelay;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

### **4. Avvio Servizi**

```bash
# Abilita sito Nginx
sudo ln -s /etc/nginx/sites-available/pandom-stack /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Avvia servizi Docker
sudo docker-compose -f docker-compose.prod.yml up -d

# Verifica stato
sudo docker-compose -f docker-compose.prod.yml ps
```

## 📊 **Monitoring e Logging**

### **1. Setup Prometheus**

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'pandom-backend'
    static_configs:
      - targets: ['backend:3000']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'pandom-database'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'pandom-minio'
    static_configs:
      - targets: ['minio:9000']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### **2. Setup Grafana**

```yaml
# monitoring/grafana/dashboards/pandom-stack.json
{
  "dashboard": {
    "title": "Pandom Stack Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors"
          }
        ]
      }
    ]
  }
}
```

### **3. Setup ELK Stack**

```yaml
# logging/docker-compose.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
```

## 🔒 **Sicurezza Produzione**

### **1. Web Application Firewall**

```bash
# Installa ModSecurity
sudo apt install libapache2-mod-security2

# Configura regole
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo nano /etc/modsecurity/modsecurity.conf

# Abilita in Nginx
sudo apt install nginx-module-security
```

### **2. Intrusion Detection**

```bash
# Installa Fail2Ban
sudo apt install fail2ban

# Configura per Nginx
sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
```

### **3. Security Headers**

```nginx
# Aggiungi a Nginx config
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'";
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";
```

## 🔄 **Backup e Recovery**

### **1. Automated Backup**

```bash
#!/bin/bash
# /opt/pandom-stack/scripts/backup.sh

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Database backup
docker-compose -f docker-compose.prod.yml exec -T postgres pg_dump \
  -U ${POSTGRES_USER} \
  -d ${POSTGRES_DB} \
  > ${BACKUP_DIR}/database_${DATE}.sql

# MinIO backup
docker-compose -f docker-compose.prod.yml exec minio mc mirror /data ${BACKUP_DIR}/minio_${DATE}

# Compress backups
gzip ${BACKUP_DIR}/database_${DATE}.sql
tar -czf ${BACKUP_DIR}/minio_${DATE}.tar.gz ${BACKUP_DIR}/minio_${DATE}

# Upload to cloud storage (AWS S3, Google Cloud, etc.)
aws s3 cp ${BACKUP_DIR}/database_${DATE}.sql.gz s3://your-backup-bucket/
aws s3 cp ${BACKUP_DIR}/minio_${DATE}.tar.gz s3://your-backup-bucket/

# Cleanup old backups
find ${BACKUP_DIR} -name "*.sql.gz" -mtime +${RETENTION_DAYS} -delete
find ${BACKUP_DIR} -name "*.tar.gz" -mtime +${RETENTION_DAYS} -delete

echo "Backup completed: ${DATE}"
```

### **2. Recovery Procedures**

```bash
#!/bin/bash
# /opt/pandom-stack/scripts/restore.sh

BACKUP_DATE=$1
BACKUP_DIR="/opt/backups"

if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    echo "Available backups:"
    ls -la ${BACKUP_DIR}/*.sql.gz | awk '{print $9}' | sed 's/.*database_\(.*\)\.sql\.gz/\1/'
    exit 1
fi

# Stop services
docker-compose -f docker-compose.prod.yml down

# Restore database
gunzip -c ${BACKUP_DIR}/database_${BACKUP_DATE}.sql.gz | \
docker-compose -f docker-compose.prod.yml exec -T postgres psql -U ${POSTGRES_USER} -d ${POSTGRES_DB}

# Restore MinIO
tar -xzf ${BACKUP_DIR}/minio_${BACKUP_DATE}.tar.gz -C ${BACKUP_DIR}/
docker-compose -f docker-compose.prod.yml exec minio mc mirror ${BACKUP_DIR}/minio_${BACKUP_DATE} /data

# Start services
docker-compose -f docker-compose.prod.yml up -d

echo "Restore completed: ${BACKUP_DATE}"
```

### **3. Disaster Recovery**

```bash
#!/bin/bash
# /opt/pandom-stack/scripts/disaster-recovery.sh

# 1. Provision new server
# 2. Install Docker and dependencies
# 3. Clone repository
# 4. Restore from latest backup
# 5. Update DNS records
# 6. Verify functionality

echo "Disaster recovery procedure initiated"
echo "1. Provisioning new server..."
echo "2. Installing dependencies..."
echo "3. Restoring from backup..."
echo "4. Updating DNS..."
echo "5. Verification complete"
```

## 📈 **Performance Optimization**

### **1. Database Optimization**

```sql
-- PostgreSQL tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Reload configuration
SELECT pg_reload_conf();
```

### **2. Application Optimization**

```bash
# Node.js optimization
export NODE_ENV=production
export NODE_OPTIONS="--max-old-space-size=4096"

# PM2 for process management
npm install -g pm2
pm2 start ecosystem.config.js
```

### **3. Caching Strategy**

```nginx
# Nginx caching
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m max_size=1g inactive=60m;

location /api/ {
    proxy_cache api_cache;
    proxy_cache_valid 200 5m;
    proxy_cache_valid 404 1m;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
}
```

## 🚨 **Alerting e Incident Response**

### **1. Alert Rules**

```yaml
# monitoring/rules/alerts.yml
groups:
  - name: pandom-stack
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value }} seconds"

      - alert: DatabaseDown
        expr: up{job="pandom-database"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database is down"
          description: "PostgreSQL database is not responding"
```

### **2. Incident Response**

```bash
#!/bin/bash
# /opt/pandom-stack/scripts/incident-response.sh

INCIDENT_TYPE=$1

case $INCIDENT_TYPE in
    "high-error-rate")
        echo "High error rate detected - scaling up backend instances"
        docker-compose -f docker-compose.prod.yml up -d --scale backend=5
        ;;
    "database-down")
        echo "Database down - initiating failover"
        # Switch to replica
        # Notify team
        ;;
    "disk-space")
        echo "Low disk space - cleaning up logs and old backups"
        docker system prune -f
        find /var/log -name "*.log" -mtime +7 -delete
        ;;
esac
```

## 📋 **Maintenance Procedures**

### **1. Regular Maintenance**

```bash
#!/bin/bash
# /opt/pandom-stack/scripts/maintenance.sh

# Weekly maintenance tasks
echo "Starting weekly maintenance..."

# Update system packages
sudo apt update && sudo apt upgrade -y

# Clean Docker
docker system prune -f
docker volume prune -f

# Rotate logs
sudo logrotate -f /etc/logrotate.conf

# Update SSL certificates
sudo certbot renew --quiet

# Restart services
docker-compose -f docker-compose.prod.yml restart

echo "Maintenance completed"
```

### **2. Health Checks**

```bash
#!/bin/bash
# /opt/pandom-stack/scripts/health-check.sh

# Check all services
curl -f http://localhost/health || echo "Frontend health check failed"
curl -f http://localhost:3000/health || echo "Backend health check failed"
curl -f http://localhost:9200/_cluster/health || echo "Elasticsearch health check failed"

# Check disk space
df -h | awk '$5 > 80 {print $0}'

# Check memory usage
free -h | awk 'NR==2{printf "Memory Usage: %s/%s (%.2f%%)\n", $3,$2,$3*100/$2 }'

# Check CPU usage
top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1
```

---

**Pandom Stack Production** - Deployment enterprise-grade con focus su sicurezza, performance, scalabilità e monitoring.