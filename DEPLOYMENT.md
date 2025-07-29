# Deployment Guide

## Production Deployment

### Ubuntu Server'da Docker ile Deployment

1. **Server Hazırlığı**
```bash
# Ubuntu güncellemeleri
sudo apt update && sudo apt upgrade -y

# Docker kurulumu
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose kurulumu
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

2. **SSL Checker Deployment**
```bash
# Repository klonlama
git clone https://github.com/your-username/Good-SSL-Checker.git
cd Good-SSL-Checker

# Production için environment
cp .env.example .env
nano .env  # Gerekli ayarları yapın

# Docker Compose ile başlatma
docker-compose -f docker-compose.prod.yml up -d
```

3. **Nginx Reverse Proxy (Opsiyonel)**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Environment Variables

```bash
# .env dosyası
FLASK_ENV=production
SECRET_KEY=your-super-secret-key-here
MAX_DOMAINS=50
SSL_TIMEOUT=10
WORKERS=4
```

## Monitoring & Logging

### Health Check
```bash
curl http://localhost:5000/health
```

### Log Monitoring
```bash
docker-compose logs -f ssl-checker
```

## Security Considerations

1. **API Rate Limiting**: Production'da rate limiting ekleyin
2. **HTTPS**: SSL sertifikası ile güvenli erişim
3. **Firewall**: Sadece gerekli portları açın (80, 443)
4. **Resource Limits**: Docker container'lar için resource limitleri belirleyin

## Backup Strategy

```bash
# Container volumes backup
docker run --rm -v ssl-checker_logs:/backup-source -v $(pwd):/backup alpine tar czf /backup/ssl-checker-backup-$(date +%Y%m%d).tar.gz -C /backup-source .
```
