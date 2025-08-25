# Good SSL Checker

🔒 Modern web-based SSL certificate monitoring application with Docker deployment.

[![Version](https://img.shields.io/badge/Version-1.20-blue)](https://github.com/birolbenli/good-ssl-checker)
[![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen)](https://github.com/birolbenli/good-ssl-checker)
[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://github.com/birolbenli/good-ssl-checker)

## ✨ Features

- **Bulk SSL Certificate Checking** - Check multiple domains simultaneously with parallel processing
- **Domain Management** - Organize domains and subdomains with proxy configuration support
- **SSL Expiry Tracking** - Monitor certificate expiration dates with visual status indicators
- **Smart SSL Logic** - Automatically handles proxied vs direct IP connections
- **Excel Import/Export** - Professional reporting and batch domain management
- **Email & Slack Notifications** - Automated expiry alerts with customizable thresholds
- **Docker Ready** - Easy deployment with docker-compose
- **Modern UI** - Clean, responsive web interface
- **Real-time Progress** - Live updates during bulk SSL checks

## 🚀 Quick Start

### Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/birolbenli/good-ssl-checker.git
cd good-ssl-checker

# Start with Docker Compose
docker compose up --build -d
```

The application will be available at `http://localhost:5000`.

**Default Login:**
- Username: `admin`
- Password: `ssl123`

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python app.py
```

## 📋 How It Works

### SSL Check Logic
The application intelligently determines how to check SSL certificates based on domain configuration:

1. **Proxied Domains (Cloudflare, etc.)** → Uses DNS resolution to get real IP
2. **Direct IP Domains** → Uses stored IP address for direct connection  
3. **NAT/Internal Domains** → Uses NAT IP for internal network checking
4. **Custom Ports** → Supports any port (443, 8443, 8000, etc.)

### Domain Formats
```
domain.com              # Default port 443, proxied check
domain.com:8000         # Custom port 8000
subdomain.example.com   # Subdomains supported
192.168.1.100:443      # Direct IP addresses
```

## ⚙️ Configuration

Copy `config.example.json` to `config.json` and configure notifications:

### Email Notifications
Configure SMTP settings for automated SSL expiry alerts:
```json
{
  "notifications": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "username": "your-email@gmail.com",
      "password": "your-app-password"
    }
  }
}
```

### Slack Notifications  
Get a webhook URL from Slack API to receive alerts:
```json
{
  "notifications": {
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/YOUR_WEBHOOK",
      "channel": "#ssl-alerts"
    }
  }
}
```

## 🎯 Usage Workflow

1. **Login** with admin credentials
2. **Bulk Check** - Add domains and check SSL certificates in parallel
3. **Domain Management** - Organize domains and configure proxy settings
4. **Track Expiry** - Monitor certificate expiration with automated alerts
5. **Export Results** - Download comprehensive reports as Excel
6. **Import Domains** - Batch import domains from Excel files

## 📊 Features in Detail

### Bulk SSL Checker
- Parallel processing for fast results
- Support for multiple domain formats
- Real-time progress tracking
- Detailed SSL certificate information

### Expiry Tracking
- Domain and subdomain organization
- Visual status indicators (Valid/Warning/Expired)
- Individual and bulk SSL checks
- Email and Slack notifications
- Excel import/export functionality

### Smart Proxy Detection
- Automatic handling of Cloudflare proxied domains
- Direct IP connection for non-proxied domains
- NAT/Internal network support
- Custom port configuration

## 🐳 Production Deployment

```yaml
version: '3.8'
services:
  ssl-checker:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ssl_data:/app/instance
      - ./config.json:/app/config.json
    restart: unless-stopped
    environment:
      - FLASK_ENV=production

volumes:
  ssl_data:
```

## 🔧 Environment Variables

- `FLASK_ENV`: Set to `production` for production deployment
- `FLASK_DEBUG`: Set to `False` for production

## 📝 License

This project is licensed under the MIT License.

---

**Made by [Birol Benli](https://github.com/birolbenli)** | **Contact:** birolbenli@gmail.com
