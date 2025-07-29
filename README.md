# Good SSL Checker

🔒 Modern web-based SSL certificate monitoring application with Docker deployment.

[![Version](https://img.shields.io/badge/Version-1.20-blue)](https://github.com/birolbenli/good-ssl-checker)
[![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen)](https://github.com/birolbenli/good-ssl-checker)
[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://github.com/birolbenli/good-ssl-checker)

## ✨ Features

- **Bulk SSL certificate checking** - Check multiple domains at once
- **Excel export** - Professional reporting
- **Email & Slack notifications** - Automated expiry alerts
- **Docker ready** - Easy deployment
- **Domain management** - Track multiple domains and subdomains
- **Fast performance** - Parallel SSL checking

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

## ⚙️ Configuration

Copy `config.example.json` to `config.json` and configure notifications:

### Email Notifications
Configure SMTP settings for automated SSL expiry alerts via email.

### Slack Notifications  
Get a webhook URL from Slack API (https://api.slack.com/apps) to receive alerts in your Slack channels.

> See `config.example.json` for detailed configuration options.

## 📋 Usage

### Domain Formats
```
domain.com              # Default port 443
domain.com:8000         # Custom port
subdomain.example.com   # Subdomains
192.168.1.100:443      # IP addresses
```

### Workflow
1. **Login** with admin credentials
2. **Bulk Check** - Add domains and check SSL certificates
3. **Track Expiry** - Monitor certificate expiration dates
4. **Get Notifications** - Receive alerts via email/Slack
5. **Export** - Download results as Excel

## 🐳 Production Docker

```yaml
services:
  ssl-checker:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ssl_data:/app/instance
      - ./config.json:/app/config.json
    restart: unless-stopped

volumes:
  ssl_data:
```

---

**Made by [Birol Benli](https://github.com/birolbenli)** | **Contact:** birolbenli@gmail.com
