# Good SSL Checker v1.30

🔒 Modern web-based SSL certificate monitoring application with comprehensive settings management and Docker deployment.

[![Version](https://img.shields.io/badge/Version-1.30-blue)](https://github.com/birolbenli/good-ssl-checker)
[![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen)](https://github.com/birolbenli/good-ssl-checker)
[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://github.com/birolbenli/good-ssl-checker)

## 🆕 What's New in v1.30

- **Web-Based Settings Management**: Complete settings interface - no more config file editing!
- **Per-Subdomain Custom Settings**: Override email and Slack settings for individual subdomains
- **Enhanced Settings Page**: SMTP configuration, notification preferences, and testing tools
- **Improved UI**: Better action button layout and responsive design
- **Database-Driven Configuration**: All settings stored in SQLite database

## ✨ Features

### SSL Certificate Management
- **Bulk SSL Checking** - Check multiple domains simultaneously with parallel processing
- **Smart Proxy Detection** - Automatically handles Cloudflare proxied vs direct IP connections
- **NAT Support** - Special handling for internal/NAT IP addresses
- **Real-time Monitoring** - Track certificate expiry dates and renewal status
- **Parallel Processing** - Fast concurrent SSL checks with progress tracking

### Web-Based Configuration
- **Settings Dashboard** - Manage all configuration through web interface
- **SMTP Configuration** - Set up email notifications with test functionality
- **Slack Integration** - Configure Slack webhooks with test messaging
- **Notification Rules** - Set expiry thresholds and notification schedules
- **Per-Subdomain Overrides** - Custom email/Slack settings for specific subdomains

### Domain & Subdomain Management
- **Domain Organization** - Group subdomains under parent domains
- **Excel Import/Export** - Bulk import subdomain data and export reports
- **SSL Status Tracking** - Visual indicators for certificate status
- **Notification Toggles** - Individual email/Slack notification controls
- **Search & Filter** - Find and filter subdomains by various criteria

### Advanced SSL Logic
- **Proxied Domains** - Uses DNS resolution for real-time IP lookup
- **Direct IP Domains** - Uses stored IP addresses for direct connections
- **NAT Domains** - Special handling for internal network addresses
- **Port Configuration** - Support for custom SSL ports
- **Certificate Details** - Full certificate information display

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

### First Time Setup

1. **Access Settings**: Navigate to Settings page from the main menu
2. **Configure SMTP**: Set up your email server settings for notifications
3. **Set Default Email**: Configure default recipient email address
4. **Configure Slack** (Optional): Set up Slack webhook for notifications
5. **Save Settings**: Click "Save All Settings" to apply configuration

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

All configuration is now managed through the web interface in the Settings page:

### SMTP Settings
- **Server**: Your SMTP server hostname
- **Port**: SMTP port (usually 587 for TLS)
- **Username**: SMTP authentication username
- **Password**: SMTP authentication password (use app passwords for Gmail)
- **From Email**: Sender email address
- **Use TLS**: Enable TLS encryption

### Notification Settings
- **Enable Notifications**: Master switch for all notifications
- **Email Notifications**: Enable/disable email notifications
- **Slack Notifications**: Enable/disable Slack notifications
- **Daily Check Time**: Time for automated checks (HH:MM format)
- **Expiry Thresholds**: Days before expiry to send alerts (comma-separated)

### Default Recipients
- **Default Email**: Fallback email address for notifications
- **Default Slack Webhook**: Fallback Slack webhook URL

### Per-Subdomain Customization
1. In domain detail view, click the "Settings" button for any subdomain
2. Override default email or Slack webhook for that specific subdomain
3. SMTP settings are always inherited from global configuration

## 🎯 Usage Workflow

1. **Login** with admin credentials
2. **Configure Settings** - Set up SMTP, email, and Slack notifications
3. **Bulk Check** - Add domains and check SSL certificates in parallel
4. **Domain Management** - Organize domains and configure proxy settings
5. **Track Expiry** - Monitor certificate expiration with automated alerts
6. **Export Results** - Download comprehensive reports as Excel
7. **Import Domains** - Batch import domains from Excel files

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

### Settings Management
- Complete web-based configuration
- Test email and Slack functionality
- Per-subdomain notification overrides
- Database-driven settings storage

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
    restart: unless-stopped
    environment:
      - FLASK_ENV=production
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  ssl_data:
```

## 🔐 Security Notes

- Change default login credentials in production
- Use app passwords for Gmail/email providers
- Store sensitive settings in environment variables if needed
- Enable HTTPS in production deployments
- Regularly backup the SQLite database

## 🛠️ Troubleshooting

### Email Notifications Not Working
1. Check SMTP settings in Settings page
2. Test email configuration using the "Test Email" button
3. Verify firewall/network access to SMTP ports
4. For Gmail: Use app passwords, not regular passwords

### Slack Notifications Not Working
1. Verify webhook URL in Settings page
2. Test Slack configuration using the "Test Slack" button
3. Check Slack app permissions and webhook configuration

### SSL Check Failures
1. Verify domain/IP configuration
2. Check proxy settings (Yes/No/NAT)
3. Ensure ports are accessible
4. Review SSL check logs in browser console

### Database Issues
1. Check instance/ directory permissions
2. Verify SQLite database file creation
3. Review application logs for database errors

## 🔧 Environment Variables

- `FLASK_ENV`: Set to `production` for production deployment
- `FLASK_DEBUG`: Set to `False` for production

## 📁 Database Structure

The application uses SQLite with these main tables:
- **domain**: Parent domain information
- **subdomain**: SSL certificate and monitoring data
- **settings**: Application configuration (NEW in v1.30)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

---

**Made by [Birol Benli](https://github.com/birolbenli)** | **Contact:** birolbenli@gmail.com

**Good SSL Checker v1.30** - Making SSL certificate management simple and reliable!
