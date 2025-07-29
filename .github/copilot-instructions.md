<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# SSL Checker Application Instructions

This is a Docker-based SSL certificate checker web application with the following features:

## Project Structure
- Python Flask backend for SSL certificate validation
- Modern HTML/CSS/JavaScript frontend
- Docker containerization for Ubuntu deployment
- Excel export functionality
- Bulk SSL certificate checking

## Key Features
- Bulk SSL certificate checking with domain list input
- Port specification support (default :443, custom ports like :8000, :8383)
- Certificate information extraction (issuer, expiration, days left)
- Modern web interface similar to SSLLookup.com
- Excel export functionality
- Responsive table display

## Technology Stack
- Backend: Python Flask
- Frontend: HTML5, CSS3, JavaScript
- SSL Checking: OpenSSL/Python ssl library
- Export: openpyxl for Excel generation
- Containerization: Docker on Ubuntu

## Code Quality Guidelines
- Use modern Python practices (type hints, async where appropriate)
- Implement proper error handling for SSL connections
- Use responsive CSS design
- Follow security best practices for web applications
- Include proper logging and monitoring
