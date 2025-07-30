class SSLChecker {
    constructor() {
        this.currentSessionId = null;
        this.checkInterval = null;
        this.initializeElements();
        this.bindEvents();
    }

    initializeElements() {
        this.domainList = document.getElementById('domainList');
        this.checkBtn = document.getElementById('checkBtn');
        this.clearBtn = document.getElementById('clearBtn');
        this.exportBtn = document.getElementById('exportBtn');
        this.newCheckBtn = document.getElementById('newCheckBtn');
        
        this.progressSection = document.getElementById('progressSection');
        this.progressFill = document.getElementById('progressFill');
        this.progressText = document.getElementById('progressText');
        this.progressCount = document.getElementById('progressCount');
        
        this.resultsSection = document.getElementById('resultsSection');
        this.resultsBody = document.getElementById('resultsBody');
        
        this.validCount = document.getElementById('validCount');
        this.warningCount = document.getElementById('warningCount');
        this.expiredCount = document.getElementById('expiredCount');
        this.errorCount = document.getElementById('errorCount');
        
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.toast = document.getElementById('toast');
    }

    bindEvents() {
        this.checkBtn.addEventListener('click', () => this.startSSLCheck());
        this.clearBtn.addEventListener('click', () => this.clearInput());
        this.exportBtn.addEventListener('click', () => this.exportToExcel());
        this.newCheckBtn.addEventListener('click', () => this.startNewCheck());
        
        // Enter key support for textarea
        this.domainList.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                this.startSSLCheck();
            }
        });
        
        // Auto-resize textarea
        this.domainList.addEventListener('input', () => {
            this.autoResizeTextarea();
        });
    }

    autoResizeTextarea() {
        this.domainList.style.height = 'auto';
        this.domainList.style.height = Math.max(120, this.domainList.scrollHeight) + 'px';
    }

    showToast(message, type = 'info') {
        this.toast.textContent = message;
        this.toast.className = `toast ${type}`;
        this.toast.classList.add('show');
        
        setTimeout(() => {
            this.toast.classList.remove('show');
        }, 4000);
    }

    validateDomains(text) {
        const domains = text.split('\n').filter(d => d.trim());
        
        if (domains.length === 0) {
            return { valid: false, error: 'Domain list cannot be empty' };
        }
        
        if (domains.length > 50) {
            return { valid: false, error: 'Maximum 50 domains can be checked' };
        }
        
        // Basic domain validation
        const invalidDomains = domains.filter(domain => {
            const cleanDomain = domain.split(':')[0];
            const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            return !domainRegex.test(cleanDomain);
        });
        
        if (invalidDomains.length > 0) {
            return { 
                valid: false, 
                error: `Geçersiz domain formatı: ${invalidDomains.slice(0, 3).join(', ')}${invalidDomains.length > 3 ? '...' : ''}` 
            };
        }
        
        return { valid: true };
    }

    async startSSLCheck() {
        const domainsText = this.domainList.value.trim();
        
        // Validation
        const validation = this.validateDomains(domainsText);
        if (!validation.valid) {
            this.showToast(validation.error, 'error');
            return;
        }
        
        try {
            this.checkBtn.disabled = true;
            this.checkBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
            
            // Start SSL check
            const response = await fetch('/check-bulk-ssl', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domains: domainsText })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            this.currentSessionId = data.session_id;
            this.showProgressSection();
            this.startProgressMonitoring();
            
        } catch (error) {
            console.error('SSL check error:', error);
            this.showToast(`Error: ${error.message}`, 'error');
            this.resetCheckButton();
        }
    }

    showProgressSection() {
        this.progressSection.style.display = 'block';
        this.resultsSection.style.display = 'none';
        this.progressFill.style.width = '0%';
        this.progressText.textContent = '0% completed';
        this.progressCount.textContent = '0 / 0';
        
        // Smooth scroll to progress section
        this.progressSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    startProgressMonitoring() {
        this.checkInterval = setInterval(async () => {
            try {
                const response = await fetch(`/progress/${this.currentSessionId}`);
                const data = await response.json();
                
                this.updateProgress(data);
                
                if (data.completed) {
                    clearInterval(this.checkInterval);
                    this.showResults(data.results);
                    this.resetCheckButton();
                }
            } catch (error) {
                console.error('Progress monitoring error:', error);
                clearInterval(this.checkInterval);
                this.showToast('Progress monitoring error', 'error');
                this.resetCheckButton();
            }
        }, 500);
    }

    updateProgress(data) {
        const progress = data.progress || 0;
        const results = data.results || [];
        const total = data.total || this.domainList.value.split('\n').filter(d => d.trim()).length;
        const processed = data.processed || results.length;
        
        this.progressFill.style.width = `${progress}%`;
        this.progressText.textContent = `${progress}% completed`;
        this.progressCount.textContent = `${processed} / ${total}`;
    }

    showResults(results) {
        this.progressSection.style.display = 'none';
        this.resultsSection.style.display = 'block';
        
        this.updateStatistics(results);
        this.renderResultsTable(results);
        
        this.showToast(`${results.length} domains successfully checked`, 'success');
        
        // Smooth scroll to results
        this.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    updateStatistics(results) {
        let valid = 0, warning = 0, expired = 0, error = 0;
        
        results.forEach(result => {
            if (result.status === 'error') {
                error++;
            } else {
                // Access nested ssl_info data or fallback to direct properties
                const sslInfo = result.ssl_info || {};
                const daysLeft = sslInfo.days_left || result.days_left;
                if (daysLeft < 0) {
                    expired++;
                } else if (daysLeft < 30) {
                    warning++;
                } else {
                    valid++;
                }
            }
        });
        
        this.animateCounter(this.validCount, valid);
        this.animateCounter(this.warningCount, warning);
        this.animateCounter(this.expiredCount, expired);
        this.animateCounter(this.errorCount, error);
    }

    animateCounter(element, targetValue) {
        const startValue = 0;
        const duration = 1000;
        const startTime = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const currentValue = Math.floor(startValue + (targetValue - startValue) * progress);
            element.textContent = currentValue;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    }

    renderResultsTable(results) {
        this.resultsBody.innerHTML = '';
        
        results.forEach((result, index) => {
            const row = document.createElement('tr');
            
            if (result.status === 'success') {
                // Access nested ssl_info data
                const sslInfo = result.ssl_info || {};
                const daysLeft = sslInfo.days_left || result.days_left;
                let statusClass, statusText, statusIcon;
                
                if (daysLeft < 0) {
                    statusClass = 'status-expired';
                    statusText = 'EXPIRED';
                    statusIcon = 'fas fa-times-circle';
                } else if (daysLeft < 30) {
                    statusClass = 'status-warning';
                    statusText = 'EXPIRING SOON';
                    statusIcon = 'fas fa-exclamation-triangle';
                } else {
                    statusClass = 'status-valid';
                    statusText = 'VALID';
                    statusIcon = 'fas fa-check-circle';
                }
                
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td><strong>${result.domain}</strong></td>
                    <td>${result.port}</td>
                    <td>${result.resolved_ip || result.ip || '-'}</td>
                    <td>${sslInfo.issuer || result.issuer || '-'}</td>
                    <td>${sslInfo.expire_date || result.expiry_date || '-'}</td>
                    <td>${daysLeft || '-'}</td>
                    <td><span class="status-badge ${statusClass}"><i class="${statusIcon}"></i> ${statusText}</span></td>
                `;
            } else {
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td><strong>${result.domain}</strong></td>
                    <td>${result.port}</td>
                    <td colspan="4">-</td>
                    <td><span class="status-badge status-error"><i class="fas fa-bug"></i> ERROR</span></td>
                `;
                row.title = result.message || result.error;
            }
            
            this.resultsBody.appendChild(row);
        });
    }

    resetCheckButton() {
        this.checkBtn.disabled = false;
        this.checkBtn.innerHTML = '<i class="fas fa-search"></i> Start SSL Check';
    }

    clearInput() {
        this.domainList.value = '';
        this.domainList.style.height = 'auto';
        this.domainList.focus();
    }

    startNewCheck() {
        this.resultsSection.style.display = 'none';
        this.progressSection.style.display = 'none';
        this.clearInput();
        
        // Smooth scroll to input section
        document.querySelector('.input-section').scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start' 
        });
    }

    async exportToExcel() {
        if (!this.currentSessionId) {
            this.showToast('No data available for export', 'error');
            return;
        }
        
        try {
            this.exportBtn.disabled = true;
            this.exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Preparing Excel...';
            
            const response = await fetch(`/export?session_id=${this.currentSessionId}`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ssl_report_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.xlsx`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            this.showToast('Excel file downloaded successfully', 'success');
            
        } catch (error) {
            console.error('Export error:', error);
            this.showToast(`Excel export error: ${error.message}`, 'error');
        } finally {
            this.exportBtn.disabled = false;
            this.exportBtn.innerHTML = '<i class="fas fa-file-excel"></i> Export to Excel';
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new SSLChecker();
    
    // Sample domains for testing
    const sampleButton = document.createElement('button');
    sampleButton.className = 'btn btn-secondary';
    sampleButton.innerHTML = '<i class="fas fa-magic"></i> Sample Domains';
    sampleButton.style.marginLeft = 'auto';
    
    sampleButton.addEventListener('click', () => {
        const sampleDomains = `google.com
github.com
stackoverflow.com
microsoft.com:443
example.com:8080`;
        document.getElementById('domainList').value = sampleDomains;
        document.getElementById('domainList').dispatchEvent(new Event('input'));
    });
    
    document.querySelector('.input-actions').appendChild(sampleButton);
});
