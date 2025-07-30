class DomainDetailManager {
    constructor() {
        console.log('🚀 DomainDetailManager constructor called');
        this.domainId = DOMAIN_ID;
        console.log('🏠 Domain ID:', this.domainId);
        this.currentSessionId = null;
        this.checkInterval = null;
        this.initializeElements();
        this.bindEvents();
        console.log('✅ DomainDetailManager initialized successfully');
    }

    initializeElements() {
        this.checkAllBtn = document.getElementById('checkAllBtn');
        this.addSubdomainBtn = document.getElementById('addSubdomainBtn');
        this.importFile = document.getElementById('importFile');
        this.searchInput = document.getElementById('searchInput');
        this.statusFilter = document.getElementById('statusFilter');
        this.selectAll = document.getElementById('selectAll');
        
        this.addSubdomainModal = document.getElementById('addSubdomainModal');
        this.addSubdomainForm = document.getElementById('addSubdomainForm');
        
        this.editSubdomainModal = document.getElementById('editSubdomainModal');
        this.editSubdomainForm = document.getElementById('editSubdomainForm');
        
        this.progressSection = document.getElementById('progressSection');
        this.progressFill = document.getElementById('progressFill');
        this.progressText = document.getElementById('progressText');
        this.progressCount = document.getElementById('progressCount');
        
        this.toast = document.getElementById('toast');
        this.table = document.getElementById('subdomainsTable');
    }

    bindEvents() {
        // Main buttons
        console.log('🔗 Binding events for checkAllBtn:', this.checkAllBtn);
        this.checkAllBtn.addEventListener('click', () => {
            console.log('🖱️ checkAllBtn clicked!');
            this.checkAllSSL();
        });
        this.addSubdomainBtn.addEventListener('click', () => this.showAddSubdomainModal());
        this.importFile.addEventListener('change', (e) => this.handleImport(e));

        // Search and filter
        this.searchInput.addEventListener('input', () => this.filterTable());
        this.statusFilter.addEventListener('change', () => this.filterTable());
        this.selectAll.addEventListener('change', (e) => this.handleSelectAll(e));

        // Form events
        this.addSubdomainForm.addEventListener('submit', (e) => this.handleAddSubdomain(e));

        // Modal events
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => this.closeModals());
        });

        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModals();
            }
        });

        // SSL check buttons
        document.querySelectorAll('.ssl-check').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleSSLCheck(e));
        });

        // Delete subdomain buttons
        document.querySelectorAll('.delete-subdomain').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleDeleteSubdomain(e));
        });

        // Edit subdomain buttons
        document.querySelectorAll('.edit-subdomain').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleEditSubdomain(e));
        });

        // Send notification buttons
        document.querySelectorAll('.send-notification').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleSendNotification(e));
        });

        // Notification toggles
        document.querySelectorAll('.email-notification, .slack-notification').forEach(toggle => {
            toggle.addEventListener('change', (e) => this.handleNotificationToggle(e));
        });

        // Subdomain selection
        document.querySelectorAll('.subdomain-select').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateSelectAllState());
        });

        // Edit form submission
        if (this.editSubdomainForm) {
            this.editSubdomainForm.addEventListener('submit', (e) => this.handleEditSubdomainSubmit(e));
        }
    }

    showAddSubdomainModal() {
        this.addSubdomainModal.style.display = 'block';
        document.getElementById('subdomainDns').focus();
    }

    closeModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }

    async handleAddSubdomain(e) {
        e.preventDefault();

        const formData = {
            dns: document.getElementById('subdomainDns').value.trim(),
            source_dns: document.getElementById('subdomainSourceDns').value.trim(),
            proxied: document.getElementById('subdomainProxied').value,
            record_type: document.getElementById('subdomainRecordType').value,
            ip: document.getElementById('subdomainIp').value.trim(),
            nat: document.getElementById('subdomainNat').value.trim(),
            port: document.getElementById('subdomainPort').value,
            owner: document.getElementById('subdomainOwner').value.trim()
        };

        if (!formData.dns) {
            this.showToast('DNS address is required', 'error');
            return;
        }

        try {
            const response = await fetch(`/expire-tracking/domain/${this.domainId}/add-subdomain`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast('Subdomain added successfully', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                this.showToast(data.error || 'Error occurred while adding subdomain', 'error');
            }
        } catch (error) {
            console.error('Add subdomain error:', error);
            this.showToast('Error occurred while adding subdomain', 'error');
        }
    }

    async handleSSLCheck(e) {
        const btn = e.target.closest('.ssl-check');
        const subdomainId = btn.dataset.subdomainId;
        const useNat = btn.dataset.useNat === 'true';
        const originalText = btn.innerHTML;

        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';

        try {
            const response = await fetch(`/expire-tracking/subdomain/${subdomainId}/check-ssl`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ use_nat: useNat })
            });

            const data = await response.json();

            if (response.ok && data.status === 'success') {
                this.showToast('SSL check completed successfully', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                this.showToast(data.error || 'SSL check failed', 'error');
            }
        } catch (error) {
            console.error('SSL check error:', error);
            this.showToast('SSL check error occurred', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    async checkAllSSL() {
        console.log('🚀 checkAllSSL function called');
        const originalText = this.checkAllBtn.innerHTML;
        this.checkAllBtn.disabled = true;
        this.checkAllBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking All...';

        try {
            console.log(`📡 Making request to: /expire-tracking/domain/${this.domainId}/check-all-ssl`);
            const response = await fetch(`/expire-tracking/domain/${this.domainId}/check-all-ssl`, {
                method: 'POST'
            });

            const data = await response.json();
            console.log('📦 Response data:', data);

            if (response.ok) {
                this.currentSessionId = data.session_id;
                console.log(`🎯 Session ID received: ${this.currentSessionId}`);
                this.showProgressSection();
                this.startProgressMonitoring();
            } else {
                console.error('❌ Server error:', data);
                this.showToast(data.error || 'Bulk SSL check could not be started', 'error');
                this.resetCheckAllButton();
            }
        } catch (error) {
            console.error('💥 Check all SSL error:', error);
            this.showToast('Bulk SSL check error occurred', 'error');
            this.resetCheckAllButton();
        }
    }

    showProgressSection() {
        this.progressSection.style.display = 'block';
        this.progressFill.style.width = '0%';
        this.progressText.textContent = '0% completed';
        this.progressCount.textContent = '0 / 0';
        
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
                    this.progressSection.style.display = 'none';
                    this.showToast('All SSL checks completed - Page refreshing...', 'success');
                    // Shorter delay for page reload to ensure table updates
                    setTimeout(() => {
                        window.location.reload();
                    }, 500);
                    this.resetCheckAllButton();
                }
            } catch (error) {
                console.error('Progress monitoring error:', error);
                clearInterval(this.checkInterval);
                this.showToast('Progress monitoring error', 'error');
                this.resetCheckAllButton();
            }
        }, 1000); // Increased to 1000ms to reduce server load
    }

    updateProgress(data) {
        const progress = data.progress || 0;
        const results = data.results || [];
        const total = document.querySelectorAll('.subdomain-select').length;
        
        this.progressFill.style.width = `${progress}%`;
        this.progressText.textContent = `${progress}% completed`;
        this.progressCount.textContent = `${results.length} / ${total}`;
    }

    resetCheckAllButton() {
        this.checkAllBtn.disabled = false;
        this.checkAllBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Check All';
    }

    async handleImport(e) {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`/expire-tracking/domain/${this.domainId}/import-excel`, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast(`${data.imported_count} subdomains imported successfully`, 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                this.showToast(data.error || 'Import operation failed', 'error');
            }
        } catch (error) {
            console.error('Import error:', error);
            this.showToast('Import operation error occurred', 'error');
        }

        // Reset file input
        e.target.value = '';
    }

    async handleDeleteSubdomain(e) {
        const btn = e.target.closest('.delete-subdomain');
        const subdomainId = btn.dataset.subdomainId;
        const row = btn.closest('tr');
        const dns = row.querySelector('td:nth-child(2)').textContent;

        if (!confirm(`Are you sure you want to delete subdomain "${dns}"?`)) {
            return;
        }

        try {
            const response = await fetch(`/expire-tracking/subdomain/${subdomainId}/delete`, {
                method: 'DELETE'
            });

            if (response.ok) {
                row.style.transition = 'all 0.3s ease';
                row.style.opacity = '0';
                
                setTimeout(() => {
                    row.remove();
                    this.showToast('Subdomain deleted successfully', 'success');
                    this.updateSelectAllState();
                }, 300);
            } else {
                const data = await response.json();
                this.showToast(data.error || 'Error occurred while deleting subdomain', 'error');
            }
        } catch (error) {
            console.error('Delete subdomain error:', error);
            this.showToast('Error occurred while deleting subdomain', 'error');
        }
    }

    filterTable() {
        const searchTerm = this.searchInput.value.toLowerCase();
        const statusFilter = this.statusFilter.value;
        const rows = this.table.querySelectorAll('tbody tr');

        rows.forEach(row => {
            const dns = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
            const ip = row.querySelector('td:nth-child(6)').textContent.toLowerCase();
            const statusBadge = row.querySelector('.status-badge');
            const status = statusBadge ? statusBadge.textContent.trim() : '';

            const matchesSearch = dns.includes(searchTerm) || ip.includes(searchTerm);
            const matchesStatus = !statusFilter || status === statusFilter;

            row.style.display = matchesSearch && matchesStatus ? '' : 'none';
        });
    }

    handleSelectAll(e) {
        const checkboxes = document.querySelectorAll('.subdomain-select');
        checkboxes.forEach(checkbox => {
            checkbox.checked = e.target.checked;
        });
    }

    updateSelectAllState() {
        const checkboxes = document.querySelectorAll('.subdomain-select');
        const checkedBoxes = document.querySelectorAll('.subdomain-select:checked');
        
        this.selectAll.checked = checkboxes.length > 0 && checkboxes.length === checkedBoxes.length;
        this.selectAll.indeterminate = checkedBoxes.length > 0 && checkedBoxes.length < checkboxes.length;
    }

    showToast(message, type = 'info') {
        this.toast.textContent = message;
        this.toast.className = `toast ${type}`;
        this.toast.classList.add('show');
        
        setTimeout(() => {
            this.toast.classList.remove('show');
        }, 4000);
    }

    async handleEditSubdomain(e) {
        const subdomainId = e.target.closest('button').dataset.subdomainId;
        const row = e.target.closest('tr');
        
        // Get current values from table row
        const cells = row.querySelectorAll('td');
        const dns = cells[1].textContent.trim();
        const sourceDns = cells[2].textContent.trim();
        const proxied = cells[3].textContent.trim();
        const recordType = cells[4].textContent.trim();
        const ip = cells[5].textContent.trim();
        const nat = cells[6].textContent.trim();
        const port = cells[7].textContent.trim();
        const owner = cells[8].textContent.trim();
        
        // Populate edit form
        document.getElementById('editSubdomainId').value = subdomainId;
        document.getElementById('editSubdomainDns').value = dns;
        document.getElementById('editSubdomainSourceDns').value = sourceDns === '-' ? '' : sourceDns;
        document.getElementById('editSubdomainProxied').value = proxied === '-' ? '' : proxied;
        document.getElementById('editSubdomainRecordType').value = recordType === '-' ? 'A' : recordType;
        document.getElementById('editSubdomainIp').value = ip === '-' ? '' : ip;
        document.getElementById('editSubdomainNat').value = nat === '-' ? '' : nat;
        document.getElementById('editSubdomainPort').value = port;
        document.getElementById('editSubdomainOwner').value = owner === '-' ? '' : owner;
        
        // Show modal
        this.editSubdomainModal.style.display = 'block';
        document.getElementById('editSubdomainDns').focus();
    }

    async handleEditSubdomainSubmit(e) {
        e.preventDefault();
        
        const subdomainId = document.getElementById('editSubdomainId').value;
        
        const formData = {
            dns: document.getElementById('editSubdomainDns').value.trim(),
            source_dns: document.getElementById('editSubdomainSourceDns').value.trim(),
            proxied: document.getElementById('editSubdomainProxied').value,
            record_type: document.getElementById('editSubdomainRecordType').value,
            ip: document.getElementById('editSubdomainIp').value.trim(),
            nat: document.getElementById('editSubdomainNat').value.trim(),
            port: document.getElementById('editSubdomainPort').value,
            owner: document.getElementById('editSubdomainOwner').value.trim()
        };

        if (!formData.dns) {
            this.showToast('DNS address is required', 'error');
            return;
        }

        try {
            const response = await fetch(`/expire-tracking/subdomain/${subdomainId}/update`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            // Check if response is JSON
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                throw new Error('Server returned non-JSON response');
            }

            const result = await response.json();

            if (result.success) {
                this.showToast('Subdomain updated successfully', 'success');
                this.closeModals();
                setTimeout(() => window.location.reload(), 1000);
            } else {
                this.showToast(result.error || 'Update error', 'error');
            }
        } catch (error) {
            console.error('Edit subdomain error:', error);
            this.showToast('Connection error: ' + error.message, 'error');
        }
    }

    async handleNotificationToggle(e) {
        const subdomainId = e.target.dataset.subdomainId;
        const isEmail = e.target.classList.contains('email-notification');
        const isSlack = e.target.classList.contains('slack-notification');
        
        const data = {};
        if (isEmail) {
            data.email_notification = e.target.checked;
        }
        if (isSlack) {
            data.slack_notification = e.target.checked;
        }

        try {
            const response = await fetch(`/expire-tracking/subdomain/${subdomainId}/notification`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (!result.success) {
                e.target.checked = !e.target.checked; // Revert change
                this.showToast(result.error || 'Notification setting could not be updated', 'error');
            }
        } catch (error) {
            e.target.checked = !e.target.checked; // Revert change
            this.showToast('Connection error: ' + error.message, 'error');
        }
    }

    async handleSendNotification(e) {
        const subdomainId = e.target.closest('button').dataset.subdomainId;
        const button = e.target.closest('button');
        
        // Ask user which type of notification to send
        const notificationType = prompt('Notification type:\n1. email\n2. slack\n\nEnter your choice:', 'email');
        if (!notificationType || !['email', 'slack'].includes(notificationType.toLowerCase())) {
            this.showToast('Invalid notification type. Please enter "email" or "slack"', 'error');
            return;
        }
        
        // Disable button during request
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

        try {
            const response = await fetch(`/expire-tracking/subdomain/${subdomainId}/send-notification`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: notificationType.toLowerCase()
                })
            });

            // Check if response is ok
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                throw new Error(`Expected JSON response, got: ${text.substring(0, 100)}...`);
            }

            const result = await response.json();

            if (result.success) {
                this.showToast(result.message || 'Notification sent successfully!', 'success');
            } else {
                this.showToast(result.message || result.error || 'Notification could not be sent', 'error');
            }
        } catch (error) {
            console.error('Notification error:', error);
            this.showToast('Connection error: ' + error.message, 'error');
        } finally {
            // Re-enable button
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-bell"></i>';
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DomainDetailManager();
});
