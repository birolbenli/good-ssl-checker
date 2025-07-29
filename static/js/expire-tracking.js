class ExpireTrackingManager {
    constructor() {
        this.initializeElements();
        this.bindEvents();
    }

    initializeElements() {
        this.addDomainBtn = document.getElementById('addDomainBtn');
        this.addFirstDomainBtn = document.getElementById('addFirstDomainBtn');
        this.addDomainModal = document.getElementById('addDomainModal');
        this.addDomainForm = document.getElementById('addDomainForm');
        this.domainNameInput = document.getElementById('domainName');
        this.toast = document.getElementById('toast');
    }

    bindEvents() {
        // Add domain buttons
        if (this.addDomainBtn) {
            this.addDomainBtn.addEventListener('click', () => this.showAddDomainModal());
        }
        if (this.addFirstDomainBtn) {
            this.addFirstDomainBtn.addEventListener('click', () => this.showAddDomainModal());
        }

        // Modal events
        this.addDomainForm.addEventListener('submit', (e) => this.handleAddDomain(e));
        
        // Modal close events
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => this.closeModals());
        });

        // Close modal on outside click
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModals();
            }
        });

        // Delete domain events
        document.querySelectorAll('.delete-domain').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleDeleteDomain(e));
        });
    }

    showAddDomainModal() {
        this.addDomainModal.style.display = 'block';
        this.domainNameInput.focus();
    }

    closeModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }

    async handleAddDomain(e) {
        e.preventDefault();
        
        const domainName = this.domainNameInput.value.trim();
        
        if (!domainName) {
            this.showToast('Domain name is required', 'error');
            return;
        }

        try {
            const response = await fetch('/expire-tracking/add-domain', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ name: domainName })
            });

            const data = await response.json();

            if (response.ok) {
                this.showToast('Domain added successfully', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                this.showToast(data.error || 'Error occurred while adding domain', 'error');
            }
        } catch (error) {
            console.error('Add domain error:', error);
            this.showToast('Error occurred while adding domain', 'error');
        }
    }

    async handleDeleteDomain(e) {
        const domainId = e.target.closest('.delete-domain').dataset.domainId;
        const domainCard = e.target.closest('.domain-card');
        const domainName = domainCard.querySelector('h3').textContent;

        if (!confirm(`Are you sure you want to delete the domain "${domainName}" and all its subdomains?`)) {
            return;
        }

        try {
            const response = await fetch(`/expire-tracking/domain/${domainId}/delete`, {
                method: 'DELETE'
            });

            if (response.ok) {
                domainCard.style.transition = 'all 0.3s ease';
                domainCard.style.opacity = '0';
                domainCard.style.transform = 'scale(0.9)';
                
                setTimeout(() => {
                    domainCard.remove();
                    this.showToast('Domain deleted successfully', 'success');
                    
                    // Check if no domains left
                    if (document.querySelectorAll('.domain-card').length === 0) {
                        setTimeout(() => window.location.reload(), 1000);
                    }
                }, 300);
            } else {
                const data = await response.json();
                this.showToast(data.error || 'Error occurred while deleting domain', 'error');
            }
        } catch (error) {
            console.error('Delete domain error:', error);
            this.showToast('Error occurred while deleting domain', 'error');
        }
    }

    showToast(message, type = 'info') {
        this.toast.textContent = message;
        this.toast.className = `toast ${type}`;
        this.toast.classList.add('show');
        
        setTimeout(() => {
            this.toast.classList.remove('show');
        }, 4000);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ExpireTrackingManager();
});
