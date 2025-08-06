// Client-side cryptographic utilities for Secure Messaging System

class CryptoUI {
    constructor() {
        this.init();
    }

    init() {
        // Initialize UI enhancements
        this.setupFormValidation();
        this.setupLoadingStates();
        this.setupSecurityIndicators();
    }

    setupFormValidation() {
        // Enhanced form validation for crypto forms
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                if (form.classList.contains('needs-validation') && !form.checkValidity()) {
                    e.preventDefault();
                    e.stopPropagation();
                }
                
                form.classList.add('was-validated');
                
                // Add loading state to submit button
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    this.setLoadingState(submitBtn, true);
                }
            });
        });
    }

    setupLoadingStates() {
        // Add loading states to buttons
        const buttons = document.querySelectorAll('button[type="submit"], .btn-primary');
        
        buttons.forEach(button => {
            button.addEventListener('click', () => {
                setTimeout(() => {
                    this.setLoadingState(button, true);
                }, 100);
            });
        });
    }

    setLoadingState(button, isLoading) {
        if (isLoading) {
            button.classList.add('btn-loading');
            button.disabled = true;
            
            // Store original text
            if (!button.dataset.originalText) {
                button.dataset.originalText = button.innerHTML;
            }
            
            button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Processing...';
        } else {
            button.classList.remove('btn-loading');
            button.disabled = false;
            
            if (button.dataset.originalText) {
                button.innerHTML = button.dataset.originalText;
            }
        }
    }

    setupSecurityIndicators() {
        // Add visual indicators for security features
        this.addEncryptionBadges();
        this.addVerificationIndicators();
    }

    addEncryptionBadges() {
        // Add encryption badges to message elements
        const messageItems = document.querySelectorAll('.message-item');
        
        messageItems.forEach(item => {
            if (!item.querySelector('.encryption-badge')) {
                const badge = document.createElement('span');
                badge.className = 'encryption-badge ms-2';
                badge.innerHTML = '<i class="fas fa-lock me-1"></i>E2E';
                badge.title = 'End-to-end encrypted';
                
                const header = item.querySelector('h6, .fw-bold');
                if (header) {
                    header.appendChild(badge);
                }
            }
        });
    }

    addVerificationIndicators() {
        // Add verification status indicators
        const userElements = document.querySelectorAll('[data-verified]');
        
        userElements.forEach(element => {
            const isVerified = element.dataset.verified === 'true';
            const indicator = document.createElement('i');
            
            if (isVerified) {
                indicator.className = 'fas fa-check-circle text-success ms-1';
                indicator.title = 'Verified user';
            } else {
                indicator.className = 'fas fa-exclamation-triangle text-warning ms-1';
                indicator.title = 'Unverified user';
            }
            
            element.appendChild(indicator);
        });
    }

    // Utility functions for crypto operations
    generateSecureRandom(length = 32) {
        // Generate secure random string for client-side use
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    async hashPassword(password, salt) {
        // Client-side password hashing (for additional security layer)
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    validateInput(input, type) {
        // Input validation helpers
        switch (type) {
            case 'email':
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
            case 'username':
                return /^[a-zA-Z0-9_-]{3,20}$/.test(input);
            case 'password':
                return input.length >= 8;
            case 'otp':
                return /^\d{6}$/.test(input);
            default:
                return true;
        }
    }

    // Animation utilities
    animateSuccess(element) {
        element.classList.add('animate__animated', 'animate__pulse');
        setTimeout(() => {
            element.classList.remove('animate__animated', 'animate__pulse');
        }, 1000);
    }

    animateError(element) {
        element.classList.add('animate__animated', 'animate__shakeX');
        setTimeout(() => {
            element.classList.remove('animate__animated', 'animate__shakeX');
        }, 1000);
    }
}

// Initialize crypto UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.cryptoUI = new CryptoUI();
    
    // Add copy functionality to keys/tokens if needed
    const copyableElements = document.querySelectorAll('[data-copyable]');
    copyableElements.forEach(element => {
        element.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(element.textContent);
                
                // Visual feedback
                const originalText = element.innerHTML;
                element.innerHTML = '<i class="fas fa-check text-success"></i> Copied!';
                
                setTimeout(() => {
                    element.innerHTML = originalText;
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        });
    });
    
    // Auto-refresh functionality for messages
    if (window.location.pathname.includes('/messages') || window.location.pathname.includes('/dashboard')) {
        setInterval(() => {
            // Could implement WebSocket or polling here
            console.log('Auto-refresh check...');
        }, 30000);
    }
});

// Export for use in other scripts if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoUI;
}
