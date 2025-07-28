/**
 * Real-time Password Strength Assessment
 * Provides immediate feedback on password strength as user types
 */

class PasswordStrengthChecker {
    constructor(passwordInputId, strengthDisplayId) {
        this.passwordInput = document.getElementById(passwordInputId);
        this.strengthDisplay = document.getElementById(strengthDisplayId);
        this.init();
    }

    init() {
        if (this.passwordInput && this.strengthDisplay) {
            this.passwordInput.addEventListener('input', (e) => {
                this.checkPasswordStrength(e.target.value);
            });
        }
    }

    async checkPasswordStrength(password) {
        if (!password || password.length === 0) {
            this.clearStrengthDisplay();
            return;
        }

        try {
            const response = await fetch('/check-password-strength/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ password: password })
            });

            const data = await response.json();
            this.displayStrengthResult(data);
        } catch (error) {
            console.error('Error checking password strength:', error);
        }
    }

    displayStrengthResult(data) {
        const { is_valid, errors, strength_score, strength_label, max_score } = data;

        // Calculate percentage
        const percentage = (strength_score / max_score) * 100;

        // Determine color based on strength
        let colorClass = 'strength-weak';
        if (percentage >= 80) colorClass = 'strength-very-strong';
        else if (percentage >= 60) colorClass = 'strength-strong';
        else if (percentage >= 40) colorClass = 'strength-medium';

        // Update strength display
        this.strengthDisplay.innerHTML = `
            <div class="password-strength-container">
                <div class="strength-bar-container">
                    <div class="strength-bar ${colorClass}" style="width: ${percentage}%"></div>
                </div>
                <div class="strength-info">
                    <span class="strength-label ${colorClass}">${strength_label}</span>
                    <span class="strength-score">${strength_score}/${max_score}</span>
                </div>
                ${errors.length > 0 ? this.renderErrors(errors) : ''}
                ${is_valid ? '<div class="strength-valid">✓ Password meets requirements</div>' : ''}
            </div>
        `;
    }

    renderErrors(errors) {
        return `
            <div class="strength-errors">
                <ul>
                    ${errors.map(error => `<li>${error}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    clearStrengthDisplay() {
        if (this.strengthDisplay) {
            this.strengthDisplay.innerHTML = '';
        }
    }

    getCSRFToken() {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                return value;
            }
        }
        return '';
    }
}

// Password Reuse Checker
class PasswordReuseChecker {
    constructor(passwordInputId, reuseDisplayId) {
        this.passwordInput = document.getElementById(passwordInputId);
        this.reuseDisplay = document.getElementById(reuseDisplayId);
        this.debounceTimer = null;
        this.init();
    }

    init() {
        if (this.passwordInput && this.reuseDisplay) {
            this.passwordInput.addEventListener('input', (e) => {
                clearTimeout(this.debounceTimer);
                this.debounceTimer = setTimeout(() => {
                    this.checkPasswordReuse(e.target.value);
                }, 1000); // Check after 1 second of no typing
            });
        }
    }

    async checkPasswordReuse(password) {
        if (!password || password.length < 8) {
            this.clearReuseDisplay();
            return;
        }

        try {
            const response = await fetch('/check-password-reuse/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ password: password })
            });

            const data = await response.json();
            this.displayReuseResult(data);
        } catch (error) {
            console.error('Error checking password reuse:', error);
        }
    }

    displayReuseResult(data) {
        const { can_use, message } = data;

        if (!can_use) {
            this.reuseDisplay.innerHTML = `
                <div class="password-reuse-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    ${message}
                </div>
            `;
        } else {
            this.clearReuseDisplay();
        }
    }

    clearReuseDisplay() {
        if (this.reuseDisplay) {
            this.reuseDisplay.innerHTML = '';
        }
    }

    getCSRFToken() {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                return value;
            }
        }
        return '';
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    // Initialize for signup form
    if (document.getElementById('signup-password')) {
        new PasswordStrengthChecker('signup-password', 'password-strength-display');
    }

    // Initialize for password change form
    if (document.getElementById('new-password')) {
        new PasswordStrengthChecker('new-password', 'password-strength-display');
        new PasswordReuseChecker('new-password', 'password-reuse-display');
    }

    // Initialize for password reset form
    if (document.getElementById('reset-password')) {
        new PasswordStrengthChecker('reset-password', 'password-strength-display');
    }
});

// Export for use in other scripts
window.PasswordStrengthChecker = PasswordStrengthChecker;
window.PasswordReuseChecker = PasswordReuseChecker;
