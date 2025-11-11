class RacoreApp {
    constructor() {
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.updateStats();
        this.initNavigation();
        this.initPasswordGenerator();
    }
    
    bindEvents() {
        const costSlider = document.getElementById('cost');
        const costValue = document.getElementById('cost-value');
        
        if (costSlider && costValue) {
            costSlider.addEventListener('input', (e) => {
                costValue.textContent = e.target.value;
                this.updateSecurityLevel();
            });
        }
        
        const keyLengthSlider = document.getElementById('key_length');
        const keyLengthValue = document.getElementById('key-length-value');
        
        if (keyLengthSlider && keyLengthValue) {
            keyLengthSlider.addEventListener('input', (e) => {
                keyLengthValue.textContent = e.target.value;
            });
        }

        const passwordLengthSlider = document.getElementById('password_length');
        const passwordLengthValue = document.getElementById('password-length-value');
        
        if (passwordLengthSlider && passwordLengthValue) {
            passwordLengthSlider.addEventListener('input', (e) => {
                passwordLengthValue.textContent = e.target.value;
            });
        }
        
        const algorithmSelect = document.getElementById('algorithm');
        if (algorithmSelect) {
            algorithmSelect.addEventListener('change', () => {
                this.updateSecurityLevel();
            });
        }
        
        const forms = document.querySelectorAll('.racore-form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                this.handleFormSubmit(e);
            });
        });
        
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.updatePasswordStrength(e.target.value);
            });
        }
        
        setInterval(() => {
            this.updateStats();
        }, 2000);
    }
    
    initNavigation() {
        window.addEventListener('scroll', () => {
            this.toggleNavigationButtons();
        });
        
        this.toggleNavigationButtons();
    }
    
    initPasswordGenerator() {
        const passwordForm = document.getElementById('passwordgen-form');
        if (passwordForm) {
            const inputs = passwordForm.querySelectorAll('input[type="checkbox"], input[type="range"]');
            inputs.forEach(input => {
                input.addEventListener('change', () => {
                    setTimeout(() => this.generatePasswordPreview(), 100);
                });
            });
        }
    }
    
    toggleNavigationButtons() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const scrollHeight = document.documentElement.scrollHeight;
        const clientHeight = document.documentElement.clientHeight;
        
        const upButton = document.querySelector('.racore-nav-up');
        const downButton = document.querySelector('.racore-nav-down');
        
        if (upButton) {
            upButton.style.display = scrollTop > 100 ? 'flex' : 'none';
        }
        
        if (downButton) {
            downButton.style.display = scrollTop < (scrollHeight - clientHeight - 100) ? 'flex' : 'none';
        }
    }
    
    updatePasswordStrength(password) {
        const strengthContainer = document.getElementById('password-strength');
        if (!strengthContainer) return;
        
        let strength = 0;
        let text = 'Şifrə gücü';
        
        if (password.length > 0) {
            if (password.length >= 8) strength += 1;
            if (/[A-Z]/.test(password)) strength += 1;
            if (/[a-z]/.test(password)) strength += 1;
            if (/[0-9]/.test(password)) strength += 1;
            if (/[^A-Za-z0-9]/.test(password)) strength += 1;
        }
        
        let strengthLevel = 'weak';
        if (password.length === 0) {
            text = 'Şifrə daxil edin';
        } else if (strength <= 2) {
            text = 'Zəif';
            strengthLevel = 'weak';
        } else if (strength <= 4) {
            text = 'Orta';
            strengthLevel = 'medium';
        } else {
            text = 'Güclü';
            strengthLevel = 'strong';
        }
        
        strengthContainer.setAttribute('data-strength', strengthLevel);
        strengthContainer.querySelector('.racore-strength-text').textContent = text;
    }
    
    updateSecurityLevel() {
        const algorithm = document.getElementById('algorithm')?.value || 'bcrypt';
        const cost = parseInt(document.getElementById('cost')?.value || '12');
        const securityLevel = document.getElementById('security-level');
        
        if (!securityLevel) return;
        
        let level = 'Orta';
        let color = '#f59e0b';
        
        if (algorithm.includes('argon2')) {
            level = 'Çox Yüksək';
            color = '#10b981';
        } else if (algorithm === 'bcrypt' && cost >= 12) {
            level = 'Yüksək';
            color = '#10b981';
        } else if (algorithm === 'bcrypt' && cost >= 8) {
            level = 'Yaxşı';
            color = '#84cc16';
        } else if (algorithm.includes('sha3')) {
            level = 'Yüksək';
            color = '#10b981';
        } else if (algorithm.includes('sha')) {
            level = 'Orta';
            color = '#f59e0b';
        } else if (algorithm === 'whirlpool') {
            level = 'Yaxşı';
            color = '#84cc16';
        }
        
        securityLevel.textContent = level;
        securityLevel.style.color = color;
    }
    
    updateStats() {
        const processingTime = document.getElementById('processing-time');
        if (processingTime) {
            const time = Math.floor(Math.random() * 30) + 5;
            processingTime.textContent = `${time}ms`;
        }
        
        this.updateSecurityLevel();
    }
    
    handleFormSubmit(e) {
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        
        if (submitBtn) {
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Emal edilir...';
            submitBtn.disabled = true;
            
            setTimeout(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }, 3000);
        }
    }
    
    generatePasswordPreview() {
        const length = parseInt(document.getElementById('password_length')?.value || '16');
        const includeUppercase = document.querySelector('input[name="include_uppercase"]')?.checked;
        const includeLowercase = document.querySelector('input[name="include_lowercase"]')?.checked;
        const includeNumbers = document.querySelector('input[name="include_numbers"]')?.checked;
        const includeSymbols = document.querySelector('input[name="include_symbols"]')?.checked;
        const excludeSimilar = document.querySelector('input[name="exclude_similar"]')?.checked;
        
        let characters = '';
        if (includeUppercase) characters += excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (includeLowercase) characters += excludeSimilar ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        if (includeNumbers) characters += excludeSimilar ? '23456789' : '0123456789';
        if (includeSymbols) characters += '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        if (characters.length === 0) {
            this.showNotification('Ən azı bir simvol növü seçilməlidir', 'error');
            return;
        }
        
        let password = '';
        for (let i = 0; i < length; i++) {
            password += characters.charAt(Math.floor(Math.random() * characters.length));
        }
        
        const previewElement = document.getElementById('preview-password');
        const previewContainer = document.getElementById('password-preview');
        
        if (previewElement && previewContainer) {
            previewElement.textContent = password;
            previewContainer.style.display = 'block';
        }
    }
    
    showNotification(message, type = 'success') {
        const notification = document.createElement('div');
        notification.className = `racore-notification racore-notification-${type}`;
        notification.innerHTML = `
            <div class="racore-notification-content">
                <i class="fas fa-${type === 'success' ? 'check' : 'exclamation'}-circle"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'racoreSlideOut 0.3s ease-in';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

const style = document.createElement('style');
style.textContent = `
    @keyframes racoreSlideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes racoreSlideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .racore-notification-success {
        border-left-color: #10b981 !important;
    }
    
    .racore-notification-error {
        border-left-color: #ef4444 !important;
    }
    
    .racore-notification-content {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-weight: 500;
    }
    
    .racore-notification-content i {
        font-size: 1.25rem;
    }
`;

document.head.appendChild(style);

function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function scrollToBottom() {
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
}

function generatePasswordPreview() {
    const app = new RacoreApp();
    app.generatePasswordPreview();
}

function racoreCopyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        const text = element.textContent;
        navigator.clipboard.writeText(text).then(() => {
            const app = new RacoreApp();
            app.showNotification('Mətn uğurla kopyalandı!');
        }).catch(err => {
            const app = new RacoreApp();
            app.showNotification('Kopyalama uğursuz oldu', 'error');
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new RacoreApp();
});