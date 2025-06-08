// Modern Theme System with Dark Mode Support

class ThemeManager {
  constructor() {
    this.themes = ['light', 'dark'];
    this.currentTheme = this.getStoredTheme() || this.getSystemTheme() || 'light';
    this.init();
  }

  init() {
    this.applyTheme(this.currentTheme);
    this.setupToggleButton();
    this.setupSystemThemeListener();
    this.setupAnimations();
  }

  getStoredTheme() {
    return localStorage.getItem('theme');
  }

  getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    this.currentTheme = theme;
    localStorage.setItem('theme', theme);
    this.updateToggleButton();
    this.dispatchThemeChange();
  }

  toggleTheme() {
    const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
    this.applyTheme(newTheme);
    this.animateThemeTransition();
  }

  setupToggleButton() {
    const toggleButton = document.getElementById('theme-toggle');
    if (toggleButton) {
      toggleButton.addEventListener('click', () => this.toggleTheme());
      this.updateToggleButton();
    }
  }

  updateToggleButton() {
    const toggleButton = document.getElementById('theme-toggle');
    if (toggleButton) {
      const icon = toggleButton.querySelector('i');
      if (icon) {
        icon.className = this.currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
      }
      toggleButton.setAttribute('aria-label', `Switch to ${this.currentTheme === 'dark' ? 'light' : 'dark'} theme`);
      toggleButton.setAttribute('title', `Switch to ${this.currentTheme === 'dark' ? 'light' : 'dark'} theme`);
    }
  }

  setupSystemThemeListener() {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!this.getStoredTheme()) {
        this.applyTheme(e.matches ? 'dark' : 'light');
      }
    });
  }

  animateThemeTransition() {
    document.body.style.transition = 'background-color 0.3s ease, color 0.3s ease';
    setTimeout(() => {
      document.body.style.transition = '';
    }, 300);
  }

  dispatchThemeChange() {
    window.dispatchEvent(new CustomEvent('themechange', {
      detail: { theme: this.currentTheme }
    }));
  }

  setupAnimations() {
    // Smooth scroll behavior
    document.documentElement.style.scrollBehavior = 'smooth';

    // Intersection Observer for fade-in animations
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('animate-fade-in');
        }
      });
    }, observerOptions);

    // Observe elements with animation classes
    document.querySelectorAll('.card, .hero, .step-wizard').forEach(el => {
      observer.observe(el);
    });
  }
}

// Utility Functions
class UIUtils {
  static showNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
      <div class="notification-content">
        <i class="fas ${this.getNotificationIcon(type)}"></i>
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
          <i class="fas fa-times"></i>
        </button>
      </div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after duration
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, duration);

    return notification;
  }

  static getNotificationIcon(type) {
    const icons = {
      success: 'fa-check-circle',
      error: 'fa-exclamation-circle',
      warning: 'fa-exclamation-triangle',
      info: 'fa-info-circle'
    };
    return icons[type] || icons.info;
  }

  static animateProgressBar(element, targetWidth, duration = 1000) {
    if (!element) return;

    const startWidth = parseFloat(element.style.width) || 0;
    const difference = targetWidth - startWidth;
    const startTime = performance.now();

    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function (ease-out)
      const easeOut = 1 - Math.pow(1 - progress, 3);
      const currentWidth = startWidth + (difference * easeOut);
      
      element.style.width = `${currentWidth}%`;
      element.setAttribute('aria-valuenow', currentWidth);
      element.textContent = `${Math.round(currentWidth)}%`;

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }

  static copyToClipboard(text) {
    if (navigator.clipboard) {
      return navigator.clipboard.writeText(text).then(() => {
        this.showNotification('Copied to clipboard!', 'success');
      }).catch(() => {
        this.fallbackCopyToClipboard(text);
      });
    } else {
      this.fallbackCopyToClipboard(text);
    }
  }

  static fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
      document.execCommand('copy');
      this.showNotification('Copied to clipboard!', 'success');
    } catch (err) {
      this.showNotification('Failed to copy to clipboard', 'error');
    }
    
    document.body.removeChild(textArea);
  }

  static formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  static formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  }

  static debounce(func, wait, immediate) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        timeout = null;
        if (!immediate) func.apply(this, args);
      };
      const callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func.apply(this, args);
    };
  }

  static throttle(func, limit) {
    let inThrottle;
    return function(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }
}

// Enhanced Navigation
class NavigationManager {
  constructor() {
    this.setupMobileMenu();
    this.setupSmoothScrolling();
    this.setupActiveNavigation();
  }

  setupMobileMenu() {
    const mobileToggle = document.querySelector('.mobile-menu-toggle');
    const mobileMenu = document.querySelector('.mobile-menu');

    if (mobileToggle && mobileMenu) {
      mobileToggle.addEventListener('click', () => {
        mobileMenu.classList.toggle('active');
        mobileToggle.classList.toggle('active');
      });

      // Close menu when clicking outside
      document.addEventListener('click', (e) => {
        if (!mobileMenu.contains(e.target) && !mobileToggle.contains(e.target)) {
          mobileMenu.classList.remove('active');
          mobileToggle.classList.remove('active');
        }
      });
    }
  }

  setupSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
          target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
          });
        }
      });
    });
  }

  setupActiveNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const currentPath = window.location.pathname;

    navLinks.forEach(link => {
      if (link.getAttribute('href') === currentPath) {
        link.classList.add('active');
      }
    });
  }
}

// Form Enhancements
class FormManager {
  constructor() {
    this.setupFormValidation();
    this.setupFormAnimations();
  }

  setupFormValidation() {
    const forms = document.querySelectorAll('form[data-validate]');
    
    forms.forEach(form => {
      form.addEventListener('submit', (e) => {
        if (!this.validateForm(form)) {
          e.preventDefault();
        }
      });

      // Real-time validation
      const inputs = form.querySelectorAll('input, select, textarea');
      inputs.forEach(input => {
        input.addEventListener('blur', () => this.validateField(input));
        input.addEventListener('input', UIUtils.debounce(() => this.validateField(input), 300));
      });
    });
  }

  validateForm(form) {
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;

    inputs.forEach(input => {
      if (!this.validateField(input)) {
        isValid = false;
      }
    });

    return isValid;
  }

  validateField(field) {
    const value = field.value.trim();
    const isRequired = field.hasAttribute('required');
    let isValid = true;
    let message = '';

    // Check if required field is empty
    if (isRequired && !value) {
      isValid = false;
      message = 'This field is required';
    }

    // Email validation
    if (field.type === 'email' && value) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(value)) {
        isValid = false;
        message = 'Please enter a valid email address';
      }
    }

    // Update field appearance
    this.updateFieldValidation(field, isValid, message);
    return isValid;
  }

  updateFieldValidation(field, isValid, message) {
    const wrapper = field.parentElement;
    let errorElement = wrapper.querySelector('.field-error');

    // Remove existing error
    if (errorElement) {
      errorElement.remove();
    }

    // Remove validation classes
    field.classList.remove('field-valid', 'field-invalid');

    if (!isValid && message) {
      // Add error styling and message
      field.classList.add('field-invalid');
      errorElement = document.createElement('div');
      errorElement.className = 'field-error';
      errorElement.textContent = message;
      wrapper.appendChild(errorElement);
    } else if (field.value.trim()) {
      // Add valid styling for non-empty fields
      field.classList.add('field-valid');
    }
  }

  setupFormAnimations() {
    // Floating label effect
    document.querySelectorAll('.form-group.floating-label').forEach(group => {
      const input = group.querySelector('input, textarea, select');
      const label = group.querySelector('label');

      if (input && label) {
        const updateLabel = () => {
          if (input.value || input === document.activeElement) {
            label.classList.add('floating');
          } else {
            label.classList.remove('floating');
          }
        };

        input.addEventListener('focus', updateLabel);
        input.addEventListener('blur', updateLabel);
        input.addEventListener('input', updateLabel);
        
        // Initial state
        updateLabel();
      }
    });
  }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  // Initialize core systems
  window.themeManager = new ThemeManager();
  window.uiUtils = UIUtils;
  window.navigationManager = new NavigationManager();
  window.formManager = new FormManager();

  // Add custom CSS for animations and notifications
  const style = document.createElement('style');
  style.textContent = `
    /* Animation Classes */
    .animate-fade-in {
      animation: fadeIn 0.6s ease-out forwards;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    /* Notifications */
    .notification {
      position: fixed;
      top: 20px;
      right: 20px;
      max-width: 400px;
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-lg);
      z-index: 9999;
      animation: slideInRight 0.3s ease-out;
    }

    .notification-content {
      padding: var(--space-lg);
      display: flex;
      align-items: center;
      gap: var(--space-md);
    }

    .notification-close {
      background: none;
      border: none;
      color: var(--text-secondary);
      cursor: pointer;
      margin-left: auto;
      padding: var(--space-xs);
      border-radius: var(--radius-sm);
      transition: all var(--transition-fast);
    }

    .notification-close:hover {
      background-color: var(--bg-hover);
      color: var(--text-primary);
    }

    .notification-success {
      border-left: 4px solid var(--success-color);
    }

    .notification-error {
      border-left: 4px solid var(--danger-color);
    }

    .notification-warning {
      border-left: 4px solid var(--warning-color);
    }

    .notification-info {
      border-left: 4px solid var(--info-color);
    }

    @keyframes slideInRight {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    /* Form Validation Styles */
    .field-invalid {
      border-color: var(--danger-color) !important;
      box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1) !important;
    }

    .field-valid {
      border-color: var(--success-color) !important;
      box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1) !important;
    }

    .field-error {
      color: var(--danger-color);
      font-size: 0.75rem;
      margin-top: var(--space-xs);
      display: flex;
      align-items: center;
      gap: var(--space-xs);
    }

    .field-error::before {
      content: '⚠';
    }

    /* Floating Labels */
    .floating-label {
      position: relative;
    }

    .floating-label label {
      position: absolute;
      left: var(--space-md);
      top: 50%;
      transform: translateY(-50%);
      background-color: var(--bg-primary);
      padding: 0 var(--space-xs);
      color: var(--text-secondary);
      transition: all var(--transition-fast);
      pointer-events: none;
    }

    .floating-label label.floating {
      top: 0;
      font-size: 0.75rem;
      color: var(--primary-color);
    }

    /* Mobile Menu */
    .mobile-menu-toggle {
      display: none;
      background: none;
      border: none;
      color: white;
      font-size: 1.5rem;
      cursor: pointer;
    }

    .mobile-menu {
      display: none;
    }

    @media (max-width: 768px) {
      .mobile-menu-toggle {
        display: block;
      }

      .navbar-nav {
        display: none;
      }

      .mobile-menu {
        display: block;
        position: absolute;
        top: 100%;
        left: 0;
        right: 0;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 0 0 var(--radius-lg) var(--radius-lg);
        box-shadow: var(--shadow-lg);
        opacity: 0;
        visibility: hidden;
        transform: translateY(-10px);
        transition: all var(--transition-base);
      }

      .mobile-menu.active {
        opacity: 1;
        visibility: visible;
        transform: translateY(0);
      }

      .mobile-menu .nav-link {
        display: block;
        padding: var(--space-md);
        color: var(--text-primary);
        border-bottom: 1px solid var(--border-color);
      }

      .mobile-menu .nav-link:hover {
        background-color: var(--bg-hover);
        color: var(--primary-color);
      }

      .notification {
        right: 10px;
        left: 10px;
        max-width: none;
      }
    }

    /* Loading States */
    .btn.loading {
      position: relative;
      color: transparent !important;
    }

    .btn.loading::after {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 16px;
      height: 16px;
      border: 2px solid transparent;
      border-top: 2px solid currentColor;
      border-radius: 50%;
      transform: translate(-50%, -50%);
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      to {
        transform: translate(-50%, -50%) rotate(360deg);
      }
    }
  `;
  document.head.appendChild(style);
});

// Export for use in other scripts
window.ThemeManager = ThemeManager;
window.UIUtils = UIUtils;
window.NavigationManager = NavigationManager;
window.FormManager = FormManager;