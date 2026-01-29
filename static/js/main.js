// PhishGuard AI - Web JavaScript

// Add any interactive features here
document.addEventListener('DOMContentLoaded', function() {
    console.log('PhishGuard AI loaded!');
    
    // Auto-resize textarea
    const textarea = document.querySelector('textarea');
    if (textarea) {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    }
});