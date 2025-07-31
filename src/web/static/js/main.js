// Metasploit-AI Framework - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize Socket.IO connection
    if (typeof io !== 'undefined') {
        initializeSocket();
    }

    // Add loading states to buttons
    addButtonLoadingStates();
    
    // Initialize auto-refresh functionality
    initializeAutoRefresh();
}

function initializeSocket() {
    const socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to Metasploit-AI server');
        updateConnectionStatus('connected');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        updateConnectionStatus('disconnected');
    });
    
    socket.on('notification', function(data) {
        showNotification(data.message, data.type);
    });
    
    socket.on('scan_update', function(data) {
        updateScanProgress(data);
    });
    
    socket.on('exploit_result', function(data) {
        updateExploitResult(data);
    });
    
    // Store socket globally for other scripts
    window.metasploitSocket = socket;
}

function updateConnectionStatus(status) {
    const statusIndicator = document.querySelector('.connection-status');
    if (statusIndicator) {
        statusIndicator.className = `connection-status status-${status}`;
        statusIndicator.textContent = status === 'connected' ? 'Online' : 'Offline';
    }
}

function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

function addButtonLoadingStates() {
    const buttons = document.querySelectorAll('button[type="submit"], .btn-ajax');
    
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            if (!this.disabled) {
                const originalText = this.innerHTML;
                this.innerHTML = '<span class="loading-spinner"></span> Loading...';
                this.disabled = true;
                
                // Store original text for restoration
                this.dataset.originalText = originalText;
            }
        });
    });
}

function restoreButtonState(button) {
    if (button && button.dataset.originalText) {
        button.innerHTML = button.dataset.originalText;
        button.disabled = false;
        delete button.dataset.originalText;
    }
}

function updateScanProgress(data) {
    const progressBar = document.querySelector(`#scan-${data.scan_id} .progress-bar`);
    if (progressBar) {
        progressBar.style.width = `${data.progress}%`;
        progressBar.textContent = `${data.progress}%`;
        
        if (data.progress === 100) {
            progressBar.classList.add('bg-success');
            showNotification(`Scan ${data.scan_id} completed successfully!`, 'success');
        }
    }
}

function updateExploitResult(data) {
    const resultContainer = document.querySelector(`#exploit-${data.exploit_id} .result`);
    if (resultContainer) {
        const statusClass = data.success ? 'text-success' : 'text-danger';
        const statusIcon = data.success ? 'fa-check-circle' : 'fa-times-circle';
        
        resultContainer.innerHTML = `
            <i class="fas ${statusIcon} ${statusClass}"></i>
            <span class="${statusClass}">${data.message}</span>
        `;
    }
}

function initializeAutoRefresh() {
    // Auto-refresh dashboard statistics every 30 seconds
    if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
        setInterval(() => {
            if (window.metasploitSocket) {
                window.metasploitSocket.emit('request_dashboard_update');
            }
        }, 30000);
    }
}

// Utility functions
function formatDateTime(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function formatFileSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard!', 'success');
    }).catch(() => {
        showNotification('Failed to copy to clipboard', 'danger');
    });
}

// AJAX helper functions
function makeRequest(url, options = {}) {
    const defaultOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    };
    
    const mergedOptions = { ...defaultOptions, ...options };
    
    return fetch(url, mergedOptions)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .catch(error => {
            console.error('Request failed:', error);
            showNotification('Request failed: ' + error.message, 'danger');
            throw error;
        });
}

// Export functions for use in other scripts
window.MetasploitAI = {
    showNotification,
    updateScanProgress,
    updateExploitResult,
    restoreButtonState,
    makeRequest,
    copyToClipboard,
    formatDateTime,
    formatFileSize
};
