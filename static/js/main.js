// Helper to get CSRF token
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

// Service control functions
function updateServiceCard(card, data, enabled) {
    // Update Badge
    const badge = card.querySelector('.status-badge');
    badge.className = 'status-badge'; // Reset classes
    if (enabled) {
        badge.classList.add('status-online');
        badge.textContent = 'ONLINE';
    } else {
        badge.classList.add('status-offline');
        badge.textContent = 'OFFLINE';
    }

    // Update URL Row
    const urlRow = card.querySelector('.current-url-row');
    const urlLink = card.querySelector('.url-link');
    if (enabled && data.url) {
        urlLink.href = data.url;
        urlLink.textContent = data.url;
        urlRow.style.display = 'flex';
    } else {
        urlRow.style.display = 'none';
    }

    // Update Regex Row
    const regexRow = card.querySelector('.regex-row');
    if (regexRow) {
        const regexCode = card.querySelector('.regex-pattern');
        if (enabled && data.regex) {
            regexCode.dataset.regex = data.regex;
            regexCode.textContent = data.regex;
            regexRow.style.display = 'flex';
        } else {
            regexRow.style.display = 'none';
        }
    }

    // Update Actions
    const actions = card.querySelector('.service-actions');
    actions.style.display = enabled ? 'flex' : 'none';
}

function updateServiceHealthUI(serviceId, isHealthy, isOnline) {
    const card = document.querySelector(`.service-card[data-service-id="${serviceId}"]`);
    if (!card) return;

    const badge = card.querySelector('.status-badge');
    const slider = card.querySelector('.slider');

    if (isOnline) {
        if (isHealthy) {
            badge.className = 'status-badge status-online';
            badge.textContent = 'ONLINE';
            slider.classList.remove('slider-error');
        } else {
            badge.className = 'status-badge status-error';
            badge.textContent = 'UNHEALTHY';
            slider.classList.add('slider-error');
        }
    } else {
        badge.className = 'status-badge status-offline';
        badge.textContent = 'OFFLINE';
        slider.classList.remove('slider-error');
    }
}

async function toggleService(serviceId, enable, event) {
    const action = enable ? 'on' : 'off';
    
    const switchInput = event.target;
    switchInput.disabled = true;
    
    // Find the parent service card to show a loading state
    const serviceCard = switchInput.closest('.service-card');
    serviceCard.classList.add('loading-state');
    
    try {
        const response = await fetch(`/api/services/${serviceId}/${action}`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            updateServiceCard(serviceCard, data, enable);
            switchInput.disabled = false;
            
            // Refresh firewall and health status in the UI
            if (window.refreshStatus) {
                window.refreshStatus();
            }
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
            // Revert the switch state on failure
            switchInput.checked = !enable;
            switchInput.disabled = false;
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
        // Revert the switch state on failure
        switchInput.checked = !enable;
        switchInput.disabled = false;
    } finally {
        serviceCard.classList.remove('loading-state');
    }
}

async function rotateService(serviceId, event) {
    const btn = event.target;
    const originalText = btn.textContent; // Save original text
    btn.disabled = true;
    btn.textContent = '⏳ Rotating...';
    
    // Find service card
    const serviceCard = btn.closest('.service-card');
    
    try {
        const response = await fetch(`/api/services/${serviceId}/rotate`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            updateServiceCard(serviceCard, data, true);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function deleteService(serviceId, serviceName) {
    const confirmMsg = `Are you sure you want to delete "${serviceName}"?\n\nThis action cannot be undone.`;
    if (!confirm(confirmMsg)) return;
    
    try {
        const response = await fetch(`/api/services/${serviceId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            // Reload after a short delay to show the toast
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
    }
}

async function diagnoseService(serviceId, event) {
    const btn = event.target;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '🔍 Checking...';
    
    try {
        const response = await fetch(`/api/services/${serviceId}/diagnose`, {
            method: 'GET'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showDiagnosticsModal(data);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
        
        btn.disabled = false;
        btn.textContent = originalText;
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function repairService(serviceId) {
    try {
        const response = await fetch(`/api/services/${serviceId}/repair`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            // Close modal and reload after a short delay
            setTimeout(() => {
                closeDiagnosticsModal();
                window.location.reload();
            }, 1500);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
    }
}



function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showDiagnosticsModal(diagnostics) {
    const modal = document.getElementById('diagnosticsModal');
    const content = document.getElementById('diagnosticsContent');
    
    let html = `<div class="diagnostics-service-info">
        <h4>${escapeHtml(diagnostics.service.name)}</h4>
        <p><strong>Status:</strong> ${diagnostics.service.enabled ? 'Enabled' : 'Disabled'}</p>
    </div>`;
    
    html += '<div class="diagnostics-checks">';
    
    for (const [checkName, checkData] of Object.entries(diagnostics.checks)) {
        const statusClass = checkData.status === 'ok' ? 'check-ok' : 
                          checkData.status === 'warning' ? 'check-warning' : 
                          checkData.status === 'fail' ? 'check-fail' : 'check-info';
        
        const statusIcon = checkData.status === 'ok' ? '✅' : 
                         checkData.status === 'warning' ? '⚠️' : 
                         checkData.status === 'fail' ? '❌' : 'ℹ️';
        
        html += `<div class="diagnostic-check ${statusClass}">
            <div class="check-header">
                <span class="check-icon">${statusIcon}</span>
                <strong>${escapeHtml(checkName.replace(/_/g, ' ').toUpperCase())}</strong>
            </div>
            <div class="check-message">${escapeHtml(checkData.message)}</div>`;
        
        // Show additional details if available
        if (checkData.expected || checkData.actual || checkData.port || checkData.hostname || checkData.target_url || checkData.target || checkData.status_code || checkData.error) {
            html += '<div class="check-details">';
            if (checkData.expected) html += `<div>Expected: <code>${escapeHtml(checkData.expected)}</code></div>`;
            if (checkData.actual) html += `<div>Actual: <code>${escapeHtml(checkData.actual)}</code></div>`;
            if (checkData.port) html += `<div>Port: <code>${escapeHtml(checkData.port)}</code></div>`;
            if (checkData.hostname) html += `<div>Hostname: <code>${escapeHtml(checkData.hostname)}</code></div>`;
            if (checkData.target_url) html += `<div>Target: <code>${escapeHtml(checkData.target_url)}</code></div>`;
            if (checkData.target) html += `<div>Backend URL: <code>${escapeHtml(checkData.target)}</code></div>`;
            if (checkData.status_code) html += `<div>Status Code: <code>${escapeHtml(checkData.status_code)}</code></div>`;
            if (checkData.error) html += `<div>Error: <code>${escapeHtml(checkData.error)}</code></div>`;
            html += '</div>';
        }
        
        html += '</div>';
    }
    
    html += '</div>';
    
    // Add repair button if there are any warnings or failures
    const hasIssues = Object.values(diagnostics.checks).some(c => c.status === 'warning' || c.status === 'fail');
    if (hasIssues && diagnostics.service.enabled) {
        html += `<div class="diagnostics-actions">
            <button class="btn btn-primary" onclick="repairService(${diagnostics.service.id})">
                🔧 Repair Configuration
            </button>
        </div>`;
    }
    
    content.textContent = '';
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    while (doc.body.firstChild) {
        content.appendChild(doc.body.firstChild);
    }
    modal.style.display = 'block';
}

function closeDiagnosticsModal() {
    document.getElementById('diagnosticsModal').style.display = 'none';
}

// Auto-hide alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
    
    // Attach event listeners to regex patterns
    document.querySelectorAll('.regex-pattern[data-regex]').forEach(element => {
        // Populate the visible text from data attribute to avoid duplication
        element.textContent = element.dataset.regex;
        
        element.addEventListener('click', function(event) {
            event.preventDefault();
            copyToClipboard(this.dataset.regex, 'Regex pattern copied to clipboard!');
        });
    });
});

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    const diagnosticsModal = document.getElementById('diagnosticsModal');
    
    if (event.target === diagnosticsModal) {
        closeDiagnosticsModal();
    }
});

// Copy to clipboard function
function copyToClipboard(text, successMessage) {
    // Modern clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showToast(successMessage, 'success');
        }).catch(err => {
            showToast('Failed to copy: ' + err, 'error');
        });
    } else {
        // Fallback for older browsers or non-HTTPS contexts
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            showToast(successMessage, 'success');
        } catch (err) {
            showToast('Failed to copy: ' + err, 'error');
        } finally {
            document.body.removeChild(textArea);
        }
    }
}
