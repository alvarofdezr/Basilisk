/**
 * Basilisk Dashboard Controller
 * Handles real-time telemetry, agent inspection, and command dispatch.
 */

let chartsVisible = false;
let currentAgentId = null;
let chartSeverityInstance = null;
let chartTypesInstance = null;

window.dashboardReady = false;
console.log("[BASILISK] dashboard.js file loaded!");
console.log("[BASILISK] Current URL: " + window.location.href);

document.addEventListener("DOMContentLoaded", function() {
    console.log("[BASILISK_INIT] DOMContentLoaded event fired!");
    window.dashboardReady = true;
    try {
        fetchDashboardData();
        setInterval(fetchDashboardData, 5000);
        console.log("[BASILISK_INIT] Fetch interval set successfully");
    } catch (err) {
        console.error("[BASILISK_ERROR] Error in DOMContentLoaded:", err);
    }
});

async function fetchDashboardData() {
    try {
        const res = await fetch('/api/v1/dashboard');
        if (!res.ok) throw new Error("API Error");
        const data = await res.json();
        
        updateServerStatus(true);
        renderAgents(data.agents);
        renderIncidents(data.recent_incidents);
        updateKPIs(data);
        if (chartsVisible) updateCharts(data.recent_incidents);

    } catch (e) {
        console.error(e);
        updateServerStatus(false);
    }
}

function updateServerStatus(online) {
    const badge = document.getElementById('server-status-badge');
    badge.className = online 
        ? 'badge bg-success shadow-sm font-monospace' 
        : 'badge bg-danger shadow-sm font-monospace';
    badge.textContent = online ? 'CONNECTED' : 'DISCONNECTED';
}

function renderAgents(agents) {
    const list = document.getElementById('agents-list');
    list.innerHTML = '';
    let count = 0;

    for (const [aid, info] of Object.entries(agents)) {
        count++;
        const isOnline = info.status === 'ONLINE';
        const item = document.createElement('div');
        item.className = 'agent-item';
        item.onclick = () => openAgentInspector(aid);
        item.innerHTML = `
            <div>
                <div class="fw-bold text-white font-monospace">
                    <i class="fa-brands fa-windows me-2 text-primary"></i>${info.hostname}
                </div>
                <div class="small text-muted" style="font-size:0.7rem">${aid.substring(0,8)}...</div>
            </div>
            <div class="text-end">
                <span class="badge ${isOnline ? 'bg-success' : 'bg-secondary'}">${info.status}</span>
            </div>
        `;
        list.appendChild(item);
    }
    document.getElementById('kpi-agents').textContent = count;
}

function renderIncidents(incidents) {
    const tbody = document.querySelector('#incidents-table tbody');
    tbody.innerHTML = '';

    const limitSelect = document.getElementById('incident-limit');
    const limit = limitSelect ? parseInt(limitSelect.value) : 10;

    const visibleIncidents = incidents.slice(0, limit);

    if (visibleIncidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted small py-3">NO ACTIVE THREATS RECORDED</td></tr>';
        return;
    }

    visibleIncidents.forEach(inc => {
        const timeStr = inc.received_at.split('T')[1].split('.')[0];
        const severityBadge = inc.severity === 'CRITICAL' 
            ? 'bg-danger' 
            : (inc.severity === 'WARNING' 
                ? 'bg-warning text-dark' 
                : 'bg-info bg-opacity-25 text-info border border-info border-opacity-25');
        
        const row = `<tr>
            <td class="font-monospace small text-muted">${timeStr}</td>
            <td class="font-monospace text-info">${inc.agent_id.substring(0,8)}...</td>
            <td><span class="badge ${severityBadge}">${inc.severity}</span></td>
            <td class="small">${inc.type}</td>
            <td class="text-light small text-truncate" style="max-width: 200px;" title="${inc.message}">${inc.message}</td>
        </tr>`;
        tbody.innerHTML += row;
    });
}

function updateKPIs(data) {
    const criticals = data.recent_incidents.filter(i => i.severity === 'CRITICAL').length;
    document.getElementById('kpi-critical').textContent = criticals;
}

function openAgentInspector(aid) {
    currentAgentId = aid;
    console.log("[INSPECTOR] Opening for " + aid);
    
    document.getElementById('modalTitle').innerHTML = 
        '<i class="fa-solid fa-terminal me-2 text-success"></i>AGENT INSPECTOR: ' +
        '<span class="text-white">' + aid.substring(0, 12) + '...</span>';
    
    const modal = new bootstrap.Modal(document.getElementById('reportModal'));
    modal.show();
    
    const loadingState = '<div class="p-5 text-center"><i class="fa-solid fa-circle-notch fa-spin fa-2x text-primary mb-3"></i><p class="text-muted small">Requesting data from agent...</p></div>';
    const waitingState = '<div class="p-5 text-center"><i class="fa-solid fa-hourglass-start text-muted"></i></div>';
    
    document.getElementById('processes-content').innerHTML = loadingState;
    document.getElementById('ports-content').innerHTML = waitingState;
    document.getElementById('audit-content').innerHTML = waitingState;
    
    console.log("[INSPECTOR] Sending 3 commands to server...");
    
    sendCommandToAgent('REPORT_PROCESSES');
    sendCommandToAgent('REPORT_PORTS');
    sendCommandToAgent('RUN_AUDIT');
    
    setTimeout(() => {
        console.log("[INSPECTOR] 8s passed, loading all reports...");
        loadReportView('processes');
        loadReportView('ports');
        loadReportView('audit');
    }, 8000);
}

function sendCommandToAgent(command) {
    console.log("[SEND] " + command + " → " + currentAgentId);
    
    if (!currentAgentId) {
        console.error("[SEND] ERROR: No agent selected!");
        return;
    }
    
    fetch('/api/v1/admin/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            target_agent_id: currentAgentId,
            command: command
        })
    })
    .then(r => r.json())
    .then(data => {
        console.log("[SEND] ✓ " + command + " queued: " + JSON.stringify(data));
    })
    .catch(e => {
        console.error("[SEND] ✗ " + command + " error: " + e);
    });
}

async function loadReportView(type) {
    console.log("[LOAD] Getting " + type + " for agent " + currentAgentId);
    
    if (!currentAgentId) {
        console.error("[LOAD] No agent ID!");
        return;
    }
    
    const container = document.getElementById(type + '-content');
    if (!container) {
        console.error("[LOAD] Container not found!");
        return;
    }
    
    container.innerHTML = '<div class="text-center p-5"><div class="spinner-border spinner-border-sm text-primary mb-2"></div><p class="small text-muted">Loading...</p></div>';
    
    try {
        const url = '/api/v1/agent/' + currentAgentId + '/' + type;
        console.log("[LOAD] GET " + url);
        
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error("HTTP " + res.status);
        }
        
        const data = await res.json();
        console.log("[LOAD] Got " + type + " data, length: " + 
            (data ? (Array.isArray(data) ? data.length : Object.keys(data).length) : 0));
        
        if (!data || 
            (Array.isArray(data) && data.length === 0) || 
            (typeof data === 'object' && Object.keys(data).length === 0)) {
            console.warn("[LOAD] No data yet for " + type);
            container.innerHTML = 
                '<div class="p-5 text-center">' +
                '<i class="fa-solid fa-hourglass fa-2x mb-3 d-block opacity-50"></i>' +
                '<p class="small text-muted">No data yet. Agent is collecting...</p>' +
                '<button class="btn btn-sm btn-outline-secondary mt-2" onclick="loadReportView(\'' + type + '\')">' +
                '<i class="fa-solid fa-rotate-right me-2"></i>Retry</button></div>';
            return;
        }
        
        if (type === 'processes') {
            renderProcessTable(container, data);
        } else if (type === 'ports') {
            renderPortsTable(container, data);
        } else if (type === 'audit') {
            renderAuditWidget(container, data);
        }
        
        console.log("[LOAD] ✓ " + type + " rendered!");
        
    } catch (err) {
        console.error("[LOAD] Error: " + err);
        container.innerHTML = 
            '<div class="p-5 text-center text-danger">' +
            '<i class="fa-solid fa-triangle-exclamation fa-2x mb-2 d-block"></i>' +
            '<p><strong>Error loading ' + type + '</strong></p>' +
            '<p class="small">' + err + '</p>' +
            '<button class="btn btn-sm btn-outline-secondary mt-2" onclick="loadReportView(\'' + type + '\')">' +
            '<i class="fa-solid fa-rotate-right me-2"></i>Retry</button></div>';
    }
}

function renderAuditWidget(container, data) {
    const fw = data.firewall || {};
    const isSecure = fw.Overall === 'SECURE';
    const getDot = (status) => status === 'ACTIVE' ? 'active' : 'inactive';
    const defStatus = data.defender || 'UNKNOWN';
    const uacStatus = data.uac || 'UNKNOWN';

    container.innerHTML = `
    <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary">
        <span class="small text-muted">Compliance Audit Report</span>
        <button class="btn btn-sm btn-outline-secondary" onclick="sendCommandToAgent('RUN_AUDIT'); setTimeout(() => loadReportView('audit'), 3000);">
            <i class="fa-solid fa-rotate-right me-1"></i>Refresh
        </button>
    </div>
    <div class="audit-widget">
        <div class="audit-card">
            <div class="card-header">
                <span><i class="fa-solid fa-fire text-warning me-2"></i>Firewall Status</span>
                <span class="badge-audit ${isSecure ? 'badge-success' : 'badge-danger'}">${fw.Overall || 'UNKNOWN'}</span>
            </div>
            <div class="fw-grid">
                <div class="fw-item"><span class="label">Domain</span><div class="status-dot ${getDot(fw.Domain)}"></div></div>
                <div class="fw-item"><span class="label">Standard</span><div class="status-dot ${getDot(fw.Standard)}"></div></div>
                <div class="fw-item"><span class="label">Public</span><div class="status-dot ${getDot(fw.Public)}"></div></div>
            </div>
        </div>

        <div class="audit-card">
            <div class="card-header border-0 mb-2"><span><i class="fa-solid fa-shield-halved text-info me-2"></i>System Hardening</span></div>
            <div class="sec-row">
                <div class="sec-item">
                    <span class="label">Defender AV</span>
                    <span class="sec-value ${defStatus === 'ACTIVE' ? 'text-green' : 'text-red'}">${defStatus}</span>
                </div>
                <div class="sec-item">
                    <span class="label">UAC Policy</span>
                    <span class="sec-value ${uacStatus === 'ENABLED' ? 'text-green' : 'text-red'}">${uacStatus}</span>
                </div>
            </div>
        </div>

        <div class="audit-footer">
            <div><i class="fa-solid fa-clock-rotate-left me-1"></i> Scan: <span class="text-light">${data.scan_time || '--'}</span></div>
            <div><i class="fa-solid fa-calendar-check me-1"></i> Update: <span class="text-light">${data.last_update || 'N/A'}</span></div>
        </div>
    </div>`;
}

function renderProcessTable(container, data) {
    let html = `
        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary">
            <span class="small text-muted">Found <strong>${data.length}</strong> processes</span>
            <button class="btn btn-sm btn-outline-secondary" onclick="sendCommandToAgent('REPORT_PROCESSES'); setTimeout(() => loadReportView('processes'), 3000);">
                <i class="fa-solid fa-rotate-right me-1"></i>Refresh
            </button>
        </div>
        <table class="table table-sm table-hover w-100">
            <thead>
                <tr><th>PID</th><th>Name</th><th>User</th><th>Path</th></tr>
            </thead>
            <tbody>`;
    data.forEach(p => {
        html += `<tr><td>${p.pid}</td><td class="text-info fw-bold">${p.name}</td><td>${p.username}</td><td class="small text-muted">${p.exe || '-'}</td></tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function renderPortsTable(container, data) {
    let html = `
        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary">
            <span class="small text-muted">Found <strong>${data.length}</strong> ports</span>
            <button class="btn btn-sm btn-outline-secondary" onclick="sendCommandToAgent('REPORT_PORTS'); setTimeout(() => loadReportView('ports'), 3000);">
                <i class="fa-solid fa-rotate-right me-1"></i>Refresh
            </button>
        </div>
        <table class="table table-sm table-hover w-100">
            <thead>
                <tr><th>Port</th><th>Proto</th><th>Service</th><th>Risk</th></tr>
            </thead>
            <tbody>`;
    data.forEach(p => {
        const badge = p.risk === 'CRITICAL' 
            ? 'bg-danger' 
            : (p.risk === 'HIGH' ? 'bg-warning text-dark' : 'bg-success');
        html += `<tr><td>${p.port}</td><td>${p.proto}</td><td>${p.service}</td><td><span class="badge ${badge}">${p.risk}</span></td></tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function switchView(viewId) {
    document.getElementById('view-dashboard').style.display = viewId === 'dashboard' ? 'block' : 'none';
    document.getElementById('view-network').style.display = viewId === 'network' ? 'block' : 'none';
}

function toggleCharts() {
    const area = document.getElementById('chart-area');
    chartsVisible = !chartsVisible;
    area.style.display = chartsVisible ? 'flex' : 'none';
    if (chartsVisible) fetchDashboardData();
}

async function logout() {
    await fetch('/api/v1/auth/logout', { method: 'POST' });
    window.location.href = '/login';
}

function confirmIsolation(isolate) {
    const action = isolate ? "ISOLATE" : "RESTORE";
    Swal.fire({
        title: `Confirm ${action}?`,
        text: isolate 
            ? "Host will lose all connectivity except C2." 
            : "Normal connectivity will be restored.",
        icon: isolate ? 'warning' : 'info',
        showCancelButton: true,
        confirmButtonColor: isolate ? '#dc3545' : '#198754',
        confirmButtonText: `Yes, ${action}`
    }).then((result) => {
        if (result.isConfirmed) {
            Swal.fire('Sent!', 'Command queued successfully.', 'success');
        }
    });
}

window.testInspector = function(agentId) {
    console.log("[TEST] Starting inspector test with agent: " + agentId);
    openAgentInspector(agentId);
    console.log("[TEST] Inspector opened. Check modal and console. Waiting 10s for data to load...");
};

console.log("[BASILISK] ✓ Dashboard fully loaded! Type: testInspector('AGENT_123') to test");