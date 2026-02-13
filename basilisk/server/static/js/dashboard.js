/* static/js/dashboard.js */

// Global State
let chartsVisible = false;
let currentAgentId = null;
let chartSeverityInstance = null;
let chartTypesInstance = null;

// --- INITIALIZATION ---
document.addEventListener("DOMContentLoaded", () => {
    fetchDashboardData();
    setInterval(fetchDashboardData, 5000); 
});

// --- CORE FUNCTIONS ---
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
    badge.className = online ? 'badge bg-success shadow-sm font-monospace' : 'badge bg-danger shadow-sm font-monospace';
    badge.textContent = online ? 'CONNECTED' : 'DISCONNECTED';
}

// --- RENDERERS ---
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
                <div class="fw-bold text-white font-monospace"><i class="fa-brands fa-windows me-2 text-primary"></i>${info.hostname}</div>
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
        
        const row = `<tr>
            <td class="font-monospace small text-muted">${timeStr}</td>
            <td class="font-monospace text-info">${inc.agent_id.substring(0,8)}...</td>
            <td><span class="badge ${inc.severity === 'CRITICAL' ? 'bg-danger' : (inc.severity === 'WARNING' ? 'bg-warning text-dark' : 'bg-info bg-opacity-25 text-info border border-info border-opacity-25')}">${inc.severity}</span></td>
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

// --- AGENT INSPECTOR (MODAL) ---
function openAgentInspector(aid) {
    currentAgentId = aid;
    document.getElementById('modalTitle').innerHTML = `<i class="fa-solid fa-terminal me-2 text-success"></i>AGENT INSPECTOR: <span class="text-white">${aid}</span>`;
    
    const modal = new bootstrap.Modal(document.getElementById('reportModal'));
    modal.show();
    
    loadReportView('processes');
}

async function loadReportView(type) {
    if (!currentAgentId) return;
    const container = document.getElementById(`${type}-content`);
    container.innerHTML = '<div class="p-4 text-center text-muted"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><br>Fetching Data...</div>';

    try {
        const res = await fetch(`/api/v1/agent/${currentAgentId}/${type}`);
        const data = await res.json();
        
        if (data.length === 0 && Object.keys(data).length === 0) {
            container.innerHTML = '<div class="p-4 text-center text-muted">No Data Available</div>';
            return;
        }

        if (type === 'processes') {
            renderProcessTable(container, data);
        } else if (type === 'ports') {
            renderPortsTable(container, data);
        } else if (type === 'audit') {
            renderAuditWidget(container, data); 
        }

    } catch (e) {
        container.innerHTML = `<div class="p-3 text-danger">Error loading data: ${e.message}</div>`;
    }
}

// --- RENDER AUDIT WIDGET  ---
function renderAuditWidget(container, data) {
    const fw = data.firewall || {};
    const isSecure = fw.Overall === 'SECURE';
    const getDot = (status) => status === 'ACTIVE' ? 'active' : 'inactive';
    const defStatus = data.defender || 'UNKNOWN';
    const uacStatus = data.uac || 'UNKNOWN';

    container.innerHTML = `
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

// --- HELPERS PARA TABLAS ---
function renderProcessTable(container, data) {
    let html = '<table class="table table-sm table-hover w-100"><thead><tr><th>PID</th><th>Name</th><th>User</th><th>Path</th></tr></thead><tbody>';
    data.forEach(p => {
        html += `<tr><td>${p.pid}</td><td class="text-info fw-bold">${p.name}</td><td>${p.username}</td><td class="small text-muted">${p.exe || '-'}</td></tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function renderPortsTable(container, data) {
    let html = '<table class="table table-sm table-hover w-100"><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Risk</th></tr></thead><tbody>';
    data.forEach(p => {
        const badge = p.risk === 'CRITICAL' ? 'bg-danger' : (p.risk === 'HIGH' ? 'bg-warning text-dark' : 'bg-success');
        html += `<tr><td>${p.port}</td><td>${p.proto}</td><td>${p.service}</td><td><span class="badge ${badge}">${p.risk}</span></td></tr>`;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

// --- UI HELPERS ---
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
        text: isolate ? "Host will lose all connectivity except C2." : "Normal connectivity will be restored.",
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