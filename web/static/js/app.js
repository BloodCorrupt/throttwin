/* ===== Throttwin Web UI — app.js ===== */
'use strict';

// ─── State ──────────────────────────────────────────────────
const state = {
    devices:    [],
    targets:    [],
    whitelisted:[],
    rules:      { whitelist: {}, blacklist: {} },
    status:     'IDLE',
    limit_mbps: 1.0,
    interface:  '',
    router_ip:  '',
    telemetry:  {},
    uptime:     0,
    sessionStartTs: null,
    speedHistory: Array(60).fill(0),
};

// ─── Helpers ─────────────────────────────────────────────────
function fmtBytes(b) {
    if (b < 1024)           return `${b} B`;
    if (b < 1048576)        return `${(b/1024).toFixed(1)} KB`;
    if (b < 1073741824)     return `${(b/1048576).toFixed(1)} MB`;
    return `${(b/1073741824).toFixed(2)} GB`;
}
function fmtDuration(s) {
    s = Math.floor(s);
    const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), ss = s%60;
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(ss).padStart(2,'0')}`;
}
function fmtMbps(v) { return `${Number(v).toFixed(2)} Mbps`; }

function toast(msg, type='info', duration=3500) {
    const icons = { success:'fa-check-circle', error:'fa-circle-xmark', info:'fa-circle-info' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<i class="fa-solid ${icons[type]||icons.info}"></i><span>${msg}</span>`;
    document.getElementById('toastContainer').appendChild(el);
    setTimeout(() => {
        el.classList.add('toast-fade');
        setTimeout(() => el.remove(), 400);
    }, duration);
}

async function api(method, path, body) {
    const opts = { method, headers: {'Content-Type':'application/json'} };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    return r.json();
}

// ─── Tab Navigation ───────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`pane-${tab}`).classList.add('active');
        if (tab === 'rules')    loadRules();
        if (tab === 'settings') loadSettings();
    });
});

// ─── Modal helpers ────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

['closeModalStart','cancelModalStart'].forEach(id =>
    document.getElementById(id)?.addEventListener('click', () => closeModal('modalStartSession')));
['closeModalAddDevice','cancelAddDevice'].forEach(id =>
    document.getElementById(id)?.addEventListener('click', () => closeModal('modalAddDevice')));
['closeModalAddRule','cancelAddRule'].forEach(id =>
    document.getElementById(id)?.addEventListener('click', () => closeModal('modalAddRule')));

document.querySelectorAll('.modal-overlay').forEach(ov => {
    ov.addEventListener('click', e => { if (e.target === ov) ov.classList.remove('active'); });
});

// ─── SSE Connection ───────────────────────────────────────────
let sseRetryTimer = null;

function connectSSE() {
    const es = new EventSource('/api/stream');
    const badge = document.getElementById('liveConnectionBadge');
    const dot   = badge.querySelector('.status-dot');
    const txt   = badge.querySelector('.status-text');

    es.onopen = () => {
        dot.className = 'status-dot connected';
        txt.textContent = 'Live';
        if (sseRetryTimer) { clearTimeout(sseRetryTimer); sseRetryTimer = null; }
    };

    es.onmessage = (e) => {
        try {
            const msg = JSON.parse(e.data);
            if (msg.type === 'init') applyState(msg.state);
            else if (msg.data?.state) applyState(msg.data.state);
            else if (msg.data?.devices) { state.devices = msg.data.devices || state.devices; renderDevicesTable(); }
        } catch {}
    };

    es.onerror = () => {
        dot.className = 'status-dot error';
        txt.textContent = 'Disconnected';
        es.close();
        sseRetryTimer = setTimeout(connectSSE, 4000);
    };
}
connectSSE();

// ─── State Application ────────────────────────────────────────
function applyState(s) {
    if (!s) return;
    state.status     = s.status     || 'IDLE';
    state.limit_mbps = s.limit_mbps || 1.0;
    state.interface  = s.interface  || state.interface;
    state.router_ip  = s.router_ip  || state.router_ip;
    state.uptime     = s.uptime     || 0;
    state.telemetry  = s.telemetry  || {};

    if (s.devices)    state.devices    = s.devices;
    if (s.targets)    state.targets    = s.targets;
    if (s.whitelisted) state.whitelisted = s.whitelisted;

    updateTopBar();
    updateMetrics(s);
    renderTargetsTable();
    renderDevicesTable();
}

// ─── Top Bar / Status ─────────────────────────────────────────
let timerInterval = null;

function updateTopBar() {
    const pill = document.getElementById('sessionStatusPill');
    const txt  = document.getElementById('sessionStatusText');
    const timer = document.getElementById('sessionTimer');
    const btn   = document.getElementById('btnSessionControl');
    const btnTxt = document.getElementById('btnSessionControlText');
    const liveInd = document.getElementById('liveIndicator');

    pill.className = `session-status-pill ${state.status.toLowerCase()}`;
    txt.textContent = state.status;

    if (state.status === 'RUNNING') {
        timer.style.display = 'flex';
        liveInd.style.display = 'inline-flex';
        btn.querySelector('i').className = 'fa-solid fa-stop';
        btnTxt.textContent = 'Stop Session';
        btn.className = 'btn btn-danger btn-glow';

        if (!timerInterval) {
            const base = Date.now() - (state.uptime * 1000);
            timerInterval = setInterval(() => {
                document.getElementById('sessionTimeDisplay').textContent =
                    fmtDuration((Date.now() - base) / 1000);
            }, 1000);
        }
    } else {
        timer.style.display = 'none';
        liveInd.style.display = 'none';
        btn.querySelector('i').className = 'fa-solid fa-play';
        btnTxt.textContent = 'Start Session';
        btn.className = 'btn btn-primary btn-glow';

        if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
        document.getElementById('sessionTimeDisplay').textContent = '00:00:00';
    }
}

// ─── Metrics ──────────────────────────────────────────────────
function updateMetrics(s) {
    const kbps  = s.total_speed_kbps || 0;
    const mbps  = s.total_speed_mbps || 0;
    const dataMb = s.total_data_mb   || 0;
    const count = s.target_count     || 0;

    document.getElementById('statThroughput').innerHTML =
        kbps >= 1000
        ? `${mbps.toFixed(2)} <span class="unit">Mbps</span>`
        : `${kbps.toFixed(1)} <span class="unit">KB/s</span>`;
    document.getElementById('statThroughputMbps').textContent = `${fmtMbps(mbps)} total speed`;
    document.getElementById('statDataThrottled').innerHTML =
        `${dataMb.toFixed(1)} <span class="unit">MB</span>`;
    document.getElementById('statTargets').textContent = count;
    document.getElementById('statLimit').innerHTML =
        state.status === 'RUNNING'
        ? `${state.limit_mbps} <span class="unit">Mbps</span>`
        : '—';

    // Speed history sparkline
    if (state.status === 'RUNNING') {
        state.speedHistory.push(kbps);
        if (state.speedHistory.length > 60) state.speedHistory.shift();
        drawSpeedChart();
        document.getElementById('speedChartCard').style.display = '';
    } else {
        document.getElementById('speedChartCard').style.display = 'none';
    }
}

// ─── Speed Chart (canvas sparkline) ──────────────────────────
function drawSpeedChart() {
    const canvas = document.getElementById('speedChart');
    const ctx    = canvas.getContext('2d');
    const W = canvas.offsetWidth; const H = 80;
    canvas.width = W; canvas.height = H;

    const data = state.speedHistory;
    const max  = Math.max(...data, 1);

    ctx.clearRect(0,0,W,H);

    // Gradient fill
    const grad = ctx.createLinearGradient(0,0,0,H);
    grad.addColorStop(0, 'rgba(99,179,237,0.35)');
    grad.addColorStop(1, 'rgba(99,179,237,0)');

    ctx.beginPath();
    ctx.moveTo(0, H);
    data.forEach((v, i) => {
        const x = (i / (data.length-1)) * W;
        const y = H - (v / max) * (H - 6);
        if (i === 0) ctx.lineTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.lineTo(W, H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((v, i) => {
        const x = (i / (data.length-1)) * W;
        const y = H - (v / max) * (H - 6);
        i === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.strokeStyle = '#63b3ed';
    ctx.lineWidth = 2;
    ctx.stroke();
}

// ─── Targets Table ────────────────────────────────────────────
function renderTargetsTable() {
    const tbody = document.getElementById('targetsTableBody');

    if (state.status !== 'RUNNING' || !state.targets.length) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7">
            <i class="fa-solid fa-moon"></i>
            No active session — start one from the toolbar above
        </td></tr>`;
        return;
    }

    tbody.innerHTML = state.targets.map(tgt => {
        const ip     = tgt.ip || '-';
        const tel    = state.telemetry[ip] || {};
        const speedMbps = tel.speed_mbps || 0;
        const totalB = tel.total_bytes || 0;
        const vendor = tgt.vendor || 'Unknown';
        const host   = tgt.hostname || '';
        const label  = host ? `${host} (${vendor})` : vendor;
        const limitMb = state.limit_mbps;

        const pct = Math.min(speedMbps / limitMb, 1);
        let statusBadge = `<span class="badge badge-idle">Idle</span>`;
        if (pct > 0.75) statusBadge = `<span class="badge badge-heavy">● Heavy</span>`;
        else if (pct > 0.05) statusBadge = `<span class="badge badge-active">● Active</span>`;

        return `<tr>
            <td class="ip-cell">${ip}</td>
            <td>${label.substring(0,28)}</td>
            <td class="speed-cell">${speedMbps.toFixed(2)} Mbps</td>
            <td>${limitMb} Mbps</td>
            <td>${fmtBytes(totalB)}</td>
            <td>${statusBadge}</td>
            <td>
                <button class="btn btn-danger btn-sm" onclick="unthrottleTarget('${ip}')">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </td>
        </tr>`;
    }).join('');
}

async function unthrottleTarget(ip) {
    const r = await api('POST', '/api/target/toggle', { ip, should_throttle: false });
    if (r.success) { toast(`Stopped throttling ${ip}`, 'success'); applyState(r.state); }
    else toast(r.error, 'error');
}

// ─── Devices Table ────────────────────────────────────────────
function renderDevicesTable() {
    const tbody = document.getElementById('devicesTableBody');

    if (!state.devices.length) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7">
            <i class="fa-solid fa-radar"></i> No devices discovered yet
        </td></tr>`;
        updateBulkActions();
        return;
    }

    const throttledIPs = new Set((state.targets||[]).map(t=>t.ip||t));

    tbody.innerHTML = state.devices.map(dev => {
        const ip     = dev.ip || '-';
        const mac    = dev.mac || 'Unknown';
        const vendor = dev.vendor || 'Unknown';
        const host   = dev.hostname || '';
        const isThrottled = throttledIPs.has(ip);

        const statusBadge = isThrottled
            ? `<span class="badge badge-bl">Throttled</span>`
            : `<span class="badge badge-idle">Free</span>`;

        const actionBtn = state.status === 'RUNNING'
            ? (isThrottled
                ? `<button class="btn btn-success btn-sm" onclick="toggleDevice('${ip}', false)">
                     <i class="fa-solid fa-shield"></i> Release
                   </button>`
                : `<button class="btn btn-danger btn-sm" onclick="toggleDevice('${ip}', true)">
                     <i class="fa-solid fa-bolt"></i> Throttle
                   </button>`)
            : '';

        return `<tr>
            <td><input type="checkbox" class="dev-check" value="${ip}" onchange="updateBulkActions()"></td>
            <td class="ip-cell">${ip}</td>
            <td class="mac-cell">${mac}</td>
            <td>${vendor}</td>
            <td>${host}</td>
            <td>${statusBadge}</td>
            <td>${actionBtn}</td>
        </tr>`;
    }).join('');

    updateBulkActions();
}

async function toggleDevice(ip, shouldThrottle) {
    if (state.status !== 'RUNNING') { toast('No session running', 'error'); return; }
    const r = await api('POST', '/api/target/toggle', { ip, should_throttle: shouldThrottle });
    if (r.success) { applyState(r.state); toast(r.message, 'success'); }
    else toast(r.error, 'error');
}

function updateBulkActions() {
    const checked = document.querySelectorAll('.dev-check:checked');
    const panel   = document.getElementById('bulkActions');
    panel.style.display = checked.length > 0 ? 'flex' : 'none';
    document.getElementById('selectedCount').textContent = `${checked.length} selected`;
}

document.getElementById('selectAllDevices')?.addEventListener('change', function() {
    document.querySelectorAll('.dev-check').forEach(c => c.checked = this.checked);
    updateBulkActions();
});

document.getElementById('btnThrottleSelected')?.addEventListener('click', async () => {
    if (state.status !== 'RUNNING') { toast('Start a session first', 'error'); return; }
    const ips = [...document.querySelectorAll('.dev-check:checked')].map(c=>c.value);
    for (const ip of ips) {
        await api('POST', '/api/target/toggle', { ip, should_throttle: true });
    }
    const r = await api('GET', '/api/status');
    if (r.success) { applyState(r.data); toast(`Throttling ${ips.length} device(s)`, 'success'); }
});

document.getElementById('btnWhitelistSelected')?.addEventListener('click', async () => {
    const ips = [...document.querySelectorAll('.dev-check:checked')].map(c=>c.value);
    if (!ips.length) return;
    for (const ip of ips) {
        const dev = state.devices.find(d=>d.ip===ip);
        if (dev?.mac) {
            await api('POST', '/api/rules', { category:'whitelist', mac: dev.mac, name: dev.vendor||'' });
        }
    }
    toast(`Whitelisted ${ips.length} device(s)`, 'success');
    loadRules();
});

// ─── Scan ─────────────────────────────────────────────────────
async function doScan() {
    document.getElementById('btnRescanTop').innerHTML = '<i class="fa-solid fa-spinner spin"></i> Scanning…';
    document.getElementById('btnRescanDevices').innerHTML = '<i class="fa-solid fa-spinner spin"></i> Scanning…';
    try {
        const r = await api('POST', '/api/scan', {
            interface: state.interface,
            router_ip: state.router_ip
        });
        if (r.success) {
            state.devices = r.devices || [];
            document.getElementById('scanHint').style.display = 'none';
            renderDevicesTable();
            toast(`Found ${r.count} device(s)`, 'success');
        } else toast(r.error, 'error');
    } finally {
        document.getElementById('btnRescanTop').innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Scan';
        document.getElementById('btnRescanDevices').innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Rescan';
    }
}

document.getElementById('btnRescanTop')?.addEventListener('click', doScan);
document.getElementById('btnRescanDevices')?.addEventListener('click', doScan);

document.getElementById('btnClearCache')?.addEventListener('click', async () => {
    const r = await api('POST', '/api/devices/clear');
    if (r.success) { state.devices = []; renderDevicesTable(); toast('Cache cleared', 'success'); }
    else toast(r.error, 'error');
});

// ─── Session Control ──────────────────────────────────────────
document.getElementById('btnSessionControl')?.addEventListener('click', async () => {
    if (state.status === 'RUNNING') {
        const r = await api('POST', '/api/session/stop');
        if (r.success) { applyState(r.state); toast('Session stopped', 'success'); }
        else toast(r.error, 'error');
    } else {
        openStartModal();
    }
});

async function openStartModal() {
    // Load interfaces
    const ifData = await api('GET', '/api/interfaces');
    const ifSelect = document.getElementById('modalInterface');
    ifSelect.innerHTML = (ifData.interfaces || []).map(i =>
        `<option value="${i}" ${i === state.interface ? 'selected' : ''}>${i}</option>`
    ).join('');
    document.getElementById('modalRouter').value = state.router_ip || ifData.default_gateway || '';
    document.getElementById('modalLimit').value  = state.limit_mbps;

    renderModalTargetList();
    document.getElementById('modalMode').value = 'blacklist';
    handleModalModeChange();

    openModal('modalStartSession');
}

document.getElementById('modalMode')?.addEventListener('change', handleModalModeChange);
function handleModalModeChange() {
    const mode = document.getElementById('modalMode').value;
    document.getElementById('targetSelectGroup').style.display    = mode==='blacklist' ? '' : 'none';
    document.getElementById('whitelistSelectGroup').style.display = mode==='whitelist' ? '' : 'none';
}

function renderModalTargetList() {
    const tgtList = document.getElementById('modalTargetList');
    const wlList  = document.getElementById('modalWhitelistList');

    if (!state.devices.length) {
        tgtList.innerHTML = wlList.innerHTML = '<p class="no-devices-msg">No devices. Click Scan first.</p>';
        return;
    }

    const makeItems = (listEl) => {
        listEl.innerHTML = state.devices.map(dev => {
            const ip  = dev.ip || '-';
            const mac = dev.mac || '';
            const label = dev.hostname ? `${dev.hostname} (${dev.vendor||'?'})` : (dev.vendor||'Unknown');
            return `<label class="target-item">
                <input type="checkbox" value="${ip}" data-mac="${mac}" data-vendor="${dev.vendor||''}">
                <div class="target-item-info">
                    <div class="target-item-ip">${ip}</div>
                    <div class="target-item-label">${mac} — ${label}</div>
                </div>
            </label>`;
        }).join('');
    };
    makeItems(tgtList);
    makeItems(wlList);
}

document.querySelectorAll('.modal-preset').forEach(btn => {
    btn.addEventListener('click', () => {
        document.getElementById('modalLimit').value = btn.dataset.val;
    });
});

document.getElementById('confirmStartSession')?.addEventListener('click', async () => {
    const iface  = document.getElementById('modalInterface').value;
    const router = document.getElementById('modalRouter').value.trim();
    const mode   = document.getElementById('modalMode').value;
    const limit  = parseFloat(document.getElementById('modalLimit').value) || 1.0;

    if (!iface || !router) { toast('Interface and router IP required', 'error'); return; }

    let targets = [], whitelisted = [];
    if (mode === 'blacklist') {
        targets = [...document.querySelectorAll('#modalTargetList input:checked')].map(c => ({
            ip: c.value, mac: c.dataset.mac, vendor: c.dataset.vendor
        }));
        if (!targets.length) { toast('Select at least one target', 'error'); return; }
    } else {
        whitelisted = [...document.querySelectorAll('#modalWhitelistList input:checked')].map(c => ({
            ip: c.value, mac: c.dataset.mac, vendor: c.dataset.vendor
        }));
    }

    const r = await api('POST', '/api/session/start', {
        interface: iface, router_ip: router, mode,
        targets, whitelisted, limit_mbps: limit
    });

    if (r.success) {
        closeModal('modalStartSession');
        applyState(r.state);
        toast('Session started successfully!', 'success');
    } else toast(r.error || 'Failed to start session', 'error');
});

// ─── Add Device ───────────────────────────────────────────────
document.getElementById('btnManualAddTop')?.addEventListener('click', () => openModal('modalAddDevice'));
document.getElementById('btnManualAdd')?.addEventListener('click',    () => openModal('modalAddDevice'));

document.getElementById('confirmAddDevice')?.addEventListener('click', async () => {
    const ip     = document.getElementById('manualIP').value.trim();
    const mac    = document.getElementById('manualMAC').value.trim();
    const vendor = document.getElementById('manualVendor').value.trim() || 'Manual Entry';

    if (!ip && !mac) { toast('Enter IP or MAC', 'error'); return; }

    const r = await api('POST', '/api/devices/manual', { ip, mac, vendor });
    if (r.success) {
        state.devices = (await api('GET', '/api/status')).data?.devices || state.devices;
        renderDevicesTable();
        renderModalTargetList();
        closeModal('modalAddDevice');
        document.getElementById('manualIP').value  = '';
        document.getElementById('manualMAC').value = '';
        document.getElementById('manualVendor').value = '';
        toast('Device added', 'success');
    } else toast(r.error, 'error');
});

// ─── Rules ────────────────────────────────────────────────────
async function loadRules() {
    const r = await api('GET', '/api/rules');
    if (r.success) {
        state.rules = r.rules;
        renderRulesTable();
    }
}

function renderRulesTable() {
    const tbody = document.getElementById('rulesTableBody');
    const wl = state.rules.whitelist || {};
    const bl = state.rules.blacklist || {};

    const rows = [
        ...Object.entries(wl).map(([mac, name]) => ({ cat:'whitelist', mac, name })),
        ...Object.entries(bl).map(([mac, name]) => ({ cat:'blacklist', mac, name })),
    ];

    if (!rows.length) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="4">
            <i class="fa-solid fa-shield"></i> No global rules defined
        </td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(({cat, mac, name}) => `<tr>
        <td>${cat==='whitelist'
            ? '<span class="badge badge-wl">WHITELIST</span>'
            : '<span class="badge badge-bl">BLACKLIST</span>'}</td>
        <td class="mac-cell">${mac}</td>
        <td>${name || '<span style="color:var(--text-muted)">—</span>'}</td>
        <td>
            <button class="btn btn-danger btn-sm" onclick="deleteRule('${cat}','${mac}')">
                <i class="fa-solid fa-trash"></i>
            </button>
        </td>
    </tr>`).join('');
}

async function deleteRule(category, mac) {
    const r = await api('DELETE', `/api/rules/${category}/${mac}`);
    if (r.success) { state.rules = r.rules; renderRulesTable(); toast('Rule removed', 'success'); }
    else toast(r.error, 'error');
}

document.getElementById('btnAddRule')?.addEventListener('click', () => openModal('modalAddRule'));

document.getElementById('confirmAddRule')?.addEventListener('click', async () => {
    const category = document.getElementById('ruleCategory').value;
    const mac      = document.getElementById('ruleMAC').value.trim().toLowerCase();
    const name     = document.getElementById('ruleName').value.trim();

    if (!mac) { toast('MAC address required', 'error'); return; }

    const r = await api('POST', '/api/rules', { category, mac, name });
    if (r.success) {
        state.rules = r.rules;
        renderRulesTable();
        closeModal('modalAddRule');
        document.getElementById('ruleMAC').value  = '';
        document.getElementById('ruleName').value = '';
        toast('Rule saved', 'success');
    } else toast(r.error, 'error');
});

// ─── Settings ─────────────────────────────────────────────────
async function loadSettings() {
    const r = await api('GET', '/api/interfaces');
    const sel = document.getElementById('settingInterface');
    sel.innerHTML = (r.interfaces||[]).map(i =>
        `<option value="${i}" ${i===state.interface?'selected':''}>${i}</option>`
    ).join('');
    document.getElementById('settingRouter').value = state.router_ip || r.default_gateway || '';
    document.getElementById('settingLimit').value  = state.limit_mbps;
    document.getElementById('settingMode').value   = 'blacklist';
}

document.getElementById('btnSaveNetworkSettings')?.addEventListener('click', () => {
    state.interface = document.getElementById('settingInterface').value;
    state.router_ip = document.getElementById('settingRouter').value.trim();
    toast('Settings saved', 'success');
});

document.getElementById('btnApplyLimit')?.addEventListener('click', async () => {
    const lim = parseFloat(document.getElementById('settingLimit').value);
    if (!lim || lim <= 0) { toast('Enter a valid limit', 'error'); return; }
    const r = await api('POST', '/api/session/limit', { limit_mbps: lim });
    if (r.success) { state.limit_mbps = lim; toast(`Limit updated to ${lim} Mbps`, 'success'); }
    else toast(r.error, 'error');
});

document.querySelectorAll('.preset-btn:not(.modal-preset)').forEach(btn => {
    btn.addEventListener('click', () => {
        document.getElementById('settingLimit').value = btn.dataset.val;
    });
});

// ─── Telemetry Polling ────────────────────────────────────────
setInterval(async () => {
    if (state.status !== 'RUNNING') return;
    try {
        const r = await api('GET', '/api/telemetry');
        if (r.success) {
            state.telemetry = r.telemetry || {};
            updateMetrics(r);
            renderTargetsTable();
        }
    } catch {}
}, 1000);

// ─── Init ─────────────────────────────────────────────────────
(async () => {
    const r = await api('GET', '/api/status');
    if (r.success) applyState(r.data);
    await loadSettings();
})();
