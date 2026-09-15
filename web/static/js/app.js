/**
 * Throttwin Web UI Client Application — Multi-Interface Edition
 * Manages multiple simultaneous sessions across different network interfaces.
 * Each session has independent devices, targets, telemetry, and controls.
 */

class ThrottwinApp {
    constructor() {
        // Multi-session state: keyed by session_id (interface name)
        this.sessions = {};         // {session_id: sessionState}
        this.activeSessionId = null;
        this.sessionIds = [];

        // Shared state
        this.rules = { whitelist: {}, blacklist: {} };
        this.availableInterfaces = [];

        this.eventSource = null;
        this.timerInterval = null;
        this.isScanning = false;

        this.init();
    }

    // ─── Session State Helpers ────────────────────────────────────────────

    _defaultSessionState(sessionId) {
        return {
            session_id: sessionId,
            status: "IDLE",
            link_status: "ONLINE",
            mode: "blacklist",
            limit_mbps: 1.0,
            interface: sessionId,
            router_ip: null,
            devices: [],
            targets: [],
            whitelisted: [],
            telemetry: [],
            uptime: 0,
            autoThrottledCount: 0,
            selectedIps: new Set(),
        };
    }

    getActiveSession() {
        if (this.activeSessionId && this.sessions[this.activeSessionId]) {
            return this.sessions[this.activeSessionId];
        }
        // Fallback to first session
        const first = Object.keys(this.sessions)[0];
        if (first) {
            this.activeSessionId = first;
            return this.sessions[first];
        }
        return this._defaultSessionState("none");
    }

    _ensureSession(sid) {
        if (!this.sessions[sid]) {
            this.sessions[sid] = this._defaultSessionState(sid);
        }
        return this.sessions[sid];
    }

    // ─── Init ─────────────────────────────────────────────────────────────

    async init() {
        this.bindEvents();
        await this.loadInterfaces();
        await this.loadRules();
        await this.fetchStatus();
        this.initSSE();
        this.startLocalTimer();
    }


    /* ==========================================================
       1. SERVER-SENT EVENTS (SSE) STREAMING
       ========================================================== */
    initSSE() {
        if (this.eventSource) {
            this.eventSource.close();
        }

        const badge = document.getElementById('liveConnectionBadge');
        this.eventSource = new EventSource('/api/stream');

        this.eventSource.onopen = () => {
            if (badge) {
                badge.innerHTML = `<span class="status-dot"></span><span class="status-text">SSE Live Stream</span>`;
            }
        };

        this.eventSource.onmessage = (event) => {
            try {
                const payload = JSON.parse(event.data);
                this.handleSSEEvent(payload);
            } catch (e) {
                // Keepalive heartbeat
            }
        };

        this.eventSource.onerror = () => {
            if (badge) {
                badge.innerHTML = `<span class="status-dot" style="background: var(--accent-amber); box-shadow: 0 0 10px var(--accent-amber);"></span><span class="status-text">Reconnecting...</span>`;
            }
        };
    }

    handleSSEEvent(payload) {
        const type = payload.type;
        const data = payload.data || payload.state || {};
        const sid = data.session_id;

        switch (type) {
            case "init":
                // Multi-session init
                if (payload.sessions) {
                    this.sessionIds = payload.session_ids || Object.keys(payload.sessions);
                    for (const [id, state] of Object.entries(payload.sessions)) {
                        this._ensureSession(id);
                        this._mergeSessionState(id, state);
                    }
                    if (!this.activeSessionId && this.sessionIds.length) {
                        this.activeSessionId = this.sessionIds[0];
                    }
                    this.renderSessionTabs();
                    this.updateActiveSessionUI();

                    // Auto-trigger scan for empty sessions
                    const active = this.getActiveSession();
                    if (!active.devices || active.devices.length === 0) {
                        this.triggerScan();
                    }
                }
                break;

            case "interfaces_updated":
                if (data.interfaces_full) {
                    this.availableInterfaces = data.interfaces_full;
                }
                if (data.sessions) {
                    this.sessionIds = data.session_ids || Object.keys(data.sessions);
                    for (const [id, state] of Object.entries(data.sessions)) {
                        this._ensureSession(id);
                        this._mergeSessionState(id, state);
                    }
                    this.renderSessionTabs();
                }
                break;

            case "interface_status_changed":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    const oldLink = sess.link_status;
                    sess.link_status = data.link_status;
                    if (data.router_ip) sess.router_ip = data.router_ip;
                    if (data.state) this._mergeSessionState(sid, data.state);

                    if (oldLink !== data.link_status) {
                        if (data.link_status === "DISCONNECTED") {
                            this.showToast(`⚠️ [${sid}] Interface disconnected / link lost!`, 'error');
                        } else if (data.link_status === "ONLINE") {
                            this.showToast(`🌐 [${sid}] Interface connected & online!`, 'success');
                        }
                    }
                    this.renderSessionTabs();
                    if (sid === this.activeSessionId) this.updateActiveSessionUI();
                }
                break;

            case "session_reconnected":
                if (sid) {
                    this._mergeSessionState(sid, data);
                    const sess = this._ensureSession(sid);
                    sess.link_status = "ONLINE";
                    this.showToast(`⚡ [${sid}] Session auto-rebound and resumed after reconnect!`, 'success');
                    this.renderSessionTabs();
                    if (sid === this.activeSessionId) this.updateActiveSessionUI();
                }
                break;

            case "devices_discovered":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    if (data.all_devices) sess.devices = data.all_devices;
                    if (data.new_devices && data.new_devices.length) {
                        const label = sid === this.activeSessionId ? '' : ` [${sid}]`;
                        this.showToast(`📡 Discovered ${data.new_devices.length} new device(s)${label}`, 'info');
                    }
                    if (sid === this.activeSessionId) {
                        this.renderDashboardTable();
                        this.renderScannerTable();
                    }
                    this.renderSessionTabs();
                }
                break;

            case "device_auto_throttled":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    sess.autoThrottledCount += 1;
                    const dev = data.device || {};
                    const limit = data.limit_mbps || sess.limit_mbps;
                    this.showToast(`⚡ AUTO-THROTTLED [${sid}]: ${dev.ip || 'Device'} (${dev.vendor || dev.mac || 'Unknown'}) capped at ${limit} Mbps!`, 'error');
                    if (sid === this.activeSessionId) {
                        this.updateRadarBanner();
                        this.fetchSessionStatus(sid);
                    }
                    this.renderSessionTabs();
                }
                break;

            case "devices_updated":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    if (data.devices) sess.devices = data.devices;
                    if (sid === this.activeSessionId) {
                        this.renderDashboardTable();
                        this.renderScannerTable();
                    }
                }
                break;

            case "target_toggled":
                if (data.state && sid) {
                    this._mergeSessionState(sid, data.state);
                    if (sid === this.activeSessionId) this.updateActiveSessionUI();
                    this.showToast(`Target ${data.ip} ${data.throttled ? 'throttling activated' : 'throttling removed'} [${sid}]`, data.throttled ? 'success' : 'info');
                    this.renderSessionTabs();
                }
                break;

            case "limit_updated":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    sess.limit_mbps = data.limit_mbps;
                    if (sid === this.activeSessionId) {
                        document.getElementById('statBandwidthLimit').innerHTML = `${sess.limit_mbps} <span class="unit">Mbps</span>`;
                        const radarLimit = document.getElementById('radarLimitVal');
                        if (radarLimit) radarLimit.textContent = sess.limit_mbps;
                    }
                    this.showToast(`⚡ Limit adjusted to ${data.limit_mbps} Mbps [${sid}]`, 'success');
                }
                break;

            case "session_started":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    sess.autoThrottledCount = 0;
                    this._mergeSessionState(sid, data);
                    if (sid === this.activeSessionId) this.updateActiveSessionUI();
                    this.renderSessionTabs();
                    this.showToast(`🚀 Session ACTIVE on ${sid}`, 'success');
                }
                break;

            case "session_stopped":
                if (sid) {
                    this._mergeSessionState(sid, data);
                    const sess = this._ensureSession(sid);
                    sess.autoThrottledCount = 0;
                    if (sid === this.activeSessionId) this.updateActiveSessionUI();
                    this.renderSessionTabs();
                    this.showToast(`🛑 Session stopped on ${sid}`, 'info');
                }
                break;

            case "session_created":
                if (sid && !this.sessions[sid]) {
                    this._ensureSession(sid);
                    if (!this.sessionIds.includes(sid)) this.sessionIds.push(sid);
                    this.renderSessionTabs();
                    this.showToast(`➕ New session created: ${sid}`, 'success');
                }
                break;

            case "session_deleted":
                if (sid && this.sessions[sid]) {
                    delete this.sessions[sid];
                    this.sessionIds = this.sessionIds.filter(id => id !== sid);
                    if (this.activeSessionId === sid) {
                        this.activeSessionId = this.sessionIds[0] || null;
                    }
                    this.renderSessionTabs();
                    if (this.activeSessionId) this.updateActiveSessionUI();
                    this.showToast(`🗑 Session removed: ${sid}`, 'info');
                }
                break;

            case "cache_cleared":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    sess.devices = [];
                    sess.selectedIps.clear();
                    if (sid === this.activeSessionId) {
                        this.renderDashboardTable();
                        this.renderScannerTable();
                    }
                }
                break;
        }
    }

    _mergeSessionState(sid, state) {
        const sess = this._ensureSession(sid);
        if (state.status) sess.status = state.status;
        if (state.link_status) sess.link_status = state.link_status;
        if (state.devices) sess.devices = state.devices;
        if (state.targets) sess.targets = state.targets;
        if (state.whitelisted) sess.whitelisted = state.whitelisted;
        if (state.telemetry) sess.telemetry = state.telemetry;
        if (state.uptime !== undefined) sess.uptime = state.uptime;
        if (state.limit_mbps) sess.limit_mbps = state.limit_mbps;
        if (state.operational_mode) sess.mode = state.operational_mode;
        if (state.interface) sess.interface = state.interface;
        if (state.router_ip) sess.router_ip = state.router_ip;
    }


    /* ==========================================================
       2. EVENT BINDINGS
       ========================================================== */
    bindEvents() {
        // Tab Navigation
        document.querySelectorAll('.nav-item').forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.dataset.tab;
                this.switchTab(targetTab);
            });
        });

        // Mode Toggles
        const btnBl = document.getElementById('btnModeBlacklist');
        const btnWl = document.getElementById('btnModeWhitelist');
        if (btnBl) btnBl.addEventListener('click', () => this.setMode('blacklist'));
        if (btnWl) btnWl.addEventListener('click', () => this.setMode('whitelist'));

        // Speed Preset Pills
        document.querySelectorAll('.preset-pill').forEach(pill => {
            pill.addEventListener('click', () => {
                document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                const customInp = document.getElementById('customSpeedInput');
                if (customInp) customInp.value = '';
                const newLimit = parseFloat(pill.dataset.speed);
                this.handleLimitSelection(newLimit);
            });
        });

        // Custom Speed Input
        const customInput = document.getElementById('customSpeedInput');
        if (customInput) {
            customInput.addEventListener('input', (e) => {
                const val = parseFloat(e.target.value);
                if (val > 0) {
                    document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));
                    this.handleLimitSelection(val);
                }
            });
        }

        // Live Apply Button
        const btnApplyLive = document.getElementById('btnApplyLiveLimit');
        if (btnApplyLive) btnApplyLive.addEventListener('click', () => this.applyLiveLimit());

        // Session Control Button
        const btnSession = document.getElementById('btnSessionControl');
        if (btnSession) btnSession.addEventListener('click', () => this.toggleSession());

        // Rescan and Add Device Buttons
        const btnRescanTop = document.getElementById('btnRescanTop');
        if (btnRescanTop) btnRescanTop.addEventListener('click', () => this.triggerScan());

        const btnScanTab = document.getElementById('btnScanDevicesTab');
        if (btnScanTab) btnScanTab.addEventListener('click', () => this.triggerScan());

        const btnManualTop = document.getElementById('btnManualAddTop');
        if (btnManualTop) btnManualTop.addEventListener('click', () => this.openModal('manualDeviceModal'));

        const btnManualTab = document.getElementById('btnManualDeviceTab');
        if (btnManualTab) btnManualTab.addEventListener('click', () => this.openModal('manualDeviceModal'));

        const btnClearTab = document.getElementById('btnClearCacheTab');
        if (btnClearTab) btnClearTab.addEventListener('click', () => this.clearCache());

        // Submit Manual Device
        const btnSubMan = document.getElementById('btnSubmitManualDevice');
        if (btnSubMan) btnSubMan.addEventListener('click', () => this.submitManualDevice());

        // Submit Rule
        const btnSubRule = document.getElementById('btnSubmitRule');
        if (btnSubRule) btnSubRule.addEventListener('click', () => this.submitRule());

        // Save Settings & Auto Detect
        const btnSaveSet = document.getElementById('btnSaveSettings');
        if (btnSaveSet) btnSaveSet.addEventListener('click', () => this.saveSettings());

        const btnAutoDetectSet = document.getElementById('btnAutoDetectSettings');
        if (btnAutoDetectSet) {
            btnAutoDetectSet.addEventListener('click', async () => {
                await this.loadInterfaces(false);
                await this.renderSettings(true);
            });
        }

        const btnResetSet = document.getElementById('btnResetAutoSettings');
        if (btnResetSet) {
            btnResetSet.addEventListener('click', async () => {
                await this.loadInterfaces(false);
                await this.renderSettings(false);
                const disc = document.getElementById('settingDiscoveryInterval');
                if (disc) disc.value = '8';
                const mode = document.getElementById('settingDefaultMode');
                if (mode) mode.value = 'blacklist';
                this.showToast('Reset settings to auto-detected system defaults.', 'info');
            });
        }

        // Select All Checkbox
        const selectAllCb = document.getElementById('selectAllCheckbox');
        if (selectAllCb) {
            selectAllCb.addEventListener('change', (e) => {
                const isChecked = e.target.checked;
                const sess = this.getActiveSession();
                document.querySelectorAll('.device-row-check').forEach(cb => {
                    cb.checked = isChecked;
                    const ip = cb.dataset.ip;
                    if (isChecked) {
                        sess.selectedIps.add(ip);
                    } else {
                        sess.selectedIps.delete(ip);
                    }
                });
            });
        }

        // Add Session Button
        const btnAddSession = document.getElementById('btnAddSession');
        if (btnAddSession) btnAddSession.addEventListener('click', () => this.openAddSessionModal());

        // Submit Add Session
        const btnSubmitAddSession = document.getElementById('btnSubmitAddSession');
        if (btnSubmitAddSession) btnSubmitAddSession.addEventListener('click', () => this.submitAddSession());

        // Auto-detect gateway when selecting interface in add-session modal
        const addSessionIface = document.getElementById('addSessionInterface');
        if (addSessionIface) {
            addSessionIface.addEventListener('change', async (e) => {
                const iface = e.target.value;
                try {
                    const res = await fetch(`/api/interfaces?interface=${encodeURIComponent(iface)}`);
                    const data = await res.json();
                    if (data.success && data.default_gateway) {
                        document.getElementById('addSessionGateway').value = data.default_gateway;
                    }
                } catch (ex) {}
            });
        }
    }


    handleLimitSelection(newLimit) {
        const sess = this.getActiveSession();
        sess.limit_mbps = newLimit;
        const statLim = document.getElementById('statBandwidthLimit');
        if (statLim) statLim.innerHTML = `${newLimit} <span class="unit">Mbps</span>`;
        const radarLim = document.getElementById('radarLimitVal');
        if (radarLim) radarLim.textContent = newLimit;

        const btnApplyLive = document.getElementById('btnApplyLiveLimit');
        if (btnApplyLive) {
            btnApplyLive.style.display = sess.status === "RUNNING" ? 'inline-flex' : 'none';
        }
    }

    async applyLiveLimit() {
        const sess = this.getActiveSession();
        try {
            const res = await fetch('/api/session/limit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ limit_mbps: sess.limit_mbps, session_id: sess.session_id })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast(`Applied limit: ${sess.limit_mbps} Mbps live on ${sess.session_id}!`, 'success');
                const btnApplyLive = document.getElementById('btnApplyLiveLimit');
                if (btnApplyLive) btnApplyLive.style.display = 'none';
            } else {
                this.showToast(data.error || 'Failed to update live limit.', 'error');
            }
        } catch (e) {
            this.showToast('Error applying live limit.', 'error');
        }
    }

    switchTab(tabId) {
        document.querySelectorAll('.nav-item').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabId);
        });
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.toggle('active', pane.id === `pane-${tabId}`);
        });

        if (tabId === 'devices') {
            this.renderScannerTable();
        } else if (tabId === 'rules') {
            this.renderRules();
        } else if (tabId === 'settings') {
            this.renderSettings();
        } else if (tabId === 'dashboard') {
            this.renderDashboardTable();
        }
    }

    setMode(mode) {
        const sess = this.getActiveSession();
        sess.mode = mode;
        const btnBl = document.getElementById('btnModeBlacklist');
        const btnWl = document.getElementById('btnModeWhitelist');
        if (btnBl) btnBl.classList.toggle('active', mode === 'blacklist');
        if (btnWl) btnWl.classList.toggle('active', mode === 'whitelist');
        const subtitle = document.getElementById('statModeSubtitle');
        if (subtitle) subtitle.textContent = `Mode: ${mode.charAt(0).toUpperCase() + mode.slice(1)}`;

        sess.selectedIps.clear();
        this.updateRadarBanner();
        this.renderDashboardTable();
    }

    updateRadarBanner() {
        const banner = document.getElementById('dynamicRadarBanner');
        if (!banner) return;
        const sess = this.getActiveSession();

        if (sess.status === "RUNNING" && sess.mode === "whitelist") {
            banner.style.display = 'flex';
            const radarLim = document.getElementById('radarLimitVal');
            const radarCount = document.getElementById('radarThrottledCount');
            if (radarLim) radarLim.textContent = sess.limit_mbps;
            if (radarCount) radarCount.textContent = sess.autoThrottledCount;
        } else {
            banner.style.display = 'none';
        }
    }


    /* ==========================================================
       3. SESSION TABS
       ========================================================== */
    renderSessionTabs() {
        const container = document.getElementById('sessionTabsList');
        const tabsBar = document.getElementById('sessionTabsBar');
        if (!container || !tabsBar) return;

        container.innerHTML = '';

        const ids = this.sessionIds.length ? this.sessionIds : Object.keys(this.sessions);

        ids.forEach(sid => {
            const sess = this.sessions[sid];
            if (!sess) return;

            const tab = document.createElement('button');
            tab.className = `session-tab ${sid === this.activeSessionId ? 'active' : ''}`;
            tab.dataset.sessionId = sid;

            let statusClass = sess.status === 'RUNNING' ? 'running' : 'idle';
            let statusLabel = sess.status === 'RUNNING' ? 'ACTIVE' : 'IDLE';
            if (sess.link_status === 'DISCONNECTED') {
                statusClass = 'disconnected';
                statusLabel = 'DISCONNECTED';
            }
            const subnet = sess.router_ip ? sess.router_ip.split('.').slice(0, 3).join('.') + '.x' : '—';
            const targetCount = (sess.targets || []).length;
            const deviceCount = (sess.devices || []).length;

            tab.innerHTML = `
                <div class="session-tab-status ${statusClass}"></div>
                <div class="session-tab-info">
                    <span class="session-tab-name">${sid}</span>
                    <span class="session-tab-subnet">${subnet} · ${deviceCount} dev${deviceCount !== 1 ? 's' : ''}</span>
                </div>
                <span class="session-tab-badge ${statusClass}">${statusLabel}${targetCount > 0 ? ` (${targetCount})` : ''}</span>
                ${ids.length > 1 && sess.status !== 'RUNNING' ? `<button class="session-tab-close" data-close-session="${sid}" title="Remove session">&times;</button>` : ''}
            `;

            tab.addEventListener('click', (e) => {
                if (e.target.classList.contains('session-tab-close')) {
                    e.stopPropagation();
                    this.deleteSession(e.target.dataset.closeSession);
                    return;
                }
                this.switchSession(sid);
            });

            container.appendChild(tab);
        });

        // Show/hide tab bar
        tabsBar.style.display = 'flex';
    }

    switchSession(sid) {
        if (sid === this.activeSessionId) return;
        this.activeSessionId = sid;
        this.renderSessionTabs();
        this.updateActiveSessionUI();
        this.renderScannerTable();
        this.renderSettings();

        // Auto-scan if empty
        const sess = this.getActiveSession();
        if (!sess.devices || sess.devices.length === 0) {
            this.triggerScan();
        }
    }

    updateActiveSessionUI() {
        const sess = this.getActiveSession();

        // Update Session Status Pill & Control Button
        const pill = document.getElementById('sessionStatusPill');
        const text = document.getElementById('sessionStatusText');
        const btn = document.getElementById('btnSessionControl');
        const timer = document.getElementById('sessionTimer');
        const btnApplyLive = document.getElementById('btnApplyLiveLimit');

        if (sess.status === "RUNNING") {
            if (pill) pill.className = 'session-status-pill running';
            if (text) text.textContent = `${sess.session_id}: ACTIVE`;
            if (btn) {
                btn.className = 'btn btn-danger btn-glow';
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-stop"></i> <span>Stop Session</span>';
            }
            if (timer) timer.style.display = 'flex';
        } else {
            if (pill) pill.className = 'session-status-pill idle';
            if (text) text.textContent = `${sess.session_id}: IDLE`;
            if (btn) {
                btn.className = 'btn btn-primary btn-glow';
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-play"></i> <span>Start Session</span>';
            }
            if (timer) timer.style.display = 'none';
            if (btnApplyLive) btnApplyLive.style.display = 'none';
        }

        // Mode Pill Sync
        const btnBl = document.getElementById('btnModeBlacklist');
        const btnWl = document.getElementById('btnModeWhitelist');
        if (btnBl) btnBl.classList.toggle('active', sess.mode === 'blacklist');
        if (btnWl) btnWl.classList.toggle('active', sess.mode === 'whitelist');
        const subtitle = document.getElementById('statModeSubtitle');
        if (subtitle) subtitle.textContent = `Mode: ${sess.mode.charAt(0).toUpperCase() + sess.mode.slice(1)}`;

        // Metrics
        const statThroughput = document.getElementById('statThroughput');
        if (statThroughput) statThroughput.innerHTML = `${sess.status === 'RUNNING' ? (sess._totalSpeedKbps || '0.0') : '0.0'} <span class="unit">KB/s</span>`;
        const statThroughputMbps = document.getElementById('statThroughputMbps');
        if (statThroughputMbps) statThroughputMbps.textContent = `${sess.status === 'RUNNING' ? (sess._totalSpeedMbps || '0.00') : '0.00'} Mbps total speed`;
        const statTargetCount = document.getElementById('statTargetCount');
        if (statTargetCount) statTargetCount.textContent = (sess.targets || []).length;
        const statLimit = document.getElementById('statBandwidthLimit');
        if (statLimit) statLimit.innerHTML = `${sess.limit_mbps} <span class="unit">Mbps</span>`;
        const statData = document.getElementById('statDataTransferred');
        if (statData) statData.innerHTML = `${sess._totalDataMb || '0.00'} <span class="unit">MB</span>`;

        this.updateRadarBanner();
        this.renderDashboardTable();
    }


    async loadInterfaces(showToastFeedback = false) {
        try {
            const res = await fetch('/api/interfaces');
            const data = await res.json();
            if (data.success) {
                this.availableInterfaces = data.interfaces_full || [];

                const select = document.getElementById('settingInterface');
                if (select) {
                    select.innerHTML = '';
                    (data.interfaces || []).forEach(iface => {
                        const opt = document.createElement('option');
                        opt.value = iface;
                        opt.textContent = iface;
                        if (iface === data.default_interface) opt.selected = true;
                        select.appendChild(opt);
                    });
                }

                const routerInp = document.getElementById('settingRouterIp');
                if (routerInp && data.default_gateway) routerInp.value = data.default_gateway;

                if (showToastFeedback) {
                    this.showToast(`Auto-detected interface: ${data.default_interface} (Gateway: ${data.default_gateway})`, 'success');
                }
            }
        } catch (e) {
            console.error("Failed to load interfaces:", e);
        }
    }

    async autoDetectGateway(iface, showToastFeedback = false) {
        try {
            const url = iface ? `/api/interfaces?interface=${encodeURIComponent(iface)}` : '/api/interfaces';
            const res = await fetch(url);
            const data = await res.json();
            if (data.success && data.default_gateway) {
                const routerInp = document.getElementById('settingRouterIp');
                if (routerInp) routerInp.value = data.default_gateway;
                if (showToastFeedback) {
                    this.showToast(`Auto-detected Gateway: ${data.default_gateway} on ${iface || data.default_interface}`, 'success');
                }
            }
        } catch (e) {
            if (showToastFeedback) {
                this.showToast('Failed to auto-detect gateway.', 'error');
            }
        }
    }


    async loadRules() {
        try {
            const res = await fetch('/api/rules');
            const data = await res.json();
            if (data.success) {
                this.rules = data.rules;
                this.renderRules();
            }
        } catch (e) {
            console.error("Failed to load rules:", e);
        }
    }

    async fetchStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            if (data.success) {
                // Multi-session aware
                if (data.sessions) {
                    this.sessionIds = data.session_ids || Object.keys(data.sessions);
                    for (const [id, state] of Object.entries(data.sessions)) {
                        this._ensureSession(id);
                        this._mergeSessionState(id, state);
                    }
                    if (!this.activeSessionId && this.sessionIds.length) {
                        this.activeSessionId = this.sessionIds[0];
                    }
                    this.renderSessionTabs();
                    this.updateActiveSessionUI();
                } else if (data.data) {
                    // Legacy single-session fallback
                    const sid = data.data.session_id || data.data.interface || 'default';
                    this._ensureSession(sid);
                    this._mergeSessionState(sid, data.data);
                    if (!this.activeSessionId) this.activeSessionId = sid;
                    this.renderSessionTabs();
                    this.updateActiveSessionUI();
                }
            }
        } catch (e) {
            console.error("Failed to fetch status:", e);
        }
    }

    async fetchSessionStatus(sid) {
        try {
            const res = await fetch(`/api/status?session_id=${encodeURIComponent(sid)}`);
            const data = await res.json();
            if (data.success && data.data) {
                this._mergeSessionState(sid, data.data);
                if (sid === this.activeSessionId) this.updateActiveSessionUI();
            }
        } catch (e) {}
    }


    /* ==========================================================
       4. DASHBOARD & LIVE TELEMETRY RENDERING
       ========================================================== */
    renderDashboardTable() {
        const tbody = document.getElementById('devicesTableBody');
        if (!tbody) return;

        const sess = this.getActiveSession();

        if (!sess.devices.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="empty-state">
                        <i class="fa-solid fa-satellite-dish fa-2x"></i>
                        <p>No active network devices detected. Click "Scan" or "Add Device" above.</p>
                    </td>
                </tr>`;
            return;
        }

        const teleMap = {};
        (sess.telemetry || []).forEach(t => {
            teleMap[t.ip] = t;
        });

        const runningTargetIps = new Set(
            (sess.targets || []).map(t => (typeof t === 'string' ? t : t.ip))
        );

        const globalWl = this.rules.whitelist || {};
        const globalBl = this.rules.blacklist || {};

        const isRunning = sess.status === "RUNNING";
        tbody.innerHTML = '';

        sess.devices.forEach(dev => {
            const tr = document.createElement('tr');
            const macLower = (dev.mac || '').toLowerCase();
            const ip = dev.ip || '-';

            const isGlobalWl = macLower in globalWl;
            const isGlobalBl = macLower in globalBl;
            const wlLabel = globalWl[macLower];
            const blLabel = globalBl[macLower];

            const isCurrentlyThrottled = runningTargetIps.has(ip);

            let isChecked = sess.selectedIps.has(ip);
            if (!isRunning && !sess.selectedIps.size) {
                if (sess.mode === "blacklist" && isGlobalBl) isChecked = true;
                if (sess.mode === "whitelist" && isGlobalWl) isChecked = true;
                if (isChecked) sess.selectedIps.add(ip);
            }

            // Rule Badge
            let badgeHtml = '<span class="text-muted">-</span>';
            if (isGlobalWl) {
                badgeHtml = `<span class="badge badge-whitelist"><i class="fa-solid fa-shield"></i> Safe ${wlLabel ? `(${wlLabel})` : ''}</span>`;
            } else if (isGlobalBl) {
                badgeHtml = `<span class="badge badge-blacklist"><i class="fa-solid fa-skull"></i> Target ${blLabel ? `(${blLabel})` : ''}</span>`;
            }

            // Telemetry
            const tele = teleMap[ip];
            let speedHtml = '<span class="text-muted">0.0 KB/s</span>';
            let onlineDot = '<span class="status-dot-sm offline" title="Offline / Idle"></span>';
            let newBadge = '';

            if (isRunning && isCurrentlyThrottled) {
                const speedKbps = tele ? tele.speed_kbps : 0.0;
                const speedMbps = tele ? tele.speed_mbps : 0.00;
                const maxCapKbps = (sess.limit_mbps * 125.0);
                const pct = Math.min(Math.round((speedKbps / Math.max(maxCapKbps, 1)) * 100), 100);

                const isOnline = tele ? tele.is_online : true;
                onlineDot = isOnline
                    ? '<span class="status-dot-sm online" title="Online & Active"></span>'
                    : '<span class="status-dot-sm offline" title="Probing / Offline"></span>';

                if (tele && tele.is_new) {
                    newBadge = '<span class="badge-pulse-glow"><i class="fa-solid fa-bolt"></i> AUTO-TRAPPED</span>';
                    tr.classList.add('row-new-target');
                }

                speedHtml = `
                    <div class="live-speed-cell">
                        <div class="speed-text-row">
                            <span class="device-speed-pill">${speedKbps} KB/s</span>
                            <span class="speed-mbps-text">${speedMbps} MB/s (${pct}%)</span>
                        </div>
                        <div class="speed-meter-track">
                            <div class="speed-meter-bar" style="width: ${pct}%;"></div>
                        </div>
                    </div>
                `;
            }

            // Status Column
            let statusToggleHtml = '';
            if (isRunning) {
                if (isGlobalWl) {
                    statusToggleHtml = `
                        <div class="hot-toggle-wrap">
                            <span class="badge badge-whitelist"><i class="fa-solid fa-shield-check"></i> SAFE (IMMUNE)</span>
                        </div>
                    `;
                } else {
                    statusToggleHtml = `
                        <div class="hot-toggle-wrap">
                            ${onlineDot}
                            <label class="switch-toggle" title="Click to hot-toggle throttling for this target">
                                <input type="checkbox" class="hot-toggle-cb" data-ip="${ip}" ${isCurrentlyThrottled ? 'checked' : ''}>
                                <span class="slider round"></span>
                            </label>
                            ${isCurrentlyThrottled ? '<span class="label-throttled">THROTTLED</span>' : '<span class="label-bypassed">BYPASSED</span>'}
                            ${newBadge}
                        </div>
                    `;
                }
            } else {
                if (sess.mode === "whitelist") {
                    statusToggleHtml = isGlobalWl || isChecked
                        ? `<span class="badge badge-whitelist"><i class="fa-solid fa-shield"></i> Safe / Whitelisted</span>`
                        : `<span class="badge badge-blacklist"><i class="fa-solid fa-crosshairs"></i> Will Throttle</span>`;
                } else {
                    statusToggleHtml = isChecked
                        ? `<span class="badge badge-blacklist"><i class="fa-solid fa-crosshairs"></i> Target</span>`
                        : `<span class="badge badge-idle">Idle</span>`;
                }
            }

            // Hostname & Vendor
            let nameHtml = '';
            if (dev.hostname) {
                nameHtml = `
                    <div class="device-name-col">
                        <span class="device-hostname" title="${dev.hostname}">${dev.hostname}</span>
                        <span class="device-vendor-sub" title="${dev.vendor || 'Unknown'}">${dev.vendor || 'Unknown'}</span>
                    </div>
                `;
            } else {
                nameHtml = `<div class="device-name-col"><span class="device-vendor-only" title="${dev.vendor || 'Unknown'}">${dev.vendor || 'Unknown'}</span></div>`;
            }

            tr.innerHTML = `
                <td>
                    <input type="checkbox" class="custom-checkbox device-row-check" data-ip="${ip}" ${isChecked ? 'checked' : ''} ${isRunning ? 'disabled' : ''}>
                </td>
                <td>${statusToggleHtml}</td>
                <td class="device-ip">${ip}</td>
                <td class="device-mac">${dev.mac || 'Unknown'}</td>
                <td>${nameHtml}</td>
                <td>${badgeHtml}</td>
                <td>${speedHtml}</td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="app.quickAddToRule('${macLower}', '${(dev.vendor || '').replace(/'/g, "\\'")}')" title="Add to global rules">
                        <i class="fa-solid fa-shield-halved"></i>
                    </button>
                </td>
            `;

            // Checkbox handler
            const cb = tr.querySelector('.device-row-check');
            if (cb) {
                cb.addEventListener('change', (e) => {
                    if (e.target.checked) {
                        sess.selectedIps.add(ip);
                    } else {
                        sess.selectedIps.delete(ip);
                    }
                    if (!isRunning) {
                        this.renderDashboardTable();
                    }
                });
            }

            // Live Hot-Toggle Switch handler
            const toggleCb = tr.querySelector('.hot-toggle-cb');
            if (toggleCb) {
                toggleCb.addEventListener('change', (e) => {
                    this.hotToggleTarget(ip, e.target.checked);
                });
            }

            tbody.appendChild(tr);
        });
    }

    async hotToggleTarget(ip, shouldThrottle) {
        const sess = this.getActiveSession();
        try {
            const res = await fetch('/api/target/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, should_throttle: shouldThrottle, session_id: sess.session_id })
            });
            const data = await res.json();
            if (data.success) {
                this._mergeSessionState(sess.session_id, data.state);
                this.updateActiveSessionUI();
                this.showToast(data.message, shouldThrottle ? 'success' : 'info');
            } else {
                this.showToast(data.error || 'Failed to toggle target.', 'error');
                this.renderDashboardTable();
            }
        } catch (e) {
            this.showToast('Network error during target toggle.', 'error');
            this.renderDashboardTable();
        }
    }

    renderScannerTable() {
        const tbody = document.getElementById('scannerTableBody');
        const statusBanner = document.getElementById('scannerStatusBanner');
        const statusText = document.getElementById('scannerStatusText');
        const titleText = document.getElementById('scannerTitleText');
        if (!tbody) return;
        const sess = this.getActiveSession();
        const subnet = sess.router_ip ? sess.router_ip.split('.').slice(0, 3).join('.') + '.x' : (sess.interface || '—');

        if (titleText) {
            titleText.innerHTML = `Discovered Network Devices &mdash; <span style="color: var(--accent-cyan); font-family: var(--font-mono); font-weight: 600;">${sess.session_id}</span> <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">(${subnet})</span>`;
        }
        if (statusText) {
            statusText.textContent = `[${sess.session_id}] ${sess.devices.length} device(s) online on subnet ${subnet}.`;
        }

        if (!sess.devices.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><p>No devices discovered yet for ${sess.session_id}. Click "Rescan Network" above.</p></td></tr>`;
            return;
        }

        tbody.innerHTML = '';
        sess.devices.forEach(dev => {
            const tr = document.createElement('tr');
            let nameHtml = '';
            if (dev.hostname) {
                nameHtml = `
                    <div class="device-name-col">
                        <span class="device-hostname" title="${dev.hostname}">${dev.hostname}</span>
                        <span class="device-vendor-sub" title="${dev.vendor || 'Unknown'}">${dev.vendor || 'Unknown'}</span>
                    </div>
                `;
            } else {
                nameHtml = `<div class="device-name-col"><span class="device-vendor-only" title="${dev.vendor || 'Unknown'}">${dev.vendor || 'Unknown'}</span></div>`;
            }

            tr.innerHTML = `
                <td class="device-ip">${dev.ip || '-'}</td>
                <td class="device-mac">${dev.mac || 'Unknown'}</td>
                <td>${nameHtml}</td>
                <td><span class="badge badge-new"><i class="fa-solid fa-wifi"></i> Active</span></td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="app.quickAddToRule('${dev.mac || ''}', '${(dev.vendor || '').replace(/'/g, "\\'")}')">
                        <i class="fa-solid fa-plus"></i> Rule
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    renderRules() {
        const wlContainer = document.getElementById('whitelistRulesContainer');
        const blContainer = document.getElementById('blacklistRulesContainer');

        if (!wlContainer || !blContainer) return;

        const wl = this.rules.whitelist || {};
        const bl = this.rules.blacklist || {};

        if (!Object.keys(wl).length) {
            wlContainer.innerHTML = '<div class="empty-state"><p>No global whitelist rules configured.</p></div>';
        } else {
            wlContainer.innerHTML = Object.entries(wl).map(([mac, name]) => `
                <div class="rule-item">
                    <div>
                        <div class="rule-mac">${mac}</div>
                        <div class="rule-name">${name || 'No label'}</div>
                    </div>
                    <button class="btn-icon-delete" onclick="app.deleteRule('whitelist', '${mac}')" title="Delete rule">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `).join('');
        }

        if (!Object.keys(bl).length) {
            blContainer.innerHTML = '<div class="empty-state"><p>No global blacklist rules configured.</p></div>';
        } else {
            blContainer.innerHTML = Object.entries(bl).map(([mac, name]) => `
                <div class="rule-item">
                    <div>
                        <div class="rule-mac">${mac}</div>
                        <div class="rule-name">${name || 'No label'}</div>
                    </div>
                    <button class="btn-icon-delete" onclick="app.deleteRule('blacklist', '${mac}')" title="Delete rule">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `).join('');
        }
    }


    /* ==========================================================
       5. SESSION ACTIONS
       ========================================================== */
    async toggleSession() {
        const btn = document.getElementById('btnSessionControl');
        const sess = this.getActiveSession();

        if (sess.status === "RUNNING") {
            sess.status = "STOPPING";
            if (btn) {
                btn.disabled = true;
                btn.className = 'btn btn-secondary';
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Stopping...</span>';
            }

            try {
                const res = await fetch('/api/session/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sess.session_id })
                });
                const data = await res.json();
                if (data.success) {
                    this.showToast(`Session stopped on ${sess.session_id}.`, 'info');
                    if (data.state) this._mergeSessionState(sess.session_id, data.state);
                    this.updateActiveSessionUI();
                    this.renderSessionTabs();
                } else {
                    this.showToast(data.error || 'Failed to stop session.', 'error');
                }
            } catch (e) {
                this.showToast('Network error while stopping session.', 'error');
            } finally {
                if (btn) btn.disabled = false;
            }
        } else if (sess.status !== "STOPPING") {
            const selectedDevices = sess.devices.filter(d => sess.selectedIps.has(d.ip));
            const globalWlMacs = new Set(Object.keys(this.rules.whitelist || {}).map(m => m.toLowerCase()));

            let targets = [];
            let whitelisted = [];

            if (sess.mode === "blacklist") {
                targets = selectedDevices.filter(d => !globalWlMacs.has((d.mac || '').toLowerCase()));
                whitelisted = sess.devices.filter(d => globalWlMacs.has((d.mac || '').toLowerCase()));
                if (!targets.length) {
                    this.showToast('Please select at least one device to throttle.', 'error');
                    return;
                }
            } else {
                const safeMacs = new Set([
                    ...globalWlMacs,
                    ...selectedDevices.map(d => (d.mac || '').toLowerCase()).filter(Boolean)
                ]);
                const safeIps = new Set(selectedDevices.map(d => d.ip).filter(ip => ip && ip !== '-'));

                whitelisted = sess.devices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    return (mac && safeMacs.has(mac)) || safeIps.has(d.ip);
                });
                targets = sess.devices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    return !((mac && safeMacs.has(mac)) || safeIps.has(d.ip));
                });
            }

            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Starting...</span>';
            }

            try {
                const payload = {
                    session_id: sess.session_id,
                    interface: sess.interface,
                    router_ip: sess.router_ip,
                    mode: sess.mode,
                    targets: targets,
                    whitelisted: whitelisted,
                    limit_mbps: sess.limit_mbps
                };

                const res = await fetch('/api/session/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (data.success) {
                    this.showToast(data.message || `Session started on ${sess.session_id}!`, 'success');
                    if (data.state) this._mergeSessionState(sess.session_id, data.state);
                    this.updateActiveSessionUI();
                    this.renderSessionTabs();
                } else {
                    this.showToast(data.error || 'Failed to start session.', 'error');
                }
            } catch (e) {
                this.showToast('Error starting session.', 'error');
            } finally {
                if (btn) btn.disabled = false;
            }
        }
    }

    async triggerScan() {
        if (this.isScanning) return;
        this.isScanning = true;
        const sess = this.getActiveSession();

        const btnTop = document.getElementById('btnRescanTop');
        const btnTab = document.getElementById('btnScanDevicesTab');
        const statusBanner = document.getElementById('scannerStatusBanner');
        const statusText = document.getElementById('scannerStatusText');

        if (btnTop) {
            btnTop.disabled = true;
            btnTop.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> <span>Scanning...</span>';
        }
        if (btnTab) {
            btnTab.disabled = true;
            btnTab.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Rescanning...';
        }
        if (statusBanner && statusText) {
            statusBanner.className = 'scanner-status-banner scanning';
            statusText.textContent = `Scanning ${sess.session_id} (Win32 SendARP)...`;
        }

        this.showToast(`Scanning ${sess.session_id}...`, 'info');

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: sess.session_id,
                    interface: sess.interface,
                    router_ip: sess.router_ip
                })
            });
            const data = await res.json();
            if (data.success) {
                sess.devices = data.devices;
                this.renderDashboardTable();
                this.renderScannerTable();
                this.renderSessionTabs();
                this.showToast(`Scan complete on ${sess.session_id}: found ${data.count} device(s).`, 'success');
                if (statusBanner && statusText) {
                    statusBanner.className = 'scanner-status-banner';
                    statusText.textContent = `[${sess.session_id}] ${data.count} device(s) online.`;
                }
            } else {
                this.showToast('Scan failed: ' + (data.error || 'Unknown error'), 'error');
            }
        } catch (e) {
            this.showToast('Network error during scan.', 'error');
        } finally {
            this.isScanning = false;
            if (btnTop) {
                btnTop.disabled = false;
                btnTop.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> <span>Scan</span>';
            }
            if (btnTab) {
                btnTab.disabled = false;
                btnTab.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Rescan Network';
            }
        }
    }


    async submitManualDevice() {
        const ip = document.getElementById('manualDeviceIp').value.trim();
        const mac = document.getElementById('manualDeviceMac').value.trim();
        const vendor = document.getElementById('manualDeviceVendor').value.trim();
        const sess = this.getActiveSession();

        if (!ip && !mac) {
            this.showToast('Please enter an IP address or a MAC address.', 'error');
            return;
        }

        try {
            const res = await fetch('/api/devices/manual', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, mac, vendor, session_id: sess.session_id })
            });
            const data = await res.json();
            if (data.success) {
                this.closeModal('manualDeviceModal');
                document.getElementById('manualDeviceIp').value = '';
                document.getElementById('manualDeviceMac').value = '';
                document.getElementById('manualDeviceVendor').value = '';
                this.showToast(`Added device: ${data.device.ip} (${data.device.mac})`, 'success');
                await this.fetchSessionStatus(sess.session_id);
            } else {
                this.showToast(data.error || 'Failed to add manual device.', 'error');
            }
        } catch (e) {
            this.showToast('Error adding manual device.', 'error');
        }
    }

    async submitRule() {
        const category = document.getElementById('ruleCategoryInput').value;
        const mac = document.getElementById('ruleMacInput').value.trim();
        const name = document.getElementById('ruleNameInput').value.trim();

        if (!mac) {
            this.showToast('MAC address is required.', 'error');
            return;
        }

        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ category, mac, name })
            });
            const data = await res.json();
            if (data.success) {
                this.closeModal('addRuleModal');
                document.getElementById('ruleMacInput').value = '';
                document.getElementById('ruleNameInput').value = '';
                this.rules = data.rules;
                this.renderRules();
                this.renderDashboardTable();
                this.showToast(`Saved rule for ${mac}`, 'success');
            } else {
                this.showToast(data.error || 'Failed to save rule.', 'error');
            }
        } catch (e) {
            this.showToast('Error saving rule.', 'error');
        }
    }

    async deleteRule(category, mac) {
        try {
            const res = await fetch(`/api/rules/${category}/${encodeURIComponent(mac)}`, { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                this.rules = data.rules;
                this.renderRules();
                this.renderDashboardTable();
                this.showToast(`Removed rule for ${mac}`, 'info');
            }
        } catch (e) {
            this.showToast('Failed to delete rule.', 'error');
        }
    }

    async clearCache() {
        if (confirm("Are you sure you want to clear device cache for this session?")) {
            const sess = this.getActiveSession();
            try {
                const res = await fetch('/api/devices/clear', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sess.session_id })
                });
                const data = await res.json();
                if (data.success) {
                    this.showToast(data.message, 'success');
                    await this.fetchSessionStatus(sess.session_id);
                } else {
                    this.showToast(data.error, 'error');
                }
            } catch (e) {
                this.showToast('Error clearing cache.', 'error');
            }
        }
    }

    async renderSettings(showToastFeedback = false) {
        const tbody = document.getElementById('settingsInterfacesBody');
        if (!tbody) return;

        try {
            const res = await fetch('/api/settings');
            const data = await res.json();
            if (data.success) {
                const ifaces = data.interfaces || [];
                tbody.innerHTML = '';

                if (!ifaces.length) {
                    tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><p>No active network interfaces detected.</p></td></tr>`;
                    return;
                }

                ifaces.forEach(iface => {
                    const tr = document.createElement('tr');
                    const isOnline = iface.link_status !== 'DISCONNECTED';
                    const linkBadge = isOnline
                        ? `<span class="badge badge-whitelist" style="font-size: 0.72rem;"><i class="fa-solid fa-bolt"></i> ONLINE</span>`
                        : `<span class="badge badge-blacklist" style="font-size: 0.72rem;"><i class="fa-solid fa-triangle-exclamation"></i> DISCONNECTED</span>`;

                    const isActiveSession = iface.name === this.activeSessionId;

                    tr.innerHTML = `
                        <td>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <strong style="color: var(--text-primary); font-size: 0.9rem;">${iface.name}</strong>
                                ${linkBadge}
                                ${isActiveSession ? '<span class="badge badge-new" style="font-size: 0.65rem;">Active View</span>' : ''}
                            </div>
                        </td>
                        <td>
                            <span class="device-ip">${iface.ip}</span>
                        </td>
                        <td>
                            <span class="device-mac">${iface.mac}</span>
                        </td>
                        <td>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" class="settings-input-sm iface-gateway-input" data-iface="${iface.name}" value="${iface.gateway || ''}" placeholder="192.168.1.1">
                                <button type="button" class="btn btn-secondary btn-sm" onclick="app.detectGatewayForIface('${iface.name}')" title="Auto-detect router gateway" style="padding: 4px 8px; flex-shrink: 0;">
                                    <i class="fa-solid fa-arrows-rotate"></i>
                                </button>
                            </div>
                        </td>
                        <td>
                            <div style="display: flex; gap: 4px; align-items: center;">
                                <input type="number" step="0.1" min="0.1" class="settings-input-sm iface-limit-input" data-iface="${iface.name}" value="${iface.default_limit || 1.0}">
                                <span style="font-size: 0.75rem; color: var(--text-muted);">Mbps</span>
                            </div>
                        </td>
                        <td style="text-align: right;">
                            <button class="btn btn-secondary btn-sm" onclick="app.switchSession('${iface.name}'); app.switchTab('dashboard');" title="Switch to this interface">
                                <i class="fa-solid fa-arrow-right-to-bracket"></i> Switch
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });

                // Global Settings
                if (data.global) {
                    const disc = document.getElementById('settingDiscoveryInterval');
                    if (disc && data.global.discovery_interval !== undefined) {
                        disc.value = String(data.global.discovery_interval);
                    }
                    const mode = document.getElementById('settingDefaultMode');
                    if (mode && data.global.default_mode) {
                        mode.value = data.global.default_mode;
                    }
                }

                if (showToastFeedback) {
                    this.showToast('Network interfaces and router gateways refreshed.', 'success');
                }
            }
        } catch (e) {
            console.error("Failed to render settings:", e);
        }
    }

    async detectGatewayForIface(ifaceName) {
        try {
            const res = await fetch(`/api/interfaces?interface=${encodeURIComponent(ifaceName)}`);
            const data = await res.json();
            if (data.success && data.default_gateway) {
                const input = document.querySelector(`.iface-gateway-input[data-iface="${ifaceName}"]`);
                if (input) input.value = data.default_gateway;
                this.showToast(`Gateway for ${ifaceName}: ${data.default_gateway}`, 'success');
            } else {
                this.showToast(`Could not auto-detect gateway for ${ifaceName}.`, 'error');
            }
        } catch (e) {
            this.showToast('Failed to auto-detect gateway.', 'error');
        }
    }

    async saveSettings() {
        const sessionsData = {};
        document.querySelectorAll('.iface-gateway-input').forEach(inp => {
            const iface = inp.dataset.iface;
            const gw = inp.value.trim();
            const limInput = document.querySelector(`.iface-limit-input[data-iface="${iface}"]`);
            const lim = limInput ? (parseFloat(limInput.value) || 1.0) : 1.0;
            sessionsData[iface] = {
                router_ip: gw,
                default_limit: lim
            };
        });

        const discoveryInterval = parseInt(document.getElementById('settingDiscoveryInterval')?.value || '8');
        const defaultMode = document.getElementById('settingDefaultMode')?.value || 'blacklist';

        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sessions: sessionsData,
                    discovery_interval: discoveryInterval,
                    operational_mode: defaultMode
                })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast('All interface configurations and engine settings saved.', 'success');
                await this.fetchStatus();
                this.renderSessionTabs();
            } else {
                this.showToast(data.error || 'Failed to save settings.', 'error');
            }
        } catch (e) {
            this.showToast('Network error while saving settings.', 'error');
        }
    }


    /* ==========================================================
       6. ADD/DELETE SESSION
       ========================================================== */
    openAddSessionModal() {
        const select = document.getElementById('addSessionInterface');
        if (select) {
            select.innerHTML = '';
            const existingIds = new Set(Object.keys(this.sessions));
            const available = this.availableInterfaces.filter(i => !existingIds.has(i.name));

            if (!available.length) {
                this.showToast('All available interfaces already have sessions.', 'info');
                return;
            }

            available.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface.name;
                opt.textContent = `${iface.name} (${iface.ip})`;
                select.appendChild(opt);
            });

            // Pre-fill gateway
            if (available.length) {
                const gw = available[0].gateway || '';
                document.getElementById('addSessionGateway').value = gw;
            }
        }
        this.openModal('addSessionModal');
    }

    async submitAddSession() {
        const iface = document.getElementById('addSessionInterface').value;
        const gateway = document.getElementById('addSessionGateway').value.trim();

        if (!iface) {
            this.showToast('Select an interface.', 'error');
            return;
        }

        try {
            const res = await fetch('/api/sessions/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface, router_ip: gateway || undefined })
            });
            const data = await res.json();
            if (data.success) {
                this.closeModal('addSessionModal');
                if (data.sessions) {
                    this.sessionIds = data.session_ids || Object.keys(data.sessions);
                    for (const [id, state] of Object.entries(data.sessions)) {
                        this._ensureSession(id);
                        this._mergeSessionState(id, state);
                    }
                }
                this.renderSessionTabs();
                this.switchSession(iface);
                this.showToast(`Created session for ${iface}`, 'success');
            } else {
                this.showToast(data.error || 'Failed to create session.', 'error');
            }
        } catch (e) {
            this.showToast('Error creating session.', 'error');
        }
    }

    async deleteSession(sid) {
        if (!confirm(`Remove session "${sid}"? This will clear all discovered devices for this interface.`)) return;

        try {
            const res = await fetch(`/api/sessions/${encodeURIComponent(sid)}/delete`, { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                delete this.sessions[sid];
                this.sessionIds = data.session_ids || this.sessionIds.filter(id => id !== sid);
                if (this.activeSessionId === sid) {
                    this.activeSessionId = this.sessionIds[0] || null;
                }
                this.renderSessionTabs();
                if (this.activeSessionId) this.updateActiveSessionUI();
                this.showToast(`Removed session: ${sid}`, 'info');
            } else {
                this.showToast(data.error || 'Failed to delete session.', 'error');
            }
        } catch (e) {
            this.showToast('Error deleting session.', 'error');
        }
    }


    /* ==========================================================
       7. UTILITIES
       ========================================================== */
    quickAddToRule(mac, vendor) {
        if (!mac || mac === 'Unknown') {
            this.showToast('Cannot create global rule without a MAC address.', 'error');
            return;
        }
        const macInp = document.getElementById('ruleMacInput');
        const nameInp = document.getElementById('ruleNameInput');
        if (macInp) macInp.value = mac;
        if (nameInp) nameInp.value = vendor;
        this.openAddRuleModal('whitelist');
    }

    openAddRuleModal(category) {
        const catInp = document.getElementById('ruleCategoryInput');
        if (catInp) catInp.value = category;
        const title = category === 'whitelist' ? 'Add to Global Whitelist' : 'Add to Global Blacklist';
        const titleEl = document.getElementById('addRuleModalTitle');
        if (titleEl) titleEl.innerHTML = `<i class="fa-solid fa-shield cyan"></i> ${title}`;
        this.openModal('addRuleModal');
    }

    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add('active');
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove('active');
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        let icon = 'fa-info-circle';
        if (type === 'success') icon = 'fa-circle-check';
        if (type === 'error') icon = 'fa-circle-exclamation';

        toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    startLocalTimer() {
        // Polling fallback every 1.5s for metrics — poll ALL running sessions
        setInterval(async () => {
            for (const [sid, sess] of Object.entries(this.sessions)) {
                if (sess.status === "RUNNING") {
                    try {
                        const res = await fetch(`/api/telemetry?session_id=${encodeURIComponent(sid)}`);
                        const data = await res.json();
                        if (data.success) {
                            sess.telemetry = data.telemetry || [];
                            sess._totalSpeedKbps = data.total_speed_kbps || '0.0';
                            sess._totalSpeedMbps = data.total_speed_mbps || '0.00';
                            sess._totalDataMb = data.total_data_mb || '0.00';

                            if (sid === this.activeSessionId) {
                                const statThroughput = document.getElementById('statThroughput');
                                if (statThroughput) statThroughput.innerHTML = `${data.total_speed_kbps || '0.0'} <span class="unit">KB/s</span>`;
                                const statThroughputMbps = document.getElementById('statThroughputMbps');
                                if (statThroughputMbps) statThroughputMbps.textContent = `${data.total_speed_mbps || '0.00'} Mbps total speed`;
                                const statData = document.getElementById('statDataTransferred');
                                if (statData) statData.innerHTML = `${data.total_data_mb || '0.00'} <span class="unit">MB</span>`;
                                this.renderDashboardTable();
                            }
                            this.renderSessionTabs();
                        }
                    } catch (e) {}
                }
            }
        }, 1500);

        // Timer interval — tick each running session's uptime
        this.timerInterval = setInterval(() => {
            for (const [sid, sess] of Object.entries(this.sessions)) {
                if (sess.status === "RUNNING") {
                    sess.uptime += 1;
                }
            }
            // Display active session timer
            const active = this.getActiveSession();
            if (active.status === "RUNNING") {
                const hrs = String(Math.floor(active.uptime / 3600)).padStart(2, '0');
                const mins = String(Math.floor((active.uptime % 3600) / 60)).padStart(2, '0');
                const secs = String(active.uptime % 60).padStart(2, '0');
                const timeDisp = document.getElementById('sessionTimeDisplay');
                if (timeDisp) timeDisp.textContent = `${hrs}:${mins}:${secs}`;
            }
        }, 1000);
    }
}

// Instantiate on load
let app = null;
window.addEventListener('DOMContentLoaded', () => {
    app = new ThrottwinApp();
    window.app = app;
});
