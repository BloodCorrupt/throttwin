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
        this.coreStatus = null;
        this.isDownloadingCore = false;

        this.eventSource = null;
        this.timerInterval = null;
        this.isScanning = false;

        // Mini Console & Packet Stream State
        this.debugLogs = [];
        this.packetLogs = [];
        this.consoleActiveTab = 'debug';
        this.consoleAutoScroll = true;
        this.consolePaused = false;
        this.consoleFilterLevel = 'ALL';
        this.consoleSearchDebug = '';
        this.consoleFilterAction = 'ALL';
        this.consoleSearchPacket = '';
        this.systemLoggingEnabled = true;
        this.packetCaptureEnabled = true;
        this.cpuSaverMode = false;
        this.recentPacketTimestamps = [];
        this.isDraggingConsole = false;
        this.dragOffset = { x: 0, y: 0 };
        this.unreadErrorsCount = 0;

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
            fuzzy_enabled: false,
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
        this.initConsole();
        await this.loadInterfaces();
        await this.loadRules();
        await this.fetchStatus();
        await this.fetchCoreStatus();
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
                if (payload.core) {
                    this.coreStatus = payload.core;
                    this.updateCoreUI();
                }
                if (payload.log_status) {
                    this.updateLogStatusUI(payload.log_status);
                }
                if (payload.recent_debug_logs && payload.recent_debug_logs.length) {
                    this.debugLogs = payload.recent_debug_logs;
                    this.renderDebugLogs();
                }
                if (payload.recent_packet_logs && payload.recent_packet_logs.length) {
                    this.packetLogs = payload.recent_packet_logs;
                    this.renderPacketLogs();
                }
                this.updateConsoleBadges();
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

            case "core_tools_updated":
                if (payload.core || data.core) {
                    this.coreStatus = payload.core || data.core;
                    this.updateCoreUI();
                }
                if (payload.message || data.message) {
                    this.showToast(payload.message || data.message, (payload.installed || data.installed) ? 'success' : 'info');
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

            case "fuzzy_toggled":
                if (sid) {
                    const sess = this._ensureSession(sid);
                    sess.fuzzy_enabled = data.fuzzy_enabled;
                    if (sid === this.activeSessionId) {
                        this.updateFuzzyUI(data.fuzzy_enabled);
                        this.renderDashboardTable();
                    }
                    this.showToast(`Fuzzy throttle ${data.fuzzy_enabled ? 'activated 🎲' : 'deactivated'} [${sid}]`, data.fuzzy_enabled ? 'warning' : 'info');
                }
                break;

            case "target_fuzzy_toggled":
                if (data.state && sid) {
                    this._mergeSessionState(sid, data.state);
                    if (sid === this.activeSessionId) {
                        this.renderDashboardTable();
                    }
                    const stateStr = data.fuzzy_enabled ? 'activated 🎲' : 'deactivated';
                    this.showToast(`Target ${data.ip} fuzzy throttle ${stateStr} [${sid}]`, data.fuzzy_enabled ? 'warning' : 'info');
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

            case "log_event":
                this.onLogEvent(data);
                break;

            case "packet_event":
                this.onPacketEvent(data);
                break;

            case "logs_cleared":
                this.onLogsCleared(data.type);
                break;

            case "log_level_changed":
                if (data.level) this.updateLogLevelUI(data.level);
                break;

            case "packet_capture_toggled":
                if (data.enabled !== undefined) this.updatePacketCaptureUI(data.enabled);
                break;

            case "system_logging_toggled":
                if (data.enabled !== undefined) this.updateSystemLoggingUI(data.enabled);
                break;

            case "cpu_saver_toggled":
                this.updateCpuSaverUI(data.cpu_saver_mode, data);
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
        if (state.fuzzy_enabled !== undefined) sess.fuzzy_enabled = state.fuzzy_enabled;
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

        // Fuzzy Throttle Toggle
        const btnFuzzy = document.getElementById('btnFuzzyToggle');
        if (btnFuzzy) btnFuzzy.addEventListener('click', () => this.toggleFuzzy());

        // Session Control Button
        const btnSession = document.getElementById('btnSessionControl');
        if (btnSession) btnSession.addEventListener('click', () => this.toggleSession());

        // Rescan and Add Device Buttons
        const btnRescanTop = document.getElementById('btnRescanTop');
        if (btnRescanTop) btnRescanTop.addEventListener('click', () => this.triggerScan(false));

        const btnAggressiveTop = document.getElementById('btnAggressiveScanTop');
        if (btnAggressiveTop) btnAggressiveTop.addEventListener('click', () => this.triggerScan(true));

        const btnScanTab = document.getElementById('btnScanDevicesTab');
        if (btnScanTab) btnScanTab.addEventListener('click', () => this.triggerScan(false));

        const btnAggressiveTab = document.getElementById('btnAggressiveScanTab');
        if (btnAggressiveTab) btnAggressiveTab.addEventListener('click', () => this.triggerScan(true));

        const btnManualTop = document.getElementById('btnManualAddTop');
        if (btnManualTop) btnManualTop.addEventListener('click', () => this.openModal('manualDeviceModal'));

        const btnManualTab = document.getElementById('btnManualDeviceTab');
        if (btnManualTab) btnManualTab.addEventListener('click', () => this.openModal('manualDeviceModal'));

        const btnClearTab = document.getElementById('btnClearCacheTab');
        if (btnClearTab) btnClearTab.addEventListener('click', () => this.clearCache());

        // Core Engine Download & Verify Buttons
        const btnDlSidebar = document.getElementById('btnDownloadCoreSidebar');
        if (btnDlSidebar) btnDlSidebar.addEventListener('click', () => this.downloadCoreEngine());

        const btnDlSettings = document.getElementById('btnDownloadCoreSettings');
        if (btnDlSettings) btnDlSettings.addEventListener('click', () => this.downloadCoreEngine());

        const btnVerifySettings = document.getElementById('btnVerifyCoreSettings');
        if (btnVerifySettings) btnVerifySettings.addEventListener('click', () => this.verifyCoreEngine());

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

    updateFuzzyUI(enabled) {
        const btn = document.getElementById('btnFuzzyToggle');
        if (!btn) return;
        if (enabled) {
            btn.classList.add('active');
            btn.title = 'Fuzzy Throttle: ON (randomly restricting and releasing bandwidth)';
        } else {
            btn.classList.remove('active');
            btn.title = 'Fuzzy Throttle: OFF (click to toggle)';
        }
    }

    async toggleFuzzy() {
        const sess = this.getActiveSession();
        if (!sess || !sess.session_id || sess.session_id === 'none') {
            this.showToast('No active session.', 'warning');
            return;
        }
        const targetState = !sess.fuzzy_enabled;
        try {
            const res = await fetch('/api/session/fuzzy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: sess.session_id,
                    enabled: targetState
                })
            });
            const data = await res.json();
            if (data.success) {
                sess.fuzzy_enabled = data.fuzzy_enabled;
                this.updateFuzzyUI(sess.fuzzy_enabled);
                this.showToast(`Fuzzy throttle ${data.fuzzy_enabled ? 'enabled 🎲' : 'disabled'} on ${sess.session_id}`, data.fuzzy_enabled ? 'warning' : 'info');
            } else {
                this.showToast(data.error || 'Failed to toggle fuzzy throttle.', 'danger');
            }
        } catch (e) {
            console.error('Error toggling fuzzy throttle:', e);
            this.showToast('Error communicating with server.', 'danger');
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

        const ids = this.sessionIds.length ? this.sessionIds : Object.keys(this.sessions);
        const existingTabs = {};
        container.querySelectorAll('.session-tab').forEach(tab => {
            const sid = tab.dataset.sessionId;
            if (sid) existingTabs[sid] = tab;
        });

        // Remove tabs that no longer exist
        Object.keys(existingTabs).forEach(sid => {
            if (!ids.includes(sid)) {
                existingTabs[sid].remove();
                delete existingTabs[sid];
            }
        });

        ids.forEach(sid => {
            const sess = this.sessions[sid];
            if (!sess) return;

            let statusClass = sess.status === 'RUNNING' ? 'running' : 'idle';
            let statusLabel = sess.status === 'RUNNING' ? 'ACTIVE' : 'IDLE';
            if (sess.link_status === 'DISCONNECTED') {
                statusClass = 'disconnected';
                statusLabel = 'DISCONNECTED';
            }
            const subnet = sess.router_ip ? sess.router_ip.split('.').slice(0, 3).join('.') + '.x' : '—';
            const targetCount = (sess.targets || []).length;
            const deviceCount = (sess.devices || []).length;
            const isActive = (sid === this.activeSessionId);

            let tab = existingTabs[sid];
            if (!tab) {
                tab = document.createElement('button');
                tab.className = `session-tab ${isActive ? 'active' : ''}`;
                tab.dataset.sessionId = sid;
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
            } else {
                // In-place update without destroying DOM elements (zero flicker!)
                const expectedClass = `session-tab ${isActive ? 'active' : ''}`;
                if (tab.className !== expectedClass) tab.className = expectedClass;

                const dot = tab.querySelector('.session-tab-status');
                if (dot && dot.className !== `session-tab-status ${statusClass}`) {
                    dot.className = `session-tab-status ${statusClass}`;
                }

                const sub = tab.querySelector('.session-tab-subnet');
                const subText = `${subnet} · ${deviceCount} dev${deviceCount !== 1 ? 's' : ''}`;
                if (sub && sub.textContent !== subText) {
                    sub.textContent = subText;
                }

                const badge = tab.querySelector('.session-tab-badge');
                const badgeText = `${statusLabel}${targetCount > 0 ? ` (${targetCount})` : ''}`;
                if (badge) {
                    if (badge.className !== `session-tab-badge ${statusClass}`) {
                        badge.className = `session-tab-badge ${statusClass}`;
                    }
                    if (badge.textContent !== badgeText) {
                        badge.textContent = badgeText;
                    }
                }

                const closeBtn = tab.querySelector('.session-tab-close');
                if (ids.length > 1 && sess.status !== 'RUNNING' && !closeBtn) {
                    const btn = document.createElement('button');
                    btn.className = 'session-tab-close';
                    btn.dataset.closeSession = sid;
                    btn.title = 'Remove session';
                    btn.innerHTML = '&times;';
                    tab.appendChild(btn);
                } else if ((ids.length <= 1 || sess.status === 'RUNNING') && closeBtn) {
                    closeBtn.remove();
                }
            }
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
        this.updateFuzzyUI(sess.fuzzy_enabled);
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

        // Defensive deduplication by IP and MAC
        const seenIps = new Set();
        const seenMacs = new Set();
        const uniqueDevices = [];
        (sess.devices || []).forEach(d => {
            if (!d) return;
            const ip = d.ip;
            const mac = (d.mac || '').toLowerCase();
            if (ip && ip !== '-' && seenIps.has(ip)) return;
            if (mac && mac !== 'unknown' && mac !== '' && seenMacs.has(mac)) return;
            if (ip && ip !== '-') seenIps.add(ip);
            if (mac && mac !== 'unknown' && mac !== '') seenMacs.add(mac);
            uniqueDevices.push(d);
        });

        if (!uniqueDevices.length) {
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

        const globalWl = {};
        if (Array.isArray(this.rules.whitelist)) {
            this.rules.whitelist.forEach(item => {
                const mac = (typeof item === 'string' ? item : (item.mac || '')).toLowerCase();
                if (mac) globalWl[mac] = item.name || '';
            });
        } else if (this.rules.whitelist && typeof this.rules.whitelist === 'object') {
            Object.entries(this.rules.whitelist).forEach(([k, v]) => {
                globalWl[k.toLowerCase()] = v || '';
            });
        }

        const globalBl = {};
        if (Array.isArray(this.rules.blacklist)) {
            this.rules.blacklist.forEach(item => {
                const mac = (typeof item === 'string' ? item : (item.mac || '')).toLowerCase();
                if (mac) globalBl[mac] = item.name || '';
            });
        } else if (this.rules.blacklist && typeof this.rules.blacklist === 'object') {
            Object.entries(this.rules.blacklist).forEach(([k, v]) => {
                globalBl[k.toLowerCase()] = v || '';
            });
        }

        const isRunning = sess.status === "RUNNING";
        tbody.innerHTML = '';

        uniqueDevices.forEach(dev => {
            const tr = document.createElement('tr');
            const macLower = (dev.mac || '').toLowerCase();
            const ip = dev.ip || '-';
            tr.dataset.ip = ip;
            tr.dataset.mac = macLower;

            const isHost = Boolean(dev.is_host);
            const isGlobalWl = (macLower in globalWl) || isHost;
            const isGlobalBl = (macLower in globalBl) && !isHost;
            const wlLabel = isHost ? (globalWl[macLower] || 'This PC') : globalWl[macLower];
            const blLabel = globalBl[macLower];

            const isCurrentlyThrottled = runningTargetIps.has(ip);

            let isChecked = sess.selectedIps.has(ip);
            if (sess.mode === "whitelist" && isGlobalWl) {
                isChecked = true;
                sess.selectedIps.add(ip);
            } else if (sess.mode === "blacklist" && isGlobalWl) {
                isChecked = false;
                sess.selectedIps.delete(ip);
            } else if (!isRunning && !sess.selectedIps.size) {
                if (sess.mode === "blacklist" && isGlobalBl) isChecked = true;
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
                    const isFuzzy = tele && tele.fuzzy_enabled !== undefined ? Boolean(tele.fuzzy_enabled) : Boolean(sess.fuzzy_enabled);
                    const fuzzyBtn = isCurrentlyThrottled
                        ? `<button type="button" class="btn-device-fuzzy ${isFuzzy ? 'active' : ''}" data-ip="${ip}" title="${isFuzzy ? 'Fuzzy: ON for this device (randomly restricting/releasing). Click to switch to steady limit.' : 'Fuzzy: OFF for this device (steady limit). Click to activate fuzzy mode for this device.'}"><i class="fa-solid fa-dice"></i> <span>Fuzzy</span></button>`
                        : '';
                    statusToggleHtml = `
                        <div class="hot-toggle-wrap">
                            ${onlineDot}
                            <label class="switch-toggle" title="Click to hot-toggle throttling for this target">
                                <input type="checkbox" class="hot-toggle-cb" data-ip="${ip}" ${isCurrentlyThrottled ? 'checked' : ''}>
                                <span class="slider round"></span>
                            </label>
                            ${isCurrentlyThrottled ? '<span class="label-throttled">THROTTLED</span>' : '<span class="label-bypassed">BYPASSED</span>'}
                            ${fuzzyBtn}
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

            const isRowDisabled = isRunning || (sess.mode === "whitelist" && isGlobalWl) || (sess.mode === "blacklist" && isGlobalWl);
            const checkTooltip = isGlobalWl ? 'title="Permanently whitelisted safe device"' : '';

            tr.innerHTML = `
                <td>
                    <input type="checkbox" class="custom-checkbox device-row-check" data-ip="${ip}" ${isChecked ? 'checked' : ''} ${isRowDisabled ? 'disabled' : ''} ${checkTooltip}>
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

            // Per-Device Fuzzy Button handler
            const fuzzyBtnEl = tr.querySelector('.btn-device-fuzzy');
            if (fuzzyBtnEl) {
                fuzzyBtnEl.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.toggleTargetFuzzy(ip);
                });
            }

            tbody.appendChild(tr);
        });

        // Sync header select all checkbox state
        const selectAllCb = document.getElementById('selectAllCheckbox');
        if (selectAllCb) {
            const selectable = uniqueDevices.filter(d => d.ip && d.ip !== '-');
            const totalSelectable = selectable.length;
            const totalChecked = selectable.filter(d => sess.selectedIps.has(d.ip)).length;
            selectAllCb.checked = totalSelectable > 0 && totalChecked === totalSelectable;
            selectAllCb.indeterminate = totalChecked > 0 && totalChecked < totalSelectable;
            selectAllCb.disabled = isRunning;
        }
    }

    updateTelemetryInTable(sess) {
        if (!sess || sess.status !== "RUNNING") return;
        const tbody = document.getElementById('devicesTableBody');
        if (!tbody) return;

        const teleMap = {};
        (sess.telemetry || []).forEach(t => {
            if (t.ip) teleMap[t.ip] = t;
        });

        const runningTargetIps = new Set(
            (sess.targets || []).map(t => (typeof t === 'string' ? t : t.ip))
        );

        const rows = tbody.querySelectorAll('tr[data-ip]');
        if (rows.length === 0) {
            this.renderDashboardTable();
            return;
        }

        let needsFullRender = false;

        rows.forEach(tr => {
            const ip = tr.dataset.ip;
            const isCurrentlyThrottled = runningTargetIps.has(ip);
            const speedCell = tr.querySelector('.live-speed-cell');
            const dot = tr.querySelector('.status-dot-sm');

            if (isCurrentlyThrottled) {
                const tele = teleMap[ip];
                if (!speedCell) {
                    needsFullRender = true;
                    return;
                }

                const speedKbps = tele ? tele.speed_kbps : 0.0;
                const speedMbps = tele ? tele.speed_mbps : 0.00;
                const maxCapKbps = (sess.limit_mbps * 125.0);
                const pct = Math.min(Math.round((speedKbps / Math.max(maxCapKbps, 1)) * 100), 100);

                const pill = speedCell.querySelector('.device-speed-pill');
                const mbpsText = speedCell.querySelector('.speed-mbps-text');
                const bar = speedCell.querySelector('.speed-meter-bar');

                if (pill) pill.textContent = `${speedKbps} KB/s`;
                if (mbpsText) mbpsText.textContent = `${speedMbps} MB/s (${pct}%)`;
                if (bar) bar.style.width = `${pct}%`;

                if (dot && tele) {
                    dot.className = `status-dot-sm ${tele.is_online ? 'online' : 'offline'}`;
                    dot.title = tele.is_online ? 'Online & Active' : 'Probing / Offline';
                }

                const fuzzyBtnEl = tr.querySelector('.btn-device-fuzzy');
                if (fuzzyBtnEl && tele && tele.fuzzy_enabled !== undefined) {
                    const isFuzzy = Boolean(tele.fuzzy_enabled);
                    fuzzyBtnEl.classList.toggle('active', isFuzzy);
                    fuzzyBtnEl.title = isFuzzy
                        ? 'Fuzzy: ON for this device (randomly restricting/releasing). Click to switch to steady limit.'
                        : 'Fuzzy: OFF for this device (steady limit). Click to activate fuzzy mode for this device.';
                }
            } else {
                if (speedCell) {
                    needsFullRender = true;
                }
            }
        });

        if (needsFullRender) {
            this.renderDashboardTable();
        }
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

    async toggleTargetFuzzy(ip) {
        const sess = this.getActiveSession();
        try {
            const res = await fetch('/api/target/fuzzy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, session_id: sess.session_id })
            });
            const data = await res.json();
            if (data.success) {
                if (data.state) {
                    this._mergeSessionState(sess.session_id, data.state);
                } else if (sess.telemetry) {
                    const item = sess.telemetry.find(t => t.ip === ip);
                    if (item) item.fuzzy_enabled = data.fuzzy_enabled;
                }
                this.renderDashboardTable();
                this.showToast(data.message || `Fuzzy ${data.fuzzy_enabled ? 'enabled 🎲' : 'disabled'} for ${ip}`, data.fuzzy_enabled ? 'warning' : 'info');
            } else {
                this.showToast(data.error || 'Failed to toggle target fuzzy mode.', 'danger');
            }
        } catch (e) {
            console.error('Error toggling target fuzzy:', e);
            this.showToast('Network error during target fuzzy toggle.', 'danger');
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

        // Defensive deduplication
        const seenIps = new Set();
        const seenMacs = new Set();
        const uniqueDevices = [];
        (sess.devices || []).forEach(d => {
            if (!d) return;
            const ip = d.ip;
            const mac = (d.mac || '').toLowerCase();
            if (ip && ip !== '-' && seenIps.has(ip)) return;
            if (mac && mac !== 'unknown' && mac !== '' && seenMacs.has(mac)) return;
            if (ip && ip !== '-') seenIps.add(ip);
            if (mac && mac !== 'unknown' && mac !== '') seenMacs.add(mac);
            uniqueDevices.push(d);
        });

        if (titleText) {
            titleText.innerHTML = `Discovered Network Devices &mdash; <span style="color: var(--accent-cyan); font-family: var(--font-mono); font-weight: 600;">${sess.session_id}</span> <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">(${subnet})</span>`;
        }
        if (statusText) {
            statusText.textContent = `[${sess.session_id}] ${uniqueDevices.length} device(s) online on subnet ${subnet}.`;
        }

        if (!uniqueDevices.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><p>No devices discovered yet for ${sess.session_id}. Click "Rescan Network" above.</p></td></tr>`;
            return;
        }

        tbody.innerHTML = '';
        uniqueDevices.forEach(dev => {
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
            const globalWlMacs = new Set(
                Array.isArray(this.rules.whitelist)
                    ? this.rules.whitelist.map(item => (typeof item === 'string' ? item : item.mac || '').toLowerCase()).filter(Boolean)
                    : Object.keys(this.rules.whitelist || {}).map(m => m.toLowerCase())
            );

            let targets = [];
            let whitelisted = [];

            if (sess.mode === "blacklist") {
                targets = selectedDevices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    const isGw = (d.ip === sess.router_ip);
                    const isHost = Boolean(d.is_host);
                    return !isGw && !isHost && !globalWlMacs.has(mac);
                });
                whitelisted = sess.devices.filter(d => d.is_host || globalWlMacs.has((d.mac || '').toLowerCase()));
                if (!targets.length) {
                    this.showToast('Please select at least one device to throttle.', 'error');
                    return;
                }
            } else {
                const hostMacs = sess.devices.filter(d => d.is_host).map(d => (d.mac || '').toLowerCase()).filter(Boolean);
                const hostIps = sess.devices.filter(d => d.is_host).map(d => d.ip).filter(ip => ip && ip !== '-');
                const safeMacs = new Set([
                    ...globalWlMacs,
                    ...hostMacs,
                    ...selectedDevices.map(d => (d.mac || '').toLowerCase()).filter(Boolean)
                ]);
                const safeIps = new Set([
                    ...hostIps,
                    ...selectedDevices.map(d => d.ip).filter(ip => ip && ip !== '-')
                ]);
                if (sess.router_ip) safeIps.add(sess.router_ip);

                whitelisted = sess.devices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    return d.is_host || (mac && safeMacs.has(mac)) || safeIps.has(d.ip);
                });
                targets = sess.devices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    const isGw = (d.ip === sess.router_ip);
                    const isHost = Boolean(d.is_host);
                    return !isGw && !isHost && !((mac && safeMacs.has(mac)) || safeIps.has(d.ip));
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

    /* ==========================================================
       CORE NATIVE ENGINE (arp-scan.exe) MANAGEMENT
       ========================================================== */
    async fetchCoreStatus() {
        try {
            const res = await fetch('/api/core/status');
            const data = await res.json();
            if (data.success && data.core) {
                this.coreStatus = data.core;
                this.updateCoreUI();
            }
        } catch (e) {
            console.error('Error fetching core status:', e);
        }
    }

    updateCoreUI() {
        if (!this.coreStatus || !this.coreStatus.arp_scan) return;
        const arp = this.coreStatus.arp_scan;

        const pill = document.getElementById('sidebarCoreStatusPill');
        const pillText = document.getElementById('sidebarCoreStatusText');
        const desc = document.getElementById('sidebarCoreDesc');
        const btnSidebar = document.getElementById('btnDownloadCoreSidebar');
        const btnSidebarText = document.getElementById('btnDownloadCoreText');
        const iconSidebar = document.getElementById('iconDownloadCore');

        const settingsPathVal = document.getElementById('settingsCorePathVal');
        const btnSettingsText = document.getElementById('btnDownloadSettingsText');

        if (this.isDownloadingCore) {
            if (pill) {
                pill.className = 'core-status-pill downloading';
            }
            if (pillText) pillText.textContent = 'Installing';
            if (desc) desc.textContent = 'Downloading from GitHub repository...';
            if (btnSidebar) {
                btnSidebar.disabled = true;
                btnSidebar.className = 'btn btn-core-action';
            }
            if (btnSidebarText) btnSidebarText.textContent = 'Downloading...';
            if (iconSidebar) iconSidebar.className = 'fa-solid fa-spinner fa-spin';
            if (btnSettingsText) btnSettingsText.textContent = 'Downloading...';
            if (settingsPathVal) settingsPathVal.innerHTML = '<span class="badge badge-pulse-glow"><i class="fa-solid fa-spinner fa-spin"></i> Downloading from GitHub...</span>';
            return;
        }

        if (arp.installed) {
            if (pill) {
                pill.className = 'core-status-pill ready';
            }
            if (pillText) pillText.textContent = 'Ready';
            if (desc) desc.textContent = '⚡ Double-Power C-Engine Active.';
            if (btnSidebar) {
                btnSidebar.disabled = false;
                btnSidebar.className = 'btn btn-core-action installed';
                btnSidebar.title = 'arp-scan is installed and active! Click to reinstall.';
            }
            if (btnSidebarText) btnSidebarText.textContent = 'Reinstall Core';
            if (iconSidebar) iconSidebar.className = 'fa-solid fa-circle-check';
            if (btnSettingsText) btnSettingsText.textContent = 'Reinstall Core (x64)';
            if (settingsPathVal) {
                const kb = Math.round((arp.size_bytes || 0) / 1024);
                settingsPathVal.innerHTML = `<span class="badge badge-whitelist"><i class="fa-solid fa-circle-check"></i> Installed & Ready (${kb} KB)</span> <span class="font-mono text-muted" style="margin-left: 8px; font-size: 0.78rem;">${arp.path}</span>`;
            }
        } else {
            if (pill) {
                pill.className = 'core-status-pill missing';
            }
            if (pillText) pillText.textContent = 'Optional';
            if (desc) desc.textContent = 'Install for instant double-power C scan.';
            if (btnSidebar) {
                btnSidebar.disabled = false;
                btnSidebar.className = 'btn btn-core-action';
                btnSidebar.title = 'Click to download and install arp-scan from GitHub';
            }
            if (btnSidebarText) btnSidebarText.textContent = 'Download Core';
            if (iconSidebar) iconSidebar.className = 'fa-solid fa-cloud-arrow-down';
            if (btnSettingsText) btnSettingsText.textContent = 'Download & Install Core';
            if (settingsPathVal) {
                settingsPathVal.innerHTML = `<span class="badge badge-idle"><i class="fa-solid fa-circle-exclamation"></i> Not Installed</span> <span class="text-muted" style="margin-left: 8px;">(Will use fallback Win32 SendARP)</span>`;
            }
        }
    }

    async downloadCoreEngine() {
        if (this.isDownloadingCore) return;
        this.isDownloadingCore = true;
        this.updateCoreUI();
        this.showToast('Downloading arp-scan C-Engine from GitHub...', 'info');

        try {
            const res = await fetch('/api/core/download', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                this.coreStatus = data.core;
                this.showToast(data.message || 'arp-scan.exe installed successfully! ⚡ Double-Power mode active.', 'success');
            } else {
                this.showToast(data.error || 'Failed to download core tool.', 'error');
            }
        } catch (e) {
            this.showToast('Network error while downloading core binary.', 'error');
        } finally {
            this.isDownloadingCore = false;
            await this.fetchCoreStatus();
        }
    }

    async verifyCoreEngine() {
        try {
            const res = await fetch('/api/core/verify', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                this.showToast('arp-scan.exe verified and responding properly!', 'success');
            } else {
                this.showToast('arp-scan is not installed or failed verification.', 'warning');
            }
            if (data.core) {
                this.coreStatus = data.core;
                this.updateCoreUI();
            }
        } catch (e) {
            this.showToast('Error verifying core binary.', 'error');
        }
    }


    /* ==========================================================
       6. SCANNING
       ========================================================== */
    async triggerScan(isAggressive = false) {
        if (this.isScanning) return;
        this.isScanning = true;
        const sess = this.getActiveSession();

        const btnTop = document.getElementById('btnRescanTop');
        const btnAggTop = document.getElementById('btnAggressiveScanTop');
        const btnTab = document.getElementById('btnScanDevicesTab');
        const btnAggTab = document.getElementById('btnAggressiveScanTab');
        const statusBanner = document.getElementById('scannerStatusBanner');
        const statusText = document.getElementById('scannerStatusText');

        if (btnTop) {
            btnTop.disabled = true;
            btnTop.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> <span>Scanning...</span>';
        }
        if (btnAggTop) {
            btnAggTop.disabled = true;
            btnAggTop.innerHTML = '<i class="fa-solid fa-bolt-lightning fa-spin cyan"></i> <span>Sweeping...</span>';
        }
        if (btnTab) {
            btnTab.disabled = true;
            btnTab.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Fast Scan...';
        }
        if (btnAggTab) {
            btnAggTab.disabled = true;
            btnAggTab.innerHTML = '<i class="fa-solid fa-bolt-lightning fa-spin cyan"></i> Aggressive Sweep...';
        }
        if (statusBanner && statusText) {
            statusBanner.className = 'scanner-status-banner scanning';
            statusText.textContent = isAggressive
                ? `⚡ Aggressive Dual-Engine Deep Sweep on ${sess.session_id}...`
                : `Scanning ${sess.session_id} (Win32 SendARP)...`;
        }

        this.showToast(isAggressive ? `⚡ Aggressive Deep Sweep on ${sess.session_id}...` : `Scanning ${sess.session_id}...`, 'info');

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: sess.session_id,
                    interface: sess.interface,
                    router_ip: sess.router_ip,
                    aggressive: isAggressive
                })
            });
            const data = await res.json();
            if (data.success) {
                sess.devices = data.devices;
                this.renderDashboardTable();
                this.renderScannerTable();
                this.renderSessionTabs();
                const engineLabel = data.engine ? ` [${data.engine}]` : '';
                this.showToast(`Scan complete on ${sess.session_id}: found ${data.count} device(s)${engineLabel}`, 'success');
                if (statusBanner && statusText) {
                    statusBanner.className = 'scanner-status-banner';
                    statusText.textContent = `[${sess.session_id}] ${data.count} device(s) online${engineLabel}.`;
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
            if (btnAggTop) {
                btnAggTop.disabled = false;
                btnAggTop.innerHTML = '<i class="fa-solid fa-bolt-lightning cyan"></i> <span>Aggressive</span>';
            }
            if (btnTab) {
                btnTab.disabled = false;
                btnTab.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Fast Scan';
            }
            if (btnAggTab) {
                btnAggTab.disabled = false;
                btnAggTab.innerHTML = '<i class="fa-solid fa-bolt-lightning cyan"></i> Aggressive Sweep';
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

    // ═════════════════════════════════════════════════════════════════════════
    // MINI DEBUG & PACKET CONSOLE WINDOW IMPLEMENTATION
    // ═════════════════════════════════════════════════════════════════════════

    initConsole() {
        // 1. Toggle window triggers
        const btnTop = document.getElementById('btnToggleMiniConsole');
        if (btnTop) btnTop.addEventListener('click', () => this.toggleMiniConsole());

        const floatTrigger = document.getElementById('floatingConsoleTrigger');
        if (floatTrigger) floatTrigger.addEventListener('click', () => this.toggleMiniConsole());

        // 2. Tab switching
        const tabDebug = document.getElementById('tabBtnDebugLogs');
        const tabPacket = document.getElementById('tabBtnPacketLogs');
        if (tabDebug) tabDebug.addEventListener('click', () => this.switchConsoleTab('debug'));
        if (tabPacket) tabPacket.addEventListener('click', () => this.switchConsoleTab('packet'));

        // 3. Window action controls
        const btnCpuSaver = document.getElementById('btnConsoleCpuSaver');
        if (btnCpuSaver) btnCpuSaver.addEventListener('click', () => this.toggleCpuSaverMode());

        const btnAutoScroll = document.getElementById('btnConsoleAutoScroll');
        if (btnAutoScroll) btnAutoScroll.addEventListener('click', () => this.toggleConsoleAutoScroll());

        const btnPause = document.getElementById('btnConsolePause');
        if (btnPause) btnPause.addEventListener('click', () => this.toggleConsolePause());

        const btnClear = document.getElementById('btnConsoleClear');
        if (btnClear) btnClear.addEventListener('click', () => this.clearConsoleLogs());

        const btnExport = document.getElementById('btnConsoleExport');
        if (btnExport) btnExport.addEventListener('click', () => this.exportConsoleLogs());

        const btnMax = document.getElementById('btnConsoleMaximize');
        if (btnMax) btnMax.addEventListener('click', () => this.toggleConsoleMaximize());

        const btnMin = document.getElementById('btnConsoleMinimize');
        if (btnMin) btnMin.addEventListener('click', () => this.toggleConsoleMinimize());

        const btnClose = document.getElementById('btnConsoleClose');
        if (btnClose) btnClose.addEventListener('click', () => this.hideMiniConsole());

        // 4. Debug Logs Filters & Search
        const selectLevel = document.getElementById('selectLogLevel');
        if (selectLevel) {
            selectLevel.addEventListener('change', (e) => {
                this.consoleFilterLevel = e.target.value;
                this.renderDebugLogs();
            });
        }

        const inputSearchDebug = document.getElementById('inputFilterDebug');
        const btnClearDebugSearch = document.getElementById('btnClearDebugSearch');
        if (inputSearchDebug) {
            inputSearchDebug.addEventListener('input', (e) => {
                this.consoleSearchDebug = e.target.value.trim().toLowerCase();
                if (btnClearDebugSearch) {
                    btnClearDebugSearch.style.display = this.consoleSearchDebug ? 'block' : 'none';
                }
                this.renderDebugLogs();
            });
        }
        if (btnClearDebugSearch) {
            btnClearDebugSearch.addEventListener('click', () => {
                if (inputSearchDebug) inputSearchDebug.value = '';
                this.consoleSearchDebug = '';
                btnClearDebugSearch.style.display = 'none';
                this.renderDebugLogs();
            });
        }

        const toggleLogging = document.getElementById('toggleSystemLogging');
        if (toggleLogging) {
            toggleLogging.addEventListener('change', (e) => {
                this.setSystemLogging(e.target.checked);
            });
        }

        const btnResumeDebug = document.getElementById('btnResumeDebugLogging');
        if (btnResumeDebug) {
            btnResumeDebug.addEventListener('click', () => {
                this.setSystemLogging(true);
            });
        }

        // 5. Packet Filter Chips & Search
        const filterChips = document.getElementById('packetFilterChips');
        if (filterChips) {
            filterChips.addEventListener('click', (e) => {
                const chip = e.target.closest('.chip');
                if (!chip) return;
                filterChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                this.consoleFilterAction = chip.dataset.filter || 'ALL';
                this.renderPacketLogs();
            });
        }

        const inputSearchPacket = document.getElementById('inputFilterPacket');
        const btnClearPacketSearch = document.getElementById('btnClearPacketSearch');
        if (inputSearchPacket) {
            inputSearchPacket.addEventListener('input', (e) => {
                this.consoleSearchPacket = e.target.value.trim().toLowerCase();
                if (btnClearPacketSearch) {
                    btnClearPacketSearch.style.display = this.consoleSearchPacket ? 'block' : 'none';
                }
                this.renderPacketLogs();
            });
        }
        if (btnClearPacketSearch) {
            btnClearPacketSearch.addEventListener('click', () => {
                if (inputSearchPacket) inputSearchPacket.value = '';
                this.consoleSearchPacket = '';
                btnClearPacketSearch.style.display = 'none';
                this.renderPacketLogs();
            });
        }

        // 6. Packet Capture Toggle
        const toggleCapture = document.getElementById('togglePacketCapture');
        if (toggleCapture) {
            toggleCapture.addEventListener('change', (e) => {
                this.setPacketCapture(e.target.checked);
            });
        }

        const btnResumePacket = document.getElementById('btnResumePacketLogging');
        if (btnResumePacket) {
            btnResumePacket.addEventListener('click', () => {
                this.setPacketCapture(true);
            });
        }

        // 7. Settings Tab CPU Saver & Logging Controls
        const btnCpuSettings = document.getElementById('btnToggleCpuSaverSettings');
        if (btnCpuSettings) {
            btnCpuSettings.addEventListener('click', () => {
                this.toggleCpuSaverMode();
            });
        }

        const selectSysLogSettings = document.getElementById('settingSystemLogging');
        if (selectSysLogSettings) {
            selectSysLogSettings.addEventListener('change', (e) => {
                this.setSystemLogging(e.target.value === '1');
            });
        }

        const selectPktCapSettings = document.getElementById('settingPacketCapture');
        if (selectPktCapSettings) {
            selectPktCapSettings.addEventListener('change', (e) => {
                this.setPacketCapture(e.target.value === '1');
            });
        }

        // 8. Dynamic Log Level Selector from Toolbar
        const levelLabel = document.getElementById('labelCurrentLogLevel');
        if (levelLabel) {
            levelLabel.style.cursor = 'pointer';
            levelLabel.addEventListener('click', async () => {
                const levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR'];
                const currentIdx = levels.indexOf(this.consoleFilterLevel === 'ALL' ? 'INFO' : this.consoleFilterLevel);
                const nextLevel = levels[(currentIdx + 1) % levels.length];
                try {
                    const res = await fetch('/api/logs/level', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ level: nextLevel })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.updateLogLevelUI(data.level);
                        this.showToast(`Server log level set to ${data.level}`, 'success');
                    }
                } catch (e) {}
            });
        }

        // 9. Initialize Draggable Window & Scroll Detection & PPS meter
        this._initConsoleDrag();
        this._initConsoleScrollDetection();
        this._startPpsMeter();
    }

    toggleMiniConsole(tab) {
        const win = document.getElementById('miniConsoleWindow');
        if (!win) return;
        if (win.classList.contains('hidden')) {
            this.showMiniConsole(tab);
        } else {
            this.hideMiniConsole();
        }
    }

    showMiniConsole(tab) {
        const win = document.getElementById('miniConsoleWindow');
        if (!win) return;
        win.classList.remove('hidden');
        if (win.classList.contains('minimized')) {
            win.classList.remove('minimized');
        }
        if (tab) {
            this.switchConsoleTab(tab);
        }
        this.unreadErrorsCount = 0;
        this.updateConsoleBadges();
        this.scrollConsoleToBottom();
    }

    hideMiniConsole() {
        const win = document.getElementById('miniConsoleWindow');
        if (win) win.classList.add('hidden');
    }

    switchConsoleTab(tab) {
        this.consoleActiveTab = tab;
        const tabDebug = document.getElementById('tabBtnDebugLogs');
        const tabPacket = document.getElementById('tabBtnPacketLogs');
        const paneDebug = document.getElementById('paneDebugLogs');
        const panePacket = document.getElementById('panePacketLogs');

        if (tab === 'packet') {
            if (tabDebug) tabDebug.classList.remove('active');
            if (tabPacket) tabPacket.classList.add('active');
            if (paneDebug) paneDebug.classList.remove('active');
            if (panePacket) panePacket.classList.add('active');
            this.renderPacketLogs();
        } else {
            if (tabDebug) tabDebug.classList.add('active');
            if (tabPacket) tabPacket.classList.remove('active');
            if (paneDebug) paneDebug.classList.add('active');
            if (panePacket) panePacket.classList.remove('active');
            this.renderDebugLogs();
        }
        this.scrollConsoleToBottom();
    }

    // ─── Realtime Event Handlers ──────────────────────────────────────────

    onLogEvent(entry) {
        if (!entry) return;
        this.debugLogs.push(entry);
        if (this.debugLogs.length > 1000) {
            this.debugLogs.shift();
        }

        const isErr = entry.level === 'ERROR' || entry.level === 'CRITICAL';
        if (isErr) {
            this.unreadErrorsCount += 1;
        }

        this.updateConsoleBadges();

        if (this.consolePaused) return;

        // If currently in debug tab and matches filters, append to DOM directly
        if (this.consoleActiveTab === 'debug' && this._matchesDebugFilter(entry)) {
            const container = document.getElementById('terminalDebugContent');
            if (container) {
                const empty = container.querySelector('.log-empty-state');
                if (empty) empty.remove();

                const el = document.createElement('div');
                el.innerHTML = this._createLogEntryHtml(entry);
                container.appendChild(el.firstElementChild);

                // Cap DOM children
                while (container.children.length > 500) {
                    container.removeChild(container.firstChild);
                }

                if (this.consoleAutoScroll) {
                    this.scrollConsoleToBottom();
                }
            }
        }
    }

    onPacketEvent(entry) {
        if (!entry) return;
        this.packetLogs.push(entry);
        if (this.packetLogs.length > 1000) {
            this.packetLogs.shift();
        }

        this.recentPacketTimestamps.push(Date.now());
        this.updateConsoleBadges();

        if (this.consolePaused) return;

        // If currently in packet tab and matches filters, append to DOM directly
        if (this.consoleActiveTab === 'packet' && this._matchesPacketFilter(entry)) {
            const list = document.getElementById('packetStreamList');
            if (list) {
                const empty = list.querySelector('.log-empty-state');
                if (empty) empty.remove();

                const el = document.createElement('div');
                el.innerHTML = this._createPacketRowHtml(entry);
                list.appendChild(el.firstElementChild);

                // Cap DOM children
                while (list.children.length > 500) {
                    list.removeChild(list.firstChild);
                }

                if (this.consoleAutoScroll) {
                    this.scrollConsoleToBottom();
                }
            }
        }
    }

    onLogsCleared(type) {
        if (type === 'debug' || type === 'all') {
            this.debugLogs = [];
            this.renderDebugLogs();
        }
        if (type === 'packet' || type === 'all') {
            this.packetLogs = [];
            this.renderPacketLogs();
        }
        this.unreadErrorsCount = 0;
        this.updateConsoleBadges();
        this.showToast('Logs buffer cleared', 'info');
    }

    // ─── Rendering ────────────────────────────────────────────────────────

    _matchesDebugFilter(entry) {
        if (this.consoleFilterLevel !== 'ALL' && entry.level !== this.consoleFilterLevel) {
            return false;
        }
        if (this.consoleSearchDebug) {
            const txt = (entry.message || '') + ' ' + (entry.name || '') + ' ' + (entry.module || '') + ' ' + (entry.funcName || '');
            if (!txt.toLowerCase().includes(this.consoleSearchDebug)) return false;
        }
        return true;
    }

    _matchesPacketFilter(entry) {
        if (this.consoleFilterAction !== 'ALL') {
            const act = entry.action || '';
            const proto = entry.proto || '';
            if (this.consoleFilterAction === 'ARP' || this.consoleFilterAction === 'IPv4' || this.consoleFilterAction === 'IPv6') {
                if (proto !== this.consoleFilterAction) return false;
            } else if (!act.includes(this.consoleFilterAction)) {
                return false;
            }
        }
        if (this.consoleSearchPacket) {
            const txt = (entry.src || '') + ' ' + (entry.dst || '') + ' ' + (entry.details || '') + ' ' + (entry.action || '');
            if (!txt.toLowerCase().includes(this.consoleSearchPacket)) return false;
        }
        return true;
    }

    _createLogEntryHtml(entry) {
        const isErr = entry.level === 'ERROR' || entry.level === 'CRITICAL';
        const isWarn = entry.level === 'WARNING' || entry.level === 'WARN';
        const rowClass = isErr ? 'is-error' : (isWarn ? 'is-warn' : '');
        const time = entry.time_str || new Date(entry.timestamp * 1000).toLocaleTimeString();
        const level = entry.level || 'INFO';
        const module = entry.module ? `[${entry.module}]` : '';
        const msg = this._escapeHtml(entry.message || entry.formatted || '');

        return `
            <div class="log-entry-row ${rowClass}" data-id="${entry.id}">
                <span class="log-entry-time">${time}</span>
                <span class="log-entry-level ${level}">${level}</span>
                <span class="log-entry-module">${module}</span>
                <span class="log-entry-msg">${msg}</span>
            </div>
        `;
    }

    _createPacketRowHtml(entry) {
        const time = entry.time_str || new Date(entry.timestamp * 1000).toLocaleTimeString();
        const action = entry.action || 'PKT';
        const proto = entry.proto || 'ETH';
        const src = this._escapeHtml(entry.src || '-');
        const dst = this._escapeHtml(entry.dst || '-');
        const length = entry.length ? (entry.length > 1024 ? `${(entry.length/1024).toFixed(1)} KB` : `${entry.length} B`) : '-';
        const details = this._escapeHtml(entry.details || '');
        const actClass = action.toLowerCase().replace('_', '-');

        return `
            <div class="packet-row action-${actClass}" data-id="${entry.id}">
                <span class="pkt-time">${time}</span>
                <span class="pkt-action ${action}">${action}</span>
                <span class="pkt-proto">${proto}</span>
                <span class="pkt-flow" title="${src} → ${dst}">${src} <span class="flow-arrow">→</span> ${dst}</span>
                <span class="pkt-size">${length}</span>
                <span class="pkt-details" title="${details}">${details}</span>
            </div>
        `;
    }

    renderDebugLogs() {
        const container = document.getElementById('terminalDebugContent');
        if (!container) return;

        const filtered = this.debugLogs.filter(e => this._matchesDebugFilter(e));
        if (!filtered.length) {
            container.innerHTML = `<div class="log-empty-state">No matching system logs. (Level: ${this.consoleFilterLevel})</div>`;
            return;
        }

        container.innerHTML = filtered.map(e => this._createLogEntryHtml(e)).join('');
        if (this.consoleAutoScroll) {
            this.scrollConsoleToBottom();
        }
    }

    renderPacketLogs() {
        const list = document.getElementById('packetStreamList');
        if (!list) return;

        const filtered = this.packetLogs.filter(e => this._matchesPacketFilter(e));
        if (!filtered.length) {
            list.innerHTML = `<div class="log-empty-state">No matching packet events. (Filter: ${this.consoleFilterAction})</div>`;
            return;
        }

        list.innerHTML = filtered.map(e => this._createPacketRowHtml(e)).join('');
        if (this.consoleAutoScroll) {
            this.scrollConsoleToBottom();
        }
    }

    updateConsoleBadges() {
        const badgeTop = document.getElementById('consoleBadge');
        if (badgeTop) {
            const total = this.debugLogs.length + this.packetLogs.length;
            badgeTop.textContent = total > 999 ? '999+' : total;
            if (this.unreadErrorsCount > 0) {
                badgeTop.classList.add('has-errors');
            } else {
                badgeTop.classList.remove('has-errors');
            }
        }

        const bDebug = document.getElementById('badgeDebugCount');
        if (bDebug) bDebug.textContent = this.debugLogs.length;

        const bPacket = document.getElementById('badgePacketCount');
        if (bPacket) bPacket.textContent = this.packetLogs.length;

        const footerText = document.getElementById('footerLogStatusText');
        if (footerText) {
            footerText.textContent = `Buffer: ${this.debugLogs.length}/1000 logs | ${this.packetLogs.length}/1000 pkts`;
        }
    }

    async setSystemLogging(enabled) {
        try {
            const res = await fetch('/api/logs/system_logging', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: Boolean(enabled) })
            });
            const data = await res.json();
            if (data.success) {
                this.updateSystemLoggingUI(data.logging_enabled);
                this.showToast(`System logging ${data.logging_enabled ? 'enabled (Full diagnostics)' : 'disabled (0% CPU overhead) ⚡'}`, 'info');
            }
        } catch (e) {
            this.showToast('Could not toggle system logging', 'error');
        }
    }

    async setPacketCapture(enabled) {
        try {
            const res = await fetch('/api/logs/packet_capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: Boolean(enabled) })
            });
            const data = await res.json();
            if (data.success) {
                this.updatePacketCaptureUI(data.packet_capture_enabled);
                this.showToast(`Packet telemetry ${data.packet_capture_enabled ? 'resumed 🛰️' : 'paused (CPU saver) ⚡'}`, 'info');
            }
        } catch (e) {
            this.showToast('Could not toggle packet capture', 'error');
        }
    }

    async toggleCpuSaverMode() {
        const target = !this.cpuSaverMode;
        try {
            const res = await fetch('/api/logs/cpu_saver', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: target })
            });
            const data = await res.json();
            if (data.success) {
                this.updateCpuSaverUI(data.cpu_saver_mode, data.status);
                if (data.cpu_saver_mode) {
                    this.showToast('🍃 CPU Saver Mode ACTIVE: Logging & packet telemetry disabled for 0% CPU overhead!', 'success');
                } else {
                    this.showToast('⚡ CPU Saver Mode DISABLED: Real-time logging & telemetry restored.', 'info');
                }
            }
        } catch (e) {
            this.showToast('Could not toggle CPU saver mode', 'error');
        }
    }

    updateSystemLoggingUI(enabled) {
        this.systemLoggingEnabled = Boolean(enabled);
        const toggle = document.getElementById('toggleSystemLogging');
        if (toggle) toggle.checked = this.systemLoggingEnabled;

        const label = document.getElementById('labelSystemLoggingSwitch');
        if (label) label.textContent = this.systemLoggingEnabled ? 'Logging' : 'Logging (Off)';

        const banner = document.getElementById('bannerCpuSaverDebug');
        if (banner) banner.style.display = this.systemLoggingEnabled ? 'none' : 'flex';

        const settingSelect = document.getElementById('settingSystemLogging');
        if (settingSelect) settingSelect.value = this.systemLoggingEnabled ? '1' : '0';

        const badge = document.getElementById('badgeSystemLoggingStatus');
        if (badge) {
            badge.textContent = this.systemLoggingEnabled ? 'Enabled' : 'Disabled (0% Overhead)';
            badge.className = `badge ${this.systemLoggingEnabled ? 'badge-whitelist' : 'badge-blacklist'}`;
        }

        this._syncCpuSaverState();
    }

    updatePacketCaptureUI(enabled) {
        this.packetCaptureEnabled = Boolean(enabled);
        const toggle = document.getElementById('togglePacketCapture');
        if (toggle) toggle.checked = this.packetCaptureEnabled;

        const label = document.getElementById('labelPacketCaptureSwitch');
        if (label) label.textContent = this.packetCaptureEnabled ? 'Capture' : 'Capture (Off)';

        const banner = document.getElementById('bannerCpuSaverPacket');
        if (banner) banner.style.display = this.packetCaptureEnabled ? 'none' : 'flex';

        const settingSelect = document.getElementById('settingPacketCapture');
        if (settingSelect) settingSelect.value = this.packetCaptureEnabled ? '1' : '0';

        const badge = document.getElementById('badgePacketCaptureStatus');
        if (badge) {
            badge.textContent = this.packetCaptureEnabled ? 'Enabled' : 'Disabled (0% Overhead)';
            badge.className = `badge ${this.packetCaptureEnabled ? 'badge-whitelist' : 'badge-blacklist'}`;
        }

        this._syncCpuSaverState();
    }

    _syncCpuSaverState() {
        const isSaver = (!this.systemLoggingEnabled) && (!this.packetCaptureEnabled);
        this.cpuSaverMode = isSaver;

        const btnWin = document.getElementById('btnConsoleCpuSaver');
        if (btnWin) {
            if (isSaver) {
                btnWin.classList.add('active');
                btnWin.title = "CPU Saver Mode ACTIVE (Logging & Telemetry Disabled) — Click to resume";
            } else {
                btnWin.classList.remove('active');
                btnWin.title = "Toggle CPU Saver Mode (Disable logging to save CPU horsepower)";
            }
        }

        const btnSettings = document.getElementById('btnToggleCpuSaverSettings');
        const labelSettings = document.getElementById('labelCpuSaverSettingsBtn');
        if (btnSettings) {
            if (isSaver) {
                btnSettings.classList.add('btn-primary');
                btnSettings.classList.remove('btn-secondary');
            } else {
                btnSettings.classList.remove('btn-primary');
                btnSettings.classList.add('btn-secondary');
            }
        }
        if (labelSettings) {
            labelSettings.textContent = isSaver ? 'Disable CPU Saver' : 'Enable CPU Saver';
        }
    }

    updateCpuSaverUI(isSaver, status) {
        this.cpuSaverMode = Boolean(isSaver);
        if (isSaver) {
            this.updateSystemLoggingUI(false);
            this.updatePacketCaptureUI(false);
        } else {
            if (status && status.logging_enabled !== undefined) {
                this.updateSystemLoggingUI(status.logging_enabled);
            } else {
                this.updateSystemLoggingUI(true);
            }
            if (status && status.packet_capture_enabled !== undefined) {
                this.updatePacketCaptureUI(status.packet_capture_enabled);
            } else {
                this.updatePacketCaptureUI(true);
            }
        }
        this._syncCpuSaverState();
    }

    updateLogStatusUI(status) {
        if (!status) return;
        if (status.log_level) {
            this.updateLogLevelUI(status.log_level);
        }
        if (status.logging_enabled !== undefined) {
            this.updateSystemLoggingUI(status.logging_enabled);
        }
        if (status.packet_capture_enabled !== undefined) {
            this.updatePacketCaptureUI(status.packet_capture_enabled);
        }
        if (status.cpu_saver_mode !== undefined) {
            this._syncCpuSaverState();
        }
    }

    updateLogLevelUI(level) {
        const label = document.getElementById('labelCurrentLogLevel');
        if (label) {
            label.innerHTML = `<span class="level-indicator-dot"></span><span>Level: ${level}</span>`;
        }
        const select = document.getElementById('selectLogLevel');
        if (select && select.value !== level && select.value === 'ALL') {
            // Keep user selection if on ALL, otherwise sync
        }
    }

    // ─── Actions & Controls ───────────────────────────────────────────────

    async clearConsoleLogs() {
        const targetType = this.consoleActiveTab === 'debug' ? 'debug' : 'packet';
        try {
            await fetch('/api/logs/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: targetType })
            });
            this.onLogsCleared(targetType);
        } catch (e) {
            this.showToast('Could not clear logs', 'error');
        }
    }

    exportConsoleLogs() {
        const isDebug = this.consoleActiveTab === 'debug';
        const data = isDebug ? this.debugLogs : this.packetLogs;
        if (!data || !data.length) {
            this.showToast('No logs to export', 'info');
            return;
        }

        const textLines = isDebug
            ? data.map(e => `[${e.time_str || ''}] [${e.level || 'INFO'}] ${e.name || ''}: ${e.message || ''}`).join('\n')
            : data.map(e => `[${e.time_str || ''}] [${e.action || ''}] ${e.proto || ''} ${e.src || ''} -> ${e.dst || ''} (${e.length || 0}B) ${e.details || ''}`).join('\n');

        navigator.clipboard.writeText(textLines).then(() => {
            this.showToast(`📋 Copied ${data.length} ${isDebug ? 'system logs' : 'packet events'} to clipboard!`, 'success');
        }).catch(() => {
            // Fallback download
            const blob = new Blob([textLines], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `throttwin-${isDebug ? 'system-logs' : 'packet-stream'}-${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Downloaded logs export file', 'success');
        });
    }

    toggleConsoleAutoScroll() {
        this.consoleAutoScroll = !this.consoleAutoScroll;
        const btn = document.getElementById('btnConsoleAutoScroll');
        const footerStatus = document.getElementById('footerAutoScrollStatus');
        if (btn) {
            if (this.consoleAutoScroll) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        }
        if (footerStatus) {
            footerStatus.innerHTML = this.consoleAutoScroll
                ? `<i class="fa-solid fa-lock"></i> Auto-Scroll: ON`
                : `<i class="fa-solid fa-lock-open" style="color:var(--text-muted);"></i> Auto-Scroll: OFF`;
        }
        if (this.consoleAutoScroll) {
            this.scrollConsoleToBottom();
        }
    }

    toggleConsolePause() {
        this.consolePaused = !this.consolePaused;
        const btn = document.getElementById('btnConsolePause');
        const footerStream = document.getElementById('footerStreamStatus');
        const liveDot = document.getElementById('consoleLiveDot');

        if (btn) {
            if (this.consolePaused) {
                btn.innerHTML = `<i class="fa-solid fa-play"></i>`;
                btn.title = "Resume Live Stream";
                btn.classList.add('active');
            } else {
                btn.innerHTML = `<i class="fa-solid fa-pause"></i>`;
                btn.title = "Pause Live Stream";
                btn.classList.remove('active');
            }
        }

        if (footerStream) {
            footerStream.innerHTML = this.consolePaused
                ? `<i class="fa-solid fa-pause" style="color:var(--accent-amber);"></i> Stream Paused`
                : `<i class="fa-solid fa-circle-dot green"></i> Streaming Live`;
        }

        if (liveDot) {
            liveDot.style.background = this.consolePaused ? '#f59e0b' : '#00f5a0';
            liveDot.style.boxShadow = this.consolePaused ? '0 0 6px #f59e0b' : '0 0 6px #00f5a0';
        }

        if (!this.consolePaused) {
            if (this.consoleActiveTab === 'debug') this.renderDebugLogs();
            else this.renderPacketLogs();
        }
    }

    toggleConsoleMaximize() {
        const win = document.getElementById('miniConsoleWindow');
        const icon = document.getElementById('iconConsoleMaximize');
        if (!win) return;

        win.classList.toggle('maximized');
        if (win.classList.contains('maximized')) {
            if (icon) icon.className = 'fa-solid fa-down-left-and-up-right-to-center';
        } else {
            if (icon) icon.className = 'fa-regular fa-window-maximize';
        }
    }

    toggleConsoleMinimize() {
        const win = document.getElementById('miniConsoleWindow');
        if (!win) return;
        win.classList.toggle('minimized');
    }

    scrollConsoleToBottom() {
        if (!this.consoleAutoScroll) return;
        requestAnimationFrame(() => {
            const container = document.getElementById('terminalDebugContainer');
            if (container && this.consoleActiveTab === 'debug') {
                container.scrollTop = container.scrollHeight;
            }
            const list = document.getElementById('packetStreamList');
            if (list && this.consoleActiveTab === 'packet') {
                list.scrollTop = list.scrollHeight;
            }
        });
    }

    _initConsoleDrag() {
        const header = document.getElementById('miniConsoleHeader');
        const win = document.getElementById('miniConsoleWindow');
        if (!header || !win) return;

        let startX = 0, startY = 0, initialLeft = 0, initialTop = 0;

        const onMouseDown = (e) => {
            if (e.target.closest('button') || e.target.closest('select') || e.target.closest('input')) {
                return;
            }
            if (win.classList.contains('maximized')) return;

            this.isDraggingConsole = true;
            const rect = win.getBoundingClientRect();
            startX = e.clientX;
            startY = e.clientY;
            initialLeft = rect.left;
            initialTop = rect.top;

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
            e.preventDefault();
        };

        const onMouseMove = (e) => {
            if (!this.isDraggingConsole) return;
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;

            win.style.left = `${Math.max(10, Math.min(window.innerWidth - win.offsetWidth - 10, initialLeft + dx))}px`;
            win.style.top = `${Math.max(10, Math.min(window.innerHeight - 60, initialTop + dy))}px`;
            win.style.bottom = 'auto';
            win.style.right = 'auto';
        };

        const onMouseUp = () => {
            this.isDraggingConsole = false;
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        };

        header.addEventListener('mousedown', onMouseDown);
    }

    _initConsoleScrollDetection() {
        const debugContainer = document.getElementById('terminalDebugContainer');
        const packetList = document.getElementById('packetStreamList');

        const onScroll = (el) => {
            if (!el) return;
            const isNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
            if (!isNearBottom && this.consoleAutoScroll) {
                // User scrolled up manually
                this.consoleAutoScroll = false;
                const btn = document.getElementById('btnConsoleAutoScroll');
                if (btn) btn.classList.remove('active');
                const footerStatus = document.getElementById('footerAutoScrollStatus');
                if (footerStatus) {
                    footerStatus.innerHTML = `<i class="fa-solid fa-lock-open" style="color:var(--text-muted);"></i> Auto-Scroll: OFF`;
                }
            } else if (isNearBottom && !this.consoleAutoScroll) {
                // User scrolled back to bottom
                this.consoleAutoScroll = true;
                const btn = document.getElementById('btnConsoleAutoScroll');
                if (btn) btn.classList.add('active');
                const footerStatus = document.getElementById('footerAutoScrollStatus');
                if (footerStatus) {
                    footerStatus.innerHTML = `<i class="fa-solid fa-lock"></i> Auto-Scroll: ON`;
                }
            }
        };

        if (debugContainer) debugContainer.addEventListener('scroll', () => onScroll(debugContainer));
        if (packetList) packetList.addEventListener('scroll', () => onScroll(packetList));
    }

    _startPpsMeter() {
        setInterval(() => {
            const now = Date.now();
            const oneSecAgo = now - 1000;
            this.recentPacketTimestamps = this.recentPacketTimestamps.filter(t => t >= oneSecAgo);
            const pps = this.recentPacketTimestamps.length;
            const badge = document.getElementById('badgePpsRate');
            if (badge) {
                badge.textContent = `${pps} pps`;
                if (pps > 0) {
                    badge.style.background = 'rgba(0, 245, 160, 0.25)';
                    badge.style.borderColor = '#00f5a0';
                } else {
                    badge.style.background = 'rgba(255, 255, 255, 0.05)';
                    badge.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                }
            }
        }, 1000);
    }

    _escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
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
                                this.updateTelemetryInTable(sess);
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
