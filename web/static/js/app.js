/**
 * Throttwin Web UI Client Application
 * Dynamic SSE-powered real-time bandwidth shaper & network monitor for Windows
 */

class ThrottwinApp {
    constructor() {
        this.state = {
            status: "IDLE",
            mode: "blacklist",
            limit_mbps: 1.0,
            interface: null,
            router_ip: null,
            devices: [],
            targets: [],
            whitelisted: [],
            rules: { whitelist: {}, blacklist: {} },
            selectedIps: new Set(),
            telemetry: [],
            uptime: 0,
            autoThrottledCount: 0
        };

        this.eventSource = null;
        this.timerInterval = null;
        this.isScanning = false;

        this.init();
    }

    async init() {
        this.bindEvents();
        await this.loadInterfaces();
        await this.loadRules();
        await this.fetchStatus();
        this.initSSE();
        this.startLocalTimer();

        // Auto-trigger background scan on load if device cache is empty
        if (!this.state.devices || this.state.devices.length === 0) {
            this.triggerScan();
        }
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
        const data = payload.data || payload.state;

        switch (type) {
            case "init":
                if (payload.state) this.updateUIWithState(payload.state);
                break;

            case "devices_discovered":
                if (data.new_devices && data.new_devices.length) {
                    this.showToast(`📡 Discovered ${data.new_devices.length} new device(s) on network.`, 'info');
                }
                if (data.all_devices) {
                    this.state.devices = data.all_devices;
                    this.renderDashboardTable();
                    this.renderScannerTable();
                }
                break;

            case "device_auto_throttled":
                this.state.autoThrottledCount += 1;
                const dev = data.device || {};
                const limit = data.limit_mbps || this.state.limit_mbps;
                this.showToast(`⚡ AUTO-THROTTLED: ${dev.ip || 'Device'} (${dev.vendor || dev.mac || 'Unknown'}) capped at ${limit} Mbps!`, 'error');
                this.updateRadarBanner();
                this.fetchStatus();
                break;

            case "devices_updated":
                if (data.devices) {
                    this.state.devices = data.devices;
                    this.renderDashboardTable();
                    this.renderScannerTable();
                }
                break;

            case "target_toggled":
                if (data.state) this.updateUIWithState(data.state);
                this.showToast(`Target ${data.ip} ${data.is_throttled ? 'throttling activated' : 'throttling removed'}.`, data.is_throttled ? 'success' : 'info');
                break;

            case "limit_updated":
                this.state.limit_mbps = data.limit_mbps;
                document.getElementById('statBandwidthLimit').innerHTML = `${this.state.limit_mbps} <span class="unit">Mbps</span>`;
                const radarLimit = document.getElementById('radarLimitVal');
                if (radarLimit) radarLimit.textContent = this.state.limit_mbps;
                this.showToast(`⚡ Live bandwidth limit adjusted to ${this.state.limit_mbps} Mbps!`, 'success');
                break;

            case "session_started":
                this.state.autoThrottledCount = 0;
                this.updateUIWithState(data);
                this.showToast('🚀 Bandwidth shaping session is now ACTIVE.', 'success');
                break;

            case "session_stopped":
                this.state.autoThrottledCount = 0;
                this.updateUIWithState(data);
                this.showToast('🛑 Session stopped. Network traffic restored.', 'info');
                break;

            case "cache_cleared":
                this.state.devices = [];
                this.state.selectedIps.clear();
                this.renderDashboardTable();
                this.renderScannerTable();
                break;
        }
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

        // Mode Toggles (Blacklist vs Whitelist)
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

        // Live Apply Button for Running Sessions
        const btnApplyLive = document.getElementById('btnApplyLiveLimit');
        if (btnApplyLive) {
            btnApplyLive.addEventListener('click', () => this.applyLiveLimit());
        }

        // Session Control Button
        const btnSession = document.getElementById('btnSessionControl');
        if (btnSession) {
            btnSession.addEventListener('click', () => this.toggleSession());
        }

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

        // Save Settings
        const btnSaveSet = document.getElementById('btnSaveSettings');
        if (btnSaveSet) btnSaveSet.addEventListener('click', () => this.saveSettings());

        // Select All Checkbox
        const selectAllCb = document.getElementById('selectAllCheckbox');
        if (selectAllCb) {
            selectAllCb.addEventListener('change', (e) => {
                const isChecked = e.target.checked;
                document.querySelectorAll('.device-row-check').forEach(cb => {
                    cb.checked = isChecked;
                    const ip = cb.dataset.ip;
                    if (isChecked) {
                        this.state.selectedIps.add(ip);
                    } else {
                        this.state.selectedIps.delete(ip);
                    }
                });
            });
        }
    }

    handleLimitSelection(newLimit) {
        this.state.limit_mbps = newLimit;
        const statLim = document.getElementById('statBandwidthLimit');
        if (statLim) statLim.innerHTML = `${newLimit} <span class="unit">Mbps</span>`;
        const radarLim = document.getElementById('radarLimitVal');
        if (radarLim) radarLim.textContent = newLimit;

        const btnApplyLive = document.getElementById('btnApplyLiveLimit');
        if (btnApplyLive) {
            if (this.state.status === "RUNNING") {
                btnApplyLive.style.display = 'inline-flex';
            } else {
                btnApplyLive.style.display = 'none';
            }
        }
    }

    async applyLiveLimit() {
        try {
            const res = await fetch('/api/session/limit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ limit_mbps: this.state.limit_mbps })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast(`Applied limit: ${this.state.limit_mbps} Mbps live!`, 'success');
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
        }
    }

    setMode(mode) {
        this.state.mode = mode;
        const btnBl = document.getElementById('btnModeBlacklist');
        const btnWl = document.getElementById('btnModeWhitelist');
        if (btnBl) btnBl.classList.toggle('active', mode === 'blacklist');
        if (btnWl) btnWl.classList.toggle('active', mode === 'whitelist');
        const subtitle = document.getElementById('statModeSubtitle');
        if (subtitle) subtitle.textContent = `Mode: ${mode.charAt(0).toUpperCase() + mode.slice(1)}`;

        // Clear selection to reset defaults for the newly chosen mode
        this.state.selectedIps.clear();
        this.updateRadarBanner();
        this.renderDashboardTable();
    }

    updateRadarBanner() {
        const banner = document.getElementById('dynamicRadarBanner');
        if (!banner) return;

        if (this.state.status === "RUNNING" && this.state.mode === "whitelist") {
            banner.style.display = 'flex';
            const radarLim = document.getElementById('radarLimitVal');
            const radarCount = document.getElementById('radarThrottledCount');
            if (radarLim) radarLim.textContent = this.state.limit_mbps;
            if (radarCount) radarCount.textContent = this.state.autoThrottledCount;
        } else {
            banner.style.display = 'none';
        }
    }

    async loadInterfaces() {
        try {
            const res = await fetch('/api/interfaces');
            const data = await res.json();
            if (data.success) {
                const select = document.getElementById('settingInterface');
                if (select) {
                    select.innerHTML = '';
                    data.interfaces.forEach(iface => {
                        const opt = document.createElement('option');
                        opt.value = iface;
                        opt.textContent = iface;
                        if (iface === data.default_interface) opt.selected = true;
                        select.appendChild(opt);
                    });
                }

                this.state.interface = data.default_interface;
                this.state.router_ip = data.default_gateway || '192.168.1.1';
                const routerInp = document.getElementById('settingRouterIp');
                if (routerInp) routerInp.value = this.state.router_ip;
            }
        } catch (e) {
            console.error("Failed to load interfaces:", e);
        }
    }

    async loadRules() {
        try {
            const res = await fetch('/api/rules');
            const data = await res.json();
            if (data.success) {
                this.state.rules = data.rules;
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
                this.updateUIWithState(data.data);
            }
        } catch (e) {
            console.error("Failed to fetch status:", e);
        }
    }

    updateUIWithState(state) {
        this.state.status = state.status;
        this.state.devices = state.devices || [];
        this.state.targets = state.targets || [];
        this.state.whitelisted = state.whitelisted || [];
        this.state.telemetry = state.telemetry || [];
        this.state.uptime = state.uptime || 0;
        if (state.limit_mbps) this.state.limit_mbps = state.limit_mbps;
        if (state.operational_mode) this.state.mode = state.operational_mode;

        // Update Session Status Pill & Control Button
        const pill = document.getElementById('sessionStatusPill');
        const text = document.getElementById('sessionStatusText');
        const btn = document.getElementById('btnSessionControl');
        const timer = document.getElementById('sessionTimer');
        const btnApplyLive = document.getElementById('btnApplyLiveLimit');

        if (state.status === "RUNNING") {
            if (pill) pill.className = 'session-status-pill running';
            if (text) text.textContent = 'ACTIVE';
            if (btn) {
                btn.className = 'btn btn-danger btn-glow';
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-stop"></i> <span>Stop Session</span>';
            }
            if (timer) timer.style.display = 'flex';
        } else {
            if (pill) pill.className = 'session-status-pill idle';
            if (text) text.textContent = 'IDLE';
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
        if (btnBl) btnBl.classList.toggle('active', this.state.mode === 'blacklist');
        if (btnWl) btnWl.classList.toggle('active', this.state.mode === 'whitelist');
        const subtitle = document.getElementById('statModeSubtitle');
        if (subtitle) subtitle.textContent = `Mode: ${this.state.mode.charAt(0).toUpperCase() + this.state.mode.slice(1)}`;

        // Metrics
        const statThroughput = document.getElementById('statThroughput');
        if (statThroughput) statThroughput.innerHTML = `${state.total_speed_kbps || '0.0'} <span class="unit">KB/s</span>`;
        const statThroughputMbps = document.getElementById('statThroughputMbps');
        if (statThroughputMbps) statThroughputMbps.textContent = `${state.total_speed_mbps || '0.00'} Mbps total speed`;
        const statTargetCount = document.getElementById('statTargetCount');
        if (statTargetCount) statTargetCount.textContent = state.target_count || 0;
        const statLimit = document.getElementById('statBandwidthLimit');
        if (statLimit) statLimit.innerHTML = `${state.limit_mbps || this.state.limit_mbps} <span class="unit">Mbps</span>`;
        const statData = document.getElementById('statDataTransferred');
        if (statData) statData.innerHTML = `${state.total_data_mb || '0.00'} <span class="unit">MB</span>`;

        this.updateRadarBanner();
        this.renderDashboardTable();
    }

    /* ==========================================================
       3. DASHBOARD & LIVE TELEMETRY RENDERING
       ========================================================== */
    renderDashboardTable() {
        const tbody = document.getElementById('devicesTableBody');
        if (!tbody) return;

        if (!this.state.devices.length) {
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
        this.state.telemetry.forEach(t => {
            teleMap[t.ip] = t;
        });

        // Set of active targets actually being throttled
        const runningTargetIps = new Set(
            this.state.targets.map(t => (typeof t === 'string' ? t : t.ip))
        );

        // Global whitelist MACs
        const globalWl = this.state.rules.whitelist || {};
        const globalBl = this.state.rules.blacklist || {};

        const isRunning = this.state.status === "RUNNING";
        tbody.innerHTML = '';

        this.state.devices.forEach(dev => {
            const tr = document.createElement('tr');
            const macLower = (dev.mac || '').toLowerCase();
            const ip = dev.ip || '-';

            const isGlobalWl = macLower in globalWl;
            const isGlobalBl = macLower in globalBl;
            const wlLabel = globalWl[macLower];
            const blLabel = globalBl[macLower];

            const isCurrentlyThrottled = runningTargetIps.has(ip);

            // Auto select defaults before session starts:
            // - In Blacklist mode: default check Blacklisted targets
            // - In Whitelist mode: default check Safe/Whitelisted devices
            let isChecked = this.state.selectedIps.has(ip);
            if (!isRunning && !this.state.selectedIps.size) {
                if (this.state.mode === "blacklist" && isGlobalBl) isChecked = true;
                if (this.state.mode === "whitelist" && isGlobalWl) isChecked = true;
                if (isChecked) this.state.selectedIps.add(ip);
            }

            // Rule Badge
            let badgeHtml = '<span class="text-muted">-</span>';
            if (isGlobalWl) {
                badgeHtml = `<span class="badge badge-whitelist"><i class="fa-solid fa-shield"></i> Safe ${wlLabel ? `(${wlLabel})` : ''}</span>`;
            } else if (isGlobalBl) {
                badgeHtml = `<span class="badge badge-blacklist"><i class="fa-solid fa-skull"></i> Target ${blLabel ? `(${blLabel})` : ''}</span>`;
            }

            // Telemetry stats & speed meter
            const tele = teleMap[ip];
            let speedHtml = '<span class="text-muted">0.0 KB/s</span>';
            let onlineDot = '<span class="status-dot-sm offline" title="Offline / Idle"></span>';
            let newBadge = '';

            if (isRunning && isCurrentlyThrottled) {
                const speedKbps = tele ? tele.speed_kbps : 0.0;
                const speedMbps = tele ? tele.speed_mbps : 0.00;
                const maxCapKbps = (this.state.limit_mbps * 125.0); // 1 Mbps = 125 KB/s
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

            // Status Column & Live Switch
            let statusToggleHtml = '';
            if (isRunning) {
                if (isGlobalWl) {
                    // Safe devices are protected and bypassed
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
                if (this.state.mode === "whitelist") {
                    statusToggleHtml = isGlobalWl || isChecked
                        ? `<span class="badge badge-whitelist"><i class="fa-solid fa-shield"></i> Safe / Whitelisted</span>`
                        : `<span class="badge badge-blacklist"><i class="fa-solid fa-crosshairs"></i> Will Throttle</span>`;
                } else {
                    statusToggleHtml = isChecked 
                        ? `<span class="badge badge-blacklist"><i class="fa-solid fa-crosshairs"></i> Target</span>`
                        : `<span class="badge badge-idle">Idle</span>`;
                }
            }

            // Hostname & Vendor Display
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
                        this.state.selectedIps.add(ip);
                    } else {
                        this.state.selectedIps.delete(ip);
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
                    const shouldThrottle = e.target.checked;
                    this.hotToggleTarget(ip, shouldThrottle);
                });
            }

            tbody.appendChild(tr);
        });
    }

    async hotToggleTarget(ip, shouldThrottle) {
        try {
            const res = await fetch('/api/target/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, should_throttle: shouldThrottle })
            });
            const data = await res.json();
            if (data.success) {
                this.updateUIWithState(data.state);
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
        if (!tbody) return;

        if (!this.state.devices.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><p>No devices discovered yet.</p></td></tr>`;
            return;
        }

        tbody.innerHTML = '';
        this.state.devices.forEach(dev => {
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

        const wl = this.state.rules.whitelist || {};
        const bl = this.state.rules.blacklist || {};

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
       4. SESSION ACTIONS
       ========================================================== */
    async toggleSession() {
        const btn = document.getElementById('btnSessionControl');

        if (this.state.status === "RUNNING") {
            // Immediate UI feedback
            this.state.status = "STOPPING";
            if (btn) {
                btn.disabled = true;
                btn.className = 'btn btn-secondary';
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Stopping...</span>';
            }

            try {
                const res = await fetch('/api/session/stop', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    this.showToast('Session stopped successfully.', 'info');
                    this.updateUIWithState(data.state);
                } else {
                    this.showToast(data.error || 'Failed to stop session.', 'error');
                }
            } catch (e) {
                this.showToast('Network error while stopping session.', 'error');
            } finally {
                if (btn) btn.disabled = false;
            }
        } else if (this.state.status !== "STOPPING") {
            // Selected devices array
            const selectedDevices = this.state.devices.filter(d => this.state.selectedIps.has(d.ip));
            const globalWlMacs = new Set(Object.keys(this.state.rules.whitelist || {}).map(m => m.toLowerCase()));

            let targets = [];
            let whitelisted = [];

            if (this.state.mode === "blacklist") {
                // In Blacklist mode: throttle selected devices (except any in global whitelist)
                targets = selectedDevices.filter(d => !globalWlMacs.has((d.mac || '').toLowerCase()));
                whitelisted = this.state.devices.filter(d => globalWlMacs.has((d.mac || '').toLowerCase()));
                if (!targets.length) {
                    this.showToast('Please select at least one device to throttle.', 'error');
                    return;
                }
            } else {
                // In Whitelist mode:
                // Safe devices = (all devices with global whitelist MAC) + (all selected devices)
                const safeMacs = new Set([
                    ...globalWlMacs,
                    ...selectedDevices.map(d => (d.mac || '').toLowerCase()).filter(Boolean)
                ]);
                const safeIps = new Set(selectedDevices.map(d => d.ip).filter(ip => ip && ip !== '-'));

                whitelisted = this.state.devices.filter(d => {
                    const mac = (d.mac || '').toLowerCase();
                    return (mac && safeMacs.has(mac)) || safeIps.has(d.ip);
                });

                // Targets = all current devices that are NOT in the safe set
                targets = this.state.devices.filter(d => {
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
                    interface: this.state.interface,
                    router_ip: this.state.router_ip,
                    mode: this.state.mode,
                    targets: targets,
                    whitelisted: whitelisted,
                    limit_mbps: this.state.limit_mbps
                };

                const res = await fetch('/api/session/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (data.success) {
                    this.showToast(data.message || 'Session started!', 'success');
                    this.updateUIWithState(data.state);
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
            statusText.textContent = 'Active Win32 SendARP sweep in progress...';
        }

        this.showToast('Scanning network (native Win32 SendARP)...', 'info');

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    interface: this.state.interface,
                    router_ip: this.state.router_ip
                })
            });
            const data = await res.json();
            if (data.success) {
                this.state.devices = data.devices;
                this.renderDashboardTable();
                this.renderScannerTable();
                this.showToast(`Scan complete: found ${data.count} active device(s).`, 'success');
                if (statusBanner && statusText) {
                    statusBanner.className = 'scanner-status-banner';
                    statusText.textContent = `Network inventory updated: ${data.count} device(s) online.`;
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

        if (!ip && !mac) {
            this.showToast('Please enter an IP address or a MAC address.', 'error');
            return;
        }

        try {
            const res = await fetch('/api/devices/manual', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, mac, vendor })
            });
            const data = await res.json();
            if (data.success) {
                this.closeModal('manualDeviceModal');
                document.getElementById('manualDeviceIp').value = '';
                document.getElementById('manualDeviceMac').value = '';
                document.getElementById('manualDeviceVendor').value = '';
                this.showToast(`Added device: ${data.device.ip} (${data.device.mac})`, 'success');
                await this.fetchStatus();
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
                this.state.rules = data.rules;
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
                this.state.rules = data.rules;
                this.renderRules();
                this.renderDashboardTable();
                this.showToast(`Removed rule for ${mac}`, 'info');
            }
        } catch (e) {
            this.showToast('Failed to delete rule.', 'error');
        }
    }

    async clearCache() {
        if (confirm("Are you sure you want to clear device cache and saved session?")) {
            try {
                const res = await fetch('/api/devices/clear', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    this.showToast(data.message, 'success');
                    await this.fetchStatus();
                } else {
                    this.showToast(data.error, 'error');
                }
            } catch (e) {
                this.showToast('Error clearing cache.', 'error');
            }
        }
    }

    async saveSettings() {
        const iface = document.getElementById('settingInterface').value;
        const router = document.getElementById('settingRouterIp').value.trim();
        const limit = parseFloat(document.getElementById('settingDefaultLimit').value) || 1.0;

        this.state.interface = iface;
        this.state.router_ip = router;
        this.state.limit_mbps = limit;

        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface, router_ip: router, default_limit: limit })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast('Settings saved successfully.', 'success');
            } else {
                this.showToast(data.error || 'Failed to save settings.', 'error');
            }
        } catch (e) {
            this.showToast('Settings saved locally.', 'success');
        }
    }

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
        // Polling fallback every 1.5s for metrics
        setInterval(async () => {
            if (this.state.status === "RUNNING") {
                try {
                    const res = await fetch('/api/telemetry');
                    const data = await res.json();
                    if (data.success) {
                        const statThroughput = document.getElementById('statThroughput');
                        if (statThroughput) statThroughput.innerHTML = `${data.total_speed_kbps || '0.0'} <span class="unit">KB/s</span>`;
                        const statThroughputMbps = document.getElementById('statThroughputMbps');
                        if (statThroughputMbps) statThroughputMbps.textContent = `${data.total_speed_mbps || '0.00'} Mbps total speed`;
                        const statData = document.getElementById('statDataTransferred');
                        if (statData) statData.innerHTML = `${data.total_data_mb || '0.00'} <span class="unit">MB</span>`;
                        this.state.telemetry = data.telemetry || [];
                        this.renderDashboardTable();
                    }
                } catch (e) {}
            }
        }, 1500);

        // Timer interval
        this.timerInterval = setInterval(() => {
            if (this.state.status === "RUNNING") {
                this.state.uptime += 1;
                const hrs = String(Math.floor(this.state.uptime / 3600)).padStart(2, '0');
                const mins = String(Math.floor((this.state.uptime % 3600) / 60)).padStart(2, '0');
                const secs = String(this.state.uptime % 60).padStart(2, '0');
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
