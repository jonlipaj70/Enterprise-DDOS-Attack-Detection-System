/* ============================================================
   Enterprise DDoS — Main Application Logic
   ============================================================ */

class DDoSShieldApp {
    constructor() {
        this.previousValues = {};
        this.lastAttackType = null;
        this.timelineEvents = [];
        this.maxTimelineEvents = 30;
    }

    init() {
        console.log('[App] Initializing Enterprise DDoS Dashboard v2.0...');

        // Keep status monitoring usable if optional visualizations cannot initialize.
        this.showApp();

        // Initialize components
        try {
            chartManager.init();
        } catch (error) {
            console.error('[App] Chart initialization failed; continuing without charts.', error);
        }
        alertManager.init();

        // Set up WebSocket handlers
        wsManager.on('update', (data) => this.handleUpdate(data));
        wsManager.on('message', (data) => this.updateOperationalStatus(data));
        wsManager.on('connected', () => this.onConnected());
        wsManager.on('disconnected', () => this.onDisconnected());

        // Connect to backend
        wsManager.connect();

        // Set up UI interactions
        this.setupUI();
        this.loadSessionAndStatus();
        setInterval(() => this.loadReadiness(), 5000);
        setInterval(() => this.loadTrainingStatus(), 4000);
        setInterval(() => this.loadModelValidation(), 10000);

        // Start footer clock
        this.updateFooterTime();
        setInterval(() => this.updateFooterTime(), 1000);
    }

    showApp() {
        setTimeout(() => {
            const overlay = document.getElementById('loading-overlay');
            const app = document.getElementById('app');

            if (overlay) {
                overlay.classList.add('fade-out');
                setTimeout(() => {
                    overlay.style.display = 'none';
                }, 600);
            }

            if (app) {
                app.classList.remove('hidden');
            }
        }, 2200);
    }

    setupUI() {
        // Fullscreen toggle
        const fsBtn = document.getElementById('btn-fullscreen');
        if (fsBtn) {
            fsBtn.addEventListener('click', () => {
                if (!document.fullscreenElement) {
                    document.documentElement.requestFullscreen();
                } else {
                    document.exitFullscreen();
                }
            });
        }

        // Threat banner dismiss
        const dismissBtn = document.getElementById('threat-dismiss');
        if (dismissBtn) {
            dismissBtn.addEventListener('click', () => {
                const banner = document.getElementById('threat-banner');
                if (banner) banner.classList.add('hidden');
            });
        }

        const logoutBtn = document.getElementById('btn-logout');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', async () => {
                await fetch('/api/auth/logout', { method: 'POST' });
                window.location.assign('/login');
            });
        }

        const trainingForm = document.getElementById('training-form');
        if (trainingForm) {
            trainingForm.addEventListener('submit', (event) => {
                event.preventDefault();
                this.uploadTrainingCsv();
            });
        }

        const sectionLinks = [...document.querySelectorAll('.enterprise-nav a')];
        const setActiveSection = (link) => {
            if (!link) return;
            sectionLinks.forEach(item => {
                    item.classList.remove('active');
            });
            link.classList.add('active');
            const route = document.querySelector('.enterprise-route-page');
            if (route) {
                route.textContent = link.textContent.trim().toLowerCase();
            }
        };
        sectionLinks.forEach(link => {
            link.addEventListener('click', () => setActiveSection(link));
        });
        const updateActiveHash = () => {
            const linkedSection = sectionLinks.find(link => link.hash === window.location.hash);
            setActiveSection(linkedSection || sectionLinks[0]);
        };
        updateActiveHash();
        window.addEventListener('hashchange', updateActiveHash);
    }

    handleUpdate(data) {
        if (!data) return;

        this.updateOperationalStatus(data);
        this.updateSuppressionNotice(data.detection);

        // Update KPI cards
        this.updateKPIs(data.metrics, data.detection);

        // Update charts
        chartManager.update(data);

        // Update alerts
        if (data.alerts) {
            alertManager.update(data.alerts);
        }

        const detectedAttack = data.detection && data.detection.attack_type !== 'none'
            ? data.detection.attack_type
            : null;
        const activeAttack = data.current_attack || detectedAttack;

        // Update threat banner
        this.updateThreatBanner(activeAttack, data.detection);

        // Update active alerts count
        const activeCount = document.getElementById('active-alerts-count');
        if (activeCount && data.alerts) {
            activeCount.textContent = data.alerts.filter(a => a.status === 'active').length;
        }

        // ═══════ NEW: Stats Bar ═══════
        this.updateStatsBar(data.latest_features, data.detection);

        // ═══════ NEW: Forensics Panel ═══════
        this.updateForensics(data.latest_features);

        // ═══════ NEW: Attack Timeline ═══════
        this.updateTimeline(activeAttack, data.detection);
    }

    updateKPIs(metrics, detection) {
        if (!metrics) return;

        // Packet Rate
        this.animateKPI('kpi-pps-value', metrics.current_pps, true);

        // Throughput
        const bpsEl = document.getElementById('kpi-bps-value');
        if (bpsEl) bpsEl.textContent = Utils.formatBps(metrics.current_bps || 0);

        // Threat Score
        const scoreEl = document.getElementById('kpi-score-value');
        if (scoreEl && detection) {
            const score = detection.anomaly_score || 0;
            scoreEl.textContent = score.toFixed(2);

            // Color based on score
            if (score >= 0.75) {
                scoreEl.style.color = '#ef476f';
            } else if (score >= 0.5) {
                scoreEl.style.color = '#ff9f43';
            } else {
                scoreEl.style.color = '#06d6a0';
            }

            // Trend indicator
            const trendEl = document.getElementById('kpi-score-trend');
            if (trendEl) {
                const prevScore = this.previousValues.score || 0;
                const arrow = trendEl.querySelector('.trend-arrow');
                const text = trendEl.querySelector('.trend-text');

                if (score > prevScore + 0.05) {
                    arrow.textContent = '↑';
                    arrow.style.color = '#ef476f';
                    text.textContent = 'Rising';
                    text.style.color = '#ef476f';
                } else if (score < prevScore - 0.05) {
                    arrow.textContent = '↓';
                    arrow.style.color = '#06d6a0';
                    text.textContent = 'Falling';
                    text.style.color = '#06d6a0';
                } else {
                    arrow.textContent = '—';
                    arrow.style.color = '#5a6478';
                    text.textContent = 'Stable';
                    text.style.color = '#5a6478';
                }
                this.previousValues.score = score;
            }
        }

        // Alert KPI card state
        const scoreCard = document.getElementById('kpi-score');
        if (scoreCard && detection) {
            if (detection.is_anomaly) {
                scoreCard.classList.add('alert-state');
            } else {
                scoreCard.classList.remove('alert-state');
            }
        }

        // Attacks Detected
        this.animateKPI('kpi-detections-value', metrics.attacks_detected, true);

        // Detection Latency
        const latencyEl = document.getElementById('kpi-latency-value');
        if (latencyEl) latencyEl.textContent = (metrics.detection_latency_ms || 0).toFixed(0);

        // Total Processed
        const processedEl = document.getElementById('kpi-processed-value');
        if (processedEl) processedEl.textContent = Utils.formatNumber(metrics.packets_processed || 0);

        // Uptime
        const uptimeEl = document.getElementById('uptime-value');
        if (uptimeEl) uptimeEl.textContent = Utils.formatUptime(metrics.uptime_seconds || 0);
    }

    animateKPI(elementId, value, isInteger = false) {
        const el = document.getElementById(elementId);
        if (!el) return;

        this.previousValues[elementId] = value;

        if (isInteger) {
            el.textContent = Utils.formatNumber(Math.round(value));
        } else {
            el.textContent = value.toFixed(2);
        }
    }

    // ═══════ NEW: Stats Bar Update ═══════
    updateStatsBar(features, detection) {
        if (!features) return;

        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        setVal('stat-confidence', detection ? (detection.anomaly_score || 0).toFixed(3) : '—');
        setVal('stat-unique-src', Math.round(features.unique_src_ips || 0));
        setVal('stat-syn-ratio', ((features.syn_ratio || 0) * 100).toFixed(1) + '%');
        setVal('stat-syn-ack', (features.syn_to_ack_ratio || 0).toFixed(2));
        setVal('stat-avg-size', Math.round(features.avg_packet_size || 0) + 'B');
        setVal('stat-entropy', (features.src_ip_entropy || 0).toFixed(2));
        setVal('stat-zero-payload', ((features.zero_payload_ratio || 0) * 100).toFixed(1) + '%');
        setVal('stat-small-window', ((features.small_window_ratio || 0) * 100).toFixed(1) + '%');

        // Color confidence based on threat level
        const confEl = document.getElementById('stat-confidence');
        if (confEl && detection) {
            const s = detection.anomaly_score || 0;
            confEl.style.color = s >= 0.7 ? '#ef476f' : s >= 0.45 ? '#ff9f43' : '#06d6a0';
        }
    }

    // ═══════ NEW: Forensics Panel Update ═══════
    updateForensics(f) {
        if (!f) return;

        const items = [
            ['fbar-tcp',  'fval-tcp',  f.tcp_ratio || 0],
            ['fbar-udp',  'fval-udp',  f.udp_ratio || 0],
            ['fbar-icmp', 'fval-icmp', f.icmp_ratio || 0],
            ['fbar-dns',  'fval-dns',  f.dns_ratio || 0],
            ['fbar-syn',  'fval-syn',  f.syn_ratio || 0],
            ['fbar-ack',  'fval-ack',  f.ack_ratio || 0],
            ['fbar-rst',  'fval-rst',  f.rst_ratio || 0],
            ['fbar-fin',  'fval-fin',  f.fin_ratio || 0],
            ['fbar-zero', 'fval-zero', f.zero_payload_ratio || 0],
            ['fbar-swin', 'fval-swin', f.small_window_ratio || 0],
            ['fbar-frag', 'fval-frag', f.fragmentation_ratio || 0],
            ['fbar-large','fval-large',f.large_packet_ratio || 0],
        ];

        items.forEach(([barId, valId, value]) => {
            const bar = document.getElementById(barId);
            const val = document.getElementById(valId);
            if (bar) bar.style.width = `${Math.min(100, value * 100)}%`;
            if (val) val.textContent = (value * 100).toFixed(1) + '%';
        });
    }

    // ═══════ NEW: Attack Timeline Update ═══════
    updateTimeline(currentAttack, detection) {
        if (!currentAttack || currentAttack === 'none' || !detection || !detection.is_anomaly) return;

        // Only add if different from last event or enough time passed
        const lastEvent = this.timelineEvents[this.timelineEvents.length - 1];
        const now = Date.now();
        if (lastEvent && lastEvent.type === currentAttack && now - lastEvent.time < 5000) return;

        this.timelineEvents.push({
            time: now,
            type: currentAttack,
            score: detection.anomaly_score,
            severity: detection.severity,
        });

        if (this.timelineEvents.length > this.maxTimelineEvents) {
            this.timelineEvents.shift();
        }

        this.renderTimeline();
    }

    renderTimeline() {
        const container = document.getElementById('attack-timeline');
        if (!container) return;

        container.innerHTML = '';

        if (this.timelineEvents.length === 0) {
            container.innerHTML = '<div class="timeline-empty"><span>⏳</span><p>Monitoring — no attacks recorded yet</p></div>';
            return;
        }

        // Show newest first
        [...this.timelineEvents].reverse().forEach(event => {
            const div = document.createElement('div');
            div.className = `timeline-entry ${event.severity || 'warning'}`;

            const timeStr = new Date(event.time).toLocaleTimeString('en-US', {
                hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
            });

            const scoreColor = event.score >= 0.75 ? '#ef476f' : event.score >= 0.5 ? '#ff9f43' : '#06d6a0';
            const typeDisplay = event.type.replace(/_/g, ' ');

            div.innerHTML = `
                <span class="timeline-time">${timeStr}</span>
                <span class="timeline-type">${typeDisplay}</span>
                <span class="timeline-score" style="color:${scoreColor}">${event.score.toFixed(3)}</span>
            `;
            container.appendChild(div);
        });
    }

    updateThreatBanner(currentAttack, detection) {
        const banner = document.getElementById('threat-banner');
        const typeEl = document.getElementById('threat-type');
        const detailsEl = document.getElementById('threat-details');
        const expertPanel = document.getElementById('expert-analysis');

        if (!banner) return;

        if (currentAttack && currentAttack !== 'none' && detection && detection.is_anomaly) {
            banner.classList.remove('hidden');
            if (typeEl) {
                typeEl.textContent = currentAttack.replace(/_/g, ' ').toUpperCase();
            }
            
            // Inject SOC Expert Analysis
            if (expertPanel && detection.expert_analysis) {
                expertPanel.classList.remove('hidden');
                document.getElementById('expert-mitre').textContent = detection.expert_analysis.mitre_id;
                document.getElementById('expert-osi').textContent = detection.expert_analysis.osi_layer;
                document.getElementById('expert-desc').textContent = detection.expert_analysis.description;
                document.getElementById('expert-mitigation').textContent = detection.expert_analysis.mitigation;
            } else if (expertPanel) {
                expertPanel.classList.add('hidden');
            }

            // Inject threat details (top features)
            if (detailsEl && detection.top_features) {
                detailsEl.innerHTML = '';
                // Take top 3 features that triggered the anomaly
                detection.top_features.slice(0, 4).forEach(([feature, zScore]) => {
                    const badge = document.createElement('span');
                    badge.className = 'threat-sig-badge';
                    const name = feature.replace(/_/g, ' ');
                    badge.textContent = `${name}: ${zScore > 0 ? '+' : ''}${zScore}σ`;
                    detailsEl.appendChild(badge);
                });
            }
            
            this.lastAttackType = currentAttack;

            // Change pipeline status to danger
            const pipelineStatus = document.getElementById('pipeline-status');
            if (pipelineStatus) {
                const dot = pipelineStatus.querySelector('.status-dot');
                const text = pipelineStatus.querySelector('.status-text');
                dot.className = 'status-dot danger';
                text.textContent = 'Attack Detected!';
                text.style.color = '#ef476f';
            }
        } else {
            if (this.lastAttackType !== null && currentAttack !== this.lastAttackType) {
                banner.classList.add('hidden');
                this.lastAttackType = null;

                // Reset pipeline status
                const pipelineStatus = document.getElementById('pipeline-status');
                if (pipelineStatus) {
                    const dot = pipelineStatus.querySelector('.status-dot');
                    const text = pipelineStatus.querySelector('.status-text');
                    dot.className = 'status-dot connected pulse';
                    text.textContent = 'Pipeline Active';
                    text.style.color = '';
                }
            }
        }
    }

    async loadSessionAndStatus() {
        try {
            const response = await fetch('/api/auth/me');
            const username = document.getElementById('session-username');
            const role = document.getElementById('session-role');
            const logout = document.getElementById('btn-logout');
            if (response.ok) {
                const data = await response.json();
                if (username) username.textContent = data.user.username;
                if (role) role.textContent = data.user.role;
                if (logout) logout.classList.remove('hidden');
            } else {
                if (username) username.textContent = 'Public';
                if (role) role.textContent = 'Monitor';
                if (logout) logout.classList.add('hidden');
            }
            this.updateTrainingAccess();
            await this.loadTrainingStatus();
            await this.loadModelValidation();
            await this.loadReadiness();
        } catch (error) {
            console.error('[App] Session status failed:', error);
        }
    }

    updateTrainingAccess() {
        const input = document.getElementById('training-csv');
        const targetColumn = document.getElementById('training-target-column');
        const modelType = document.getElementById('training-model-type');
        const submit = document.getElementById('training-submit');
        const access = document.getElementById('training-access');
        if (input) input.disabled = false;
        if (targetColumn) targetColumn.disabled = false;
        if (modelType) modelType.disabled = false;
        if (submit) submit.disabled = false;
        if (access) access.textContent = 'Available to all dashboard users. Dataset is processed on the server.';
    }

    async uploadTrainingCsv() {
        const input = document.getElementById('training-csv');
        const targetColumn = document.getElementById('training-target-column');
        const modelType = document.getElementById('training-model-type');
        const file = input && input.files ? input.files[0] : null;
        if (!file) {
            this.renderTrainingStatus({ state: 'failed', message: 'Select a CSV or ZIP file first.' });
            return;
        }
        const lowerName = file.name.toLowerCase();
        const validDataset = ['.csv', '.csv.gz', '.csv.bz2', '.csv.xz', '.zip'].some((suffix) => lowerName.endsWith(suffix));
        if (!validDataset) {
            this.renderTrainingStatus({ state: 'failed', message: 'Only .csv, compressed CSV, and .zip dataset files are accepted.' });
            return;
        }

        const selectedModelType = modelType ? modelType.value : 'hist_gradient_boosting';
        const selectedTargetColumn = targetColumn ? targetColumn.value.trim() : '';
        this.renderTrainingStatus({ state: 'uploading', message: `Uploading ${file.name}...` });
        try {
            const params = new URLSearchParams({
                filename: file.name,
                model_type: selectedModelType,
            });
            if (selectedTargetColumn) params.set('target_column', selectedTargetColumn);
            const response = await fetch(
                `/api/training/cicddos/upload?${params.toString()}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': lowerName.endsWith('.zip') ? 'application/zip' : 'text/csv' },
                    body: file,
                }
            );
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.detail || 'Training upload failed.');
            this.renderTrainingStatus(payload);
            await this.loadTrainingStatus();
        } catch (error) {
            this.renderTrainingStatus({ state: 'failed', message: error.message });
        }
    }

    async loadTrainingStatus() {
        try {
            const response = await fetch('/api/training/cicddos/status');
            if (!response.ok) return;
            this.renderTrainingStatus(await response.json());
        } catch (error) {
            console.error('[App] Training status failed:', error);
        }
    }

    async loadModelValidation() {
        try {
            const response = await fetch('/api/models/validation');
            if (!response.ok) return;
            this.renderModelValidation(await response.json());
        } catch (error) {
            console.error('[App] Model validation status failed:', error);
        }
    }

    formatValidationMetric(value, format) {
        if (value === null || typeof value === 'undefined') return 'N/A';
        if (format === 'percentage' && typeof value === 'number') {
            return `${(value * 100).toFixed(2)}%`;
        }
        if (format === 'decimal' && typeof value === 'number') {
            return value.toFixed(6);
        }
        if (format === 'integer' && typeof value === 'number') {
            return value.toLocaleString();
        }
        return String(value);
    }

    renderModelValidation(payload) {
        const grid = document.getElementById('model-validation-grid');
        const note = document.getElementById('validation-note');
        if (note) {
            note.textContent = payload.validation_note || 'Saved validation metrics for trained algorithms.';
        }
        if (!grid || !Array.isArray(payload.models)) return;

        grid.replaceChildren();
        payload.models.forEach((model) => {
            const card = document.createElement('article');
            card.className = 'validation-model-card';

            const category = document.createElement('span');
            category.className = 'validation-model-category';
            category.textContent = model.category;

            const title = document.createElement('h5');
            title.textContent = model.name;

            const primaryLabel = document.createElement('span');
            primaryLabel.className = 'validation-primary-label';
            primaryLabel.textContent = model.primary_metric;

            const primaryValue = document.createElement('strong');
            primaryValue.className = model.primary_value === null ? 'validation-na' : '';
            primaryValue.textContent = this.formatValidationMetric(model.primary_value, 'percentage');

            const secondary = document.createElement('div');
            secondary.className = 'validation-secondary';
            const secondaryLabel = document.createElement('span');
            secondaryLabel.textContent = model.secondary_metric;
            const secondaryValue = document.createElement('b');
            secondaryValue.textContent = this.formatValidationMetric(
                model.secondary_value,
                model.secondary_format
            );
            secondary.append(secondaryLabel, secondaryValue);

            const details = document.createElement('dl');
            details.className = 'validation-details';
            (model.details || []).forEach((detail) => {
                const label = document.createElement('dt');
                label.textContent = detail.label;
                const value = document.createElement('dd');
                value.textContent = this.formatValidationMetric(detail.value, detail.format);
                details.append(label, value);
            });

            const basis = document.createElement('p');
            basis.textContent = model.basis;

            card.append(category, title, primaryLabel, primaryValue, secondary);
            if (details.childElementCount) card.append(details);
            card.append(basis);
            grid.appendChild(card);
        });
    }

    renderTrainingStatus(status) {
        const stateEl = document.getElementById('training-state');
        const message = document.getElementById('training-message');
        const submit = document.getElementById('training-submit');
        const input = document.getElementById('training-csv');
        const targetColumn = document.getElementById('training-target-column');
        const modelType = document.getElementById('training-model-type');
        const stateName = status.state || 'idle';
        const isBusy = ['uploading', 'queued', 'training'].includes(stateName);
        const result = status.result || {};

        if (stateEl) {
            stateEl.className = `training-state ${stateName}`;
            stateEl.textContent = stateName.replace('_', ' ');
        }
        if (message) message.textContent = status.message || 'No offline training status available.';
        if (submit) submit.disabled = isBusy;
        if (input) input.disabled = isBusy;
        if (targetColumn) targetColumn.disabled = isBusy;
        if (modelType) {
            modelType.disabled = isBusy;
            if (status.model_type) modelType.value = status.model_type;
        }

        const setMetric = (id, value) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        };
        setMetric('training-model', result.model_name || status.model_name || '-');
        setMetric('training-target', result.target_column || '-');
        setMetric('training-rows', result.rows_used ? result.rows_used.toLocaleString() : '-');
        setMetric('training-features', result.feature_count || '-');
        setMetric(
            'training-plain-accuracy',
            typeof result.accuracy === 'number' ? result.accuracy.toFixed(4) : '-'
        );
        setMetric(
            'training-accuracy',
            typeof result.balanced_accuracy === 'number' ? result.balanced_accuracy.toFixed(4) : '-'
        );
        setMetric(
            'training-f1',
            typeof result.f1_score === 'number' ? result.f1_score.toFixed(4) : '-'
        );
        this.renderTrainingAlgorithms(result.candidate_metrics || []);
        if (stateName === 'ready' && status.job_id !== this.lastValidationJobId) {
            this.lastValidationJobId = status.job_id;
            this.loadModelValidation();
        }
    }

    renderTrainingAlgorithms(candidateMetrics) {
        const container = document.getElementById('training-algorithms');
        if (!container) return;
        container.replaceChildren();
        if (!candidateMetrics.length) return;

        const heading = document.createElement('h5');
        heading.textContent = 'Algorithm results';
        container.appendChild(heading);

        candidateMetrics.forEach((metric) => {
            const row = document.createElement('div');
            row.className = `training-algorithm-row ${metric.status || 'trained'}`;

            const name = document.createElement('span');
            name.textContent = metric.model_name || metric.model_type || 'Model';

            const values = document.createElement('strong');
            if (metric.status === 'failed') {
                values.textContent = 'failed';
                values.title = metric.error || '';
            } else {
                const accuracy = typeof metric.accuracy === 'number' ? metric.accuracy.toFixed(4) : '-';
                const balanced = typeof metric.balanced_accuracy === 'number' ? metric.balanced_accuracy.toFixed(4) : '-';
                const f1 = typeof metric.f1_score === 'number' ? metric.f1_score.toFixed(4) : '-';
                values.textContent = `acc ${accuracy} / bal ${balanced} / f1 ${f1}`;
            }

            row.append(name, values);
            container.appendChild(row);
        });
    }

    async loadReadiness() {
        try {
            const response = await fetch('/api/health/ready');
            if (response.ok) this.updateOperationalStatus(await response.json());
        } catch (error) {
            console.error('[App] Readiness status failed:', error);
        }
    }

    updateOperationalStatus(data) {
        if (!data || typeof data.capture_state !== 'string') return;
        const banner = document.getElementById('operational-banner');
        const label = document.getElementById('operational-banner-label');
        const detail = document.getElementById('operational-banner-detail');
        const pipelineStatus = document.getElementById('pipeline-status');
        const sidebarDot = document.getElementById('sidebar-sensor-dot');
        const sidebarState = document.getElementById('sidebar-sensor-state');
        const sidebarSource = document.getElementById('sidebar-sensor-source');
        if (!banner || !label || !detail) return;

        let stateClass = 'status-idle';
        let stateLabel = data.last_packet_at ? 'CAPTURE IDLE' : 'WAITING FOR LIVE TRAFFIC';
        let stateDetail = data.last_packet_at
            ? 'Capture is healthy; no packets arrived during the recent idle window.'
            : 'Capture is ready and waiting for the first network packet.';
        if (data.response_mode === 'enforce') {
            stateClass = 'status-enforce';
            stateLabel = 'RESPONSE ENFORCEMENT ACTIVE';
            stateDetail = 'Firewall changes are enabled. Review audit events immediately.';
        } else if (data.capture_state === 'failed') {
            stateClass = 'status-failed';
            stateLabel = 'CAPTURE FAILED';
            stateDetail = data.last_capture_error || 'The detection pipeline is not operational.';
        } else if (data.capture_state === 'recovering') {
            stateClass = 'status-recovering';
            stateLabel = 'CAPTURE RECOVERING';
            stateDetail = data.last_capture_error || 'The sensor is retrying live packet capture.';
        } else if (data.capture_state === 'switching') {
            stateClass = 'status-switching';
            stateLabel = 'SWITCHING NETWORK ADAPTER';
            stateDetail = 'The sensor detected a route change and is reconnecting automatically.';
        } else if (data.capture_source === 'simulation') {
            stateClass = 'status-simulation';
            stateLabel = 'SIMULATION';
            stateDetail = 'Synthetic traffic is active; this is not live monitoring.';
        } else if (data.capture_state === 'receiving') {
            stateClass = 'status-live';
            stateLabel = 'LIVE CAPTURE';
            stateDetail = 'Live packets are being received and evaluated.';
        }

        banner.className = `operational-banner ${stateClass}`;
        label.textContent = stateLabel;
        detail.textContent = stateDetail;
        if (sidebarDot) {
            sidebarDot.className = `enterprise-sensor-dot ${stateClass}`;
        }
        if (sidebarState) {
            sidebarState.textContent = stateLabel;
        }
        if (sidebarSource) {
            const source = data.capture_source === 'tshark' ? 'TShark + Enterprise Wireless' : 'Simulation source';
            sidebarSource.textContent = source;
        }
        if (pipelineStatus && stateLabel !== 'RESPONSE ENFORCEMENT ACTIVE') {
            const dot = pipelineStatus.querySelector('.status-dot');
            const text = pipelineStatus.querySelector('.status-text');
            if (dot) dot.className = `status-dot ${stateClass === 'status-live' ? 'connected pulse' : 'warning'}`;
            if (text) text.textContent = stateLabel;
        }
    }

    updateSuppressionNotice(detection) {
        const notice = document.getElementById('suppression-notice');
        if (!notice) return;
        if (detection && detection.suppressed && detection.suppression_reason) {
            notice.textContent = `Detection suppressed by live filter: ${detection.suppression_reason} (raw score: ${(detection.raw_anomaly_score || 0).toFixed(3)})`;
            notice.classList.remove('hidden');
        } else {
            notice.classList.add('hidden');
        }
    }

    updateFooterTime() {
        const el = document.getElementById('footer-time');
        if (el) {
            el.textContent = new Date().toLocaleString('en-US', {
                weekday: 'short',
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false,
            });
        }
    }

    onConnected() {
        console.log('[App] Connected to detection pipeline');
    }

    onDisconnected() {
        console.log('[App] Disconnected from detection pipeline');
    }
}

// ─── Bootstrap ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const app = new DDoSShieldApp();
    app.init();
});
