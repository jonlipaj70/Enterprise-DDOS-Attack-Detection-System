/* ============================================================
   DDoS Shield — Alert Management UI
   ============================================================ */

class AlertManager {
    constructor() {
        this.alerts = [];
        this.currentFilter = 'all';
        this.seenAlertIds = new Set();
    }

    init() {
        // Set up filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.currentFilter = btn.dataset.filter;
                this.render();
            });
        });
    }

    update(alerts) {
        if (!alerts || !Array.isArray(alerts)) return;

        // Detect new alerts
        const newAlerts = alerts.filter(a => !this.seenAlertIds.has(a.alert_id));
        newAlerts.forEach(a => this.seenAlertIds.add(a.alert_id));

        this.alerts = alerts;
        this.render();

        // Update badge
        const badge = document.getElementById('alert-count-badge');
        if (badge) badge.textContent = alerts.length;

        return newAlerts;
    }

    render() {
        const tbody = document.getElementById('alerts-tbody');
        if (!tbody) return;

        let filtered = this.alerts;
        if (this.currentFilter !== 'all') {
            filtered = this.alerts.filter(a => a.severity === this.currentFilter);
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `
                <tr class="no-alerts-row">
                    <td colspan="7">
                        <div class="no-alerts">
                            <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <p>No alerts matching filter</p>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        // Show most recent first
        const sorted = [...filtered].reverse();

        tbody.innerHTML = sorted.map((alert, index) => {
            const isNew = index === 0 && this.seenAlertIds.size > sorted.length;
            const score = alert.anomaly_score || 0;
            const scoreClass = score >= 0.8 ? 'high' : score >= 0.6 ? 'medium' : 'low';

            return `
                <tr class="${isNew ? 'new-alert' : ''}">
                    <td>
                        <span class="severity-badge ${alert.severity}">
                            <span class="severity-dot"></span>
                            ${alert.severity}
                        </span>
                    </td>
                    <td>${Utils.formatRelativeTime(alert.timestamp)}</td>
                    <td><span class="attack-type-badge">${(alert.attack_type || 'unknown').replace(/_/g, ' ')}</span></td>
                    <td><span class="score-value ${scoreClass}">${score.toFixed(2)}</span></td>
                    <td><span class="score-value">${(alert.confidence || 0).toFixed(2)}</span></td>
                    <td><span class="pps-value">${Utils.formatNumber(alert.packet_rate)}</span></td>
                    <td><span class="status-badge ${alert.status || 'active'}">${alert.status || 'active'}</span></td>
                </tr>`;
        }).join('');
    }
}

// Global instance
const alertManager = new AlertManager();
