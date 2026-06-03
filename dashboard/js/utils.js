/* ============================================================
   DDoS Shield — Utility Functions
   ============================================================ */

const Utils = {
    /**
     * Format a number with commas and optional decimals
     */
    formatNumber(num, decimals = 0) {
        if (num === undefined || num === null || isNaN(num)) return '0';
        if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
        if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
        if (num >= 1e4) return (num / 1e3).toFixed(1) + 'K';
        return Number(num).toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    /**
     * Format bytes to human-readable
     */
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    },

    /**
     * Format bytes per second
     */
    formatBps(bps) {
        if (bps === 0) return '0 bps';
        const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
        const i = Math.floor(Math.log(bps * 8) / Math.log(1000));
        return ((bps * 8) / Math.pow(1000, i)).toFixed(1) + ' ' + units[Math.min(i, 3)];
    },

    /**
     * Format seconds to HH:MM:SS
     */
    formatUptime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;
        return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    },

    /**
     * Format timestamp to time string
     */
    formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString('en-US', { hour12: false });
    },

    /**
     * Format relative time
     */
    formatRelativeTime(timestamp) {
        const diff = Date.now() / 1000 - timestamp;
        if (diff < 5) return 'just now';
        if (diff < 60) return `${Math.floor(diff)}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        return `${Math.floor(diff / 3600)}h ago`;
    },

    /**
     * Smooth value animation
     */
    animateValue(element, start, end, duration = 500) {
        const startTime = performance.now();
        const diff = end - start;

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
            const current = start + diff * eased;

            if (element) {
                if (Number.isInteger(end)) {
                    element.textContent = Utils.formatNumber(Math.round(current));
                } else {
                    element.textContent = current.toFixed(2);
                }
            }

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    },

    /**
     * Debounce function calls
     */
    debounce(fn, delay) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn(...args), delay);
        };
    },

    /**
     * Get severity color
     */
    getSeverityColor(severity) {
        const colors = {
            emergency: '#ff1744',
            critical: '#ef476f',
            warning: '#ff9f43',
            info: '#118ab2',
        };
        return colors[severity] || '#5a6478';
    },

    /**
     * Create chart gradient
     */
    createGradient(ctx, color, opacity1 = 0.3, opacity2 = 0.0) {
        const gradient = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height);
        gradient.addColorStop(0, color.replace(')', `, ${opacity1})`).replace('rgb', 'rgba'));
        gradient.addColorStop(1, color.replace(')', `, ${opacity2})`).replace('rgb', 'rgba'));
        return gradient;
    },
};
