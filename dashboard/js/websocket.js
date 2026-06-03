/* ============================================================
   DDoS Shield — WebSocket Connection Manager
   ============================================================ */

class WebSocketManager {
    constructor() {
        this.ws = null;
        const pagePort = window.location.port;
        const apiPort = (!pagePort || pagePort === '8080' || pagePort === '3000') ? '8000' : pagePort;
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.url = `${protocol}//${window.location.hostname}:${apiPort}/ws`;
        this.reconnectDelay = 2000;
        this.maxReconnectDelay = 30000;
        this.currentDelay = this.reconnectDelay;
        this.handlers = new Map();
        this.isConnected = false;
        this.reconnectTimer = null;
        this.pingInterval = null;
    }

    connect() {
        try {
            this.ws = new WebSocket(this.url);

            this.ws.onopen = () => {
                console.log('[WS] Connected to detection pipeline');
                this.isConnected = true;
                this.currentDelay = this.reconnectDelay;
                this.updateConnectionUI(true);
                this.startPing();
                this.emit('connected');
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.emit('message', data);

                    if (data.type === 'update' || data.type === 'local_security_update') {
                        this.emit('update', data);
                    }
                } catch (e) {
                    console.error('[WS] Parse error:', e);
                }
            };

            this.ws.onclose = (event) => {
                console.log('[WS] Disconnected, code:', event.code);
                this.isConnected = false;
                this.updateConnectionUI(false);
                this.stopPing();
                this.scheduleReconnect();
                this.emit('disconnected');
            };

            this.ws.onerror = (error) => {
                console.error('[WS] Error:', error);
                this.emit('error', error);
            };

        } catch (e) {
            console.error('[WS] Connection failed:', e);
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

        this.reconnectTimer = setTimeout(() => {
            console.log(`[WS] Reconnecting in ${this.currentDelay}ms...`);
            this.connect();
            this.currentDelay = Math.min(this.currentDelay * 1.5, this.maxReconnectDelay);
        }, this.currentDelay);
    }

    startPing() {
        this.pingInterval = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 25000);
    }

    stopPing() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }

    updateConnectionUI(connected) {
        const statusEl = document.getElementById('connection-status');
        if (!statusEl) return;

        const dot = statusEl.querySelector('.status-dot');
        const text = statusEl.querySelector('.status-text');

        if (connected) {
            dot.className = 'status-dot connected pulse';
            text.textContent = 'Connected';
        } else {
            dot.className = 'status-dot offline';
            text.textContent = 'Reconnecting...';
        }
    }

    on(event, handler) {
        if (!this.handlers.has(event)) {
            this.handlers.set(event, []);
        }
        this.handlers.get(event).push(handler);
    }

    emit(event, data) {
        const handlers = this.handlers.get(event) || [];
        handlers.forEach(handler => {
            try {
                handler(data);
            } catch (e) {
                console.error(`[WS] Handler error for ${event}:`, e);
            }
        });
    }

    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        }
    }

    disconnect() {
        this.stopPing();
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
        if (this.ws) this.ws.close();
    }
}

// Global instance
const wsManager = new WebSocketManager();
