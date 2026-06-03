/* ============================================================
   DDoS Shield — Chart Rendering Engine
   ============================================================ */

class ChartManager {
    constructor() {
        this.charts = {};
        this.sparklines = {};
        this.sparkData = {
            pps: [],
            bps: [],
        };
    }

    init() {
        if (typeof Chart === 'undefined') {
            console.warn('[Charts] Chart.js is unavailable; continuing without charts.');
            return false;
        }

        this.configureDefaults();
        this.createTrafficChart();
        this.createModelsChart();
        this.createProtocolChart();
        this.createSourcesChart();
        this.createFlagsChart();
        this.createBandwidthChart();
        this.createPktSizeChart();
        this.createTtlFragChart();
        this.createSparklines();
        return true;
    }

    configureDefaults() {
        // Chart.js global defaults for dark theme
        Chart.defaults.color = '#8b95a8';
        Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
        Chart.defaults.font.family = "'Inter', sans-serif";
        Chart.defaults.font.size = 11;
        Chart.defaults.plugins.legend.display = false;
        Chart.defaults.animation.duration = 400;
    }

    createTrafficChart() {
        const ctx = document.getElementById('chart-traffic');
        if (!ctx) return;

        this.charts.traffic = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Packet Rate',
                        data: [],
                        borderColor: '#56c7ff',
                        backgroundColor: 'rgba(86, 199, 255, 0.08)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        yAxisID: 'y',
                    },
                    {
                        label: 'Anomaly Score',
                        data: [],
                        borderColor: '#a34cff',
                        backgroundColor: 'rgba(163, 76, 255, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        yAxisID: 'y1',
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { maxTicksLimit: 10, font: { size: 10 } },
                    },
                    y: {
                        position: 'left',
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        title: { display: true, text: 'PPS', font: { size: 10 } },
                        ticks: {
                            callback: v => Utils.formatNumber(v),
                            font: { size: 10 },
                        },
                    },
                    y1: {
                        position: 'right',
                        min: 0,
                        max: 1,
                        grid: { display: false },
                        title: { display: true, text: 'Score', font: { size: 10 } },
                        ticks: { font: { size: 10 } },
                    },
                },
                plugins: {
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleFont: { weight: 600 },
                        bodyFont: { size: 12 },
                        padding: 10,
                        cornerRadius: 8,
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderWidth: 1,
                    },
                },
            },
        });
    }

    createModelsChart() {
        const ctx = document.getElementById('chart-models');
        if (!ctx) return;

        this.charts.models = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['IF Score', 'GB Score', 'AE Score', 'Confidence', 'Ensemble'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    borderColor: '#56c7ff',
                    backgroundColor: 'rgba(86, 199, 255, 0.12)',
                    borderWidth: 2,
                    pointBackgroundColor: '#56c7ff',
                    pointBorderColor: '#56c7ff',
                    pointRadius: 3,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        min: 0,
                        max: 1,
                        ticks: { stepSize: 0.25, font: { size: 9 }, backdropColor: 'transparent' },
                        grid: { color: 'rgba(255,255,255,0.06)' },
                        angleLines: { color: 'rgba(255,255,255,0.06)' },
                        pointLabels: { font: { size: 10 }, color: '#8b95a8' },
                    },
                },
            },
        });
    }

    createProtocolChart() {
        const ctx = document.getElementById('chart-protocols');
        if (!ctx) return;

        this.charts.protocols = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'DNS'],
                datasets: [{
                    data: [65, 20, 5, 10],
                    backgroundColor: ['#56c7ff', '#417cff', '#a34cff', '#f3a34c'],
                    borderColor: '#151c2e',
                    borderWidth: 3,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            padding: 12,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            font: { size: 11 },
                        },
                    },
                },
            },
        });
    }

    createSourcesChart() {
        const ctx = document.getElementById('chart-sources');
        if (!ctx) return;

        this.charts.sources = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Unique Sources',
                        data: [],
                        borderColor: '#a34cff',
                        backgroundColor: 'rgba(163, 76, 255, 0.08)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                    },
                    {
                        label: 'IP Entropy',
                        data: [],
                        borderColor: '#ff9f43',
                        backgroundColor: 'rgba(255, 159, 67, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        yAxisID: 'y1',
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 9 } } },
                    y: {
                        position: 'left',
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        title: { display: true, text: 'IPs', font: { size: 9 } },
                        ticks: { font: { size: 9 } },
                    },
                    y1: {
                        position: 'right',
                        grid: { display: false },
                        title: { display: true, text: 'Entropy', font: { size: 9 } },
                        ticks: { font: { size: 9 } },
                    },
                },
            },
        });
    }

    createFlagsChart() {
        const ctx = document.getElementById('chart-flags');
        if (!ctx) return;

        this.charts.flags = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['SYN', 'SYN-ACK', 'ACK', 'RST', 'FIN'],
                datasets: [{
                    data: [10, 10, 40, 5, 5],
                    backgroundColor: [
                        'rgba(86, 199, 255, 0.7)',
                        'rgba(65, 124, 255, 0.7)',
                        'rgba(163, 76, 255, 0.7)',
                        'rgba(239, 71, 111, 0.7)',
                        'rgba(255, 159, 67, 0.7)',
                    ],
                    borderRadius: 4,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { font: { size: 10 } },
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: {
                            callback: v => (v * 100).toFixed(0) + '%',
                            font: { size: 9 },
                        },
                        max: 1,
                    },
                },
            },
        });
    }

    createBandwidthChart() {
        const ctx = document.getElementById('chart-bandwidth');
        if (!ctx) return;

        this.charts.bandwidth = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Byte Rate',
                        data: [],
                        borderColor: '#56c7ff',
                        backgroundColor: 'rgba(86, 199, 255, 0.08)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        yAxisID: 'y',
                    },
                    {
                        label: 'UDP Ratio',
                        data: [],
                        borderColor: '#ff9f43',
                        backgroundColor: 'rgba(255, 159, 67, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0,
                        yAxisID: 'y1',
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 9 } } },
                    y: {
                        position: 'left',
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        title: { display: true, text: 'BPS', font: { size: 9 } },
                        ticks: { callback: v => Utils.formatBps(v), font: { size: 9 } },
                    },
                    y1: {
                        position: 'right',
                        min: 0,
                        max: 1,
                        grid: { display: false },
                        title: { display: true, text: 'UDP %', font: { size: 9 } },
                        ticks: { callback: v => (v * 100).toFixed(0) + '%', font: { size: 9 } },
                    },
                },
            },
        });
    }

    createPktSizeChart() {
        const ctx = document.getElementById('chart-pkt-size');
        if (!ctx) return;

        this.charts.pktSize = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Avg Size', 'Std Dev', 'Payload', 'Window/100'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(86, 199, 255, 0.7)',
                        'rgba(163, 76, 255, 0.7)',
                        'rgba(65, 124, 255, 0.7)',
                        'rgba(255, 159, 67, 0.7)',
                    ],
                    borderRadius: 4,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { display: false }, ticks: { font: { size: 10 } } },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: { font: { size: 9 } },
                    },
                },
            },
        });
    }

    createTtlFragChart() {
        const ctx = document.getElementById('chart-ttl-frag');
        if (!ctx) return;

        this.charts.ttlFrag = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Avg TTL', 'TTL Diversity', 'Frag %', 'Lg Pkt %', 'Zero Pay %'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(0, 194, 209, 0.7)',
                        'rgba(163, 76, 255, 0.7)',
                        'rgba(239, 71, 111, 0.7)',
                        'rgba(255, 159, 67, 0.7)',
                        'rgba(224, 86, 160, 0.7)',
                    ],
                    borderRadius: 4,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { display: false }, ticks: { font: { size: 9 } } },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.04)' },
                        ticks: { font: { size: 9 } },
                    },
                },
            },
        });
    }

    createSparklines() {
        ['pps', 'bps'].forEach(key => {
            const ctx = document.getElementById(`spark-${key}`);
            if (!ctx) return;

            this.sparklines[key] = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: new Array(20).fill(''),
                    datasets: [{
                        data: new Array(20).fill(0),
                        borderColor: key === 'pps' ? '#56c7ff' : '#a34cff',
                        borderWidth: 1.5,
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        x: { display: false },
                        y: { display: false },
                    },
                    plugins: { tooltip: { enabled: false } },
                },
            });
        });
    }

    update(data) {
        if (!data) return;

        const history = data.traffic_history || [];
        const detection = data.detection || {};
        const features = data.latest_features || {};

        // Update traffic chart
        if (this.charts.traffic && history.length > 0) {
            const labels = history.map(h => Utils.formatTime(h.timestamp));
            const pps = history.map(h => h.packet_rate);
            const scores = history.map(h => h.anomaly_score);

            this.charts.traffic.data.labels = labels;
            this.charts.traffic.data.datasets[0].data = pps;
            this.charts.traffic.data.datasets[1].data = scores;
            this.charts.traffic.update('none');
        }

        // Update models radar
        if (this.charts.models) {
            this.charts.models.data.datasets[0].data = [
                detection.if_score || 0,
                detection.gb_score || 0,
                detection.ae_score || 0,
                detection.anomaly_score || 0,
                detection.anomaly_score || 0,
            ];
            this.charts.models.update('none');
        }

        // Update protocol doughnut
        if (this.charts.protocols) {
            this.charts.protocols.data.datasets[0].data = [
                (features.tcp_ratio || 0.65) * 100,
                (features.udp_ratio || 0.2) * 100,
                (features.icmp_ratio || 0.05) * 100,
                (features.dns_ratio || 0.1) * 100,
            ];
            this.charts.protocols.update('none');
        }

        // Update sources chart
        if (this.charts.sources && history.length > 0) {
            const labels = history.map(h => Utils.formatTime(h.timestamp));
            this.charts.sources.data.labels = labels;
            this.charts.sources.data.datasets[0].data = history.map(h => h.unique_src_ips || 0);
            this.charts.sources.data.datasets[1].data = history.map(h => h.src_ip_entropy || 0);
            this.charts.sources.update('none');
        }

        // Update flags bar chart
        if (this.charts.flags) {
            this.charts.flags.data.datasets[0].data = [
                features.syn_ratio || 0.1,
                features.syn_ack_ratio || 0.1,
                features.ack_ratio || 0.4,
                features.rst_ratio || 0.05,
                features.fin_ratio || 0.05,
            ];
            this.charts.flags.update('none');
        }

        // Update bandwidth chart
        if (this.charts.bandwidth && history.length > 0) {
            const labels = history.map(h => Utils.formatTime(h.timestamp));
            this.charts.bandwidth.data.labels = labels;
            this.charts.bandwidth.data.datasets[0].data = history.map(h => h.byte_rate || 0);
            this.charts.bandwidth.data.datasets[1].data = history.map(h => h.udp_ratio || 0);
            this.charts.bandwidth.update('none');
        }

        // Update packet size chart
        if (this.charts.pktSize) {
            this.charts.pktSize.data.datasets[0].data = [
                features.avg_packet_size || 0,
                features.std_packet_size || 0,
                features.avg_payload_size || 0,
                (features.avg_window_size || 0) / 100,
            ];
            this.charts.pktSize.update('none');
        }

        // Update TTL / frag chart
        if (this.charts.ttlFrag) {
            this.charts.ttlFrag.data.datasets[0].data = [
                features.avg_ttl || 0,
                features.ttl_diversity || 0,
                (features.fragmentation_ratio || 0) * 100,
                (features.large_packet_ratio || 0) * 100,
                (features.zero_payload_ratio || 0) * 100,
            ];
            this.charts.ttlFrag.update('none');
        }

        // Update sparklines
        const pps = data.metrics?.current_pps || 0;
        const bps = data.metrics?.current_bps || 0;

        this.sparkData.pps.push(pps);
        this.sparkData.bps.push(bps);
        if (this.sparkData.pps.length > 20) this.sparkData.pps.shift();
        if (this.sparkData.bps.length > 20) this.sparkData.bps.shift();

        if (this.sparklines.pps) {
            this.sparklines.pps.data.datasets[0].data = [...this.sparkData.pps];
            this.sparklines.pps.update('none');
        }
        if (this.sparklines.bps) {
            this.sparklines.bps.data.datasets[0].data = [...this.sparkData.bps];
            this.sparklines.bps.update('none');
        }

        // Update model score bars
        this.updateModelBars(detection);
    }

    updateModelBars(detection) {
        const pairs = [
            ['bar-if', 'score-if', detection.if_score],
            ['bar-gb', 'score-gb', detection.gb_score],
            ['bar-ae', 'score-ae', detection.ae_score],
        ];

        pairs.forEach(([barId, scoreId, value]) => {
            const bar = document.getElementById(barId);
            const score = document.getElementById(scoreId);
            if (bar) bar.style.width = `${(value || 0) * 100}%`;
            if (score) score.textContent = (value || 0).toFixed(2);
        });
    }
}

// Global instance
const chartManager = new ChartManager();
