# Technical Documentation — DDoS Detection System

## 1. System Architecture

### 1.1 High-Level Architecture

The system follows a streaming microservices pattern with five distinct layers:

- **Ingestion Layer**: The API consumes live TShark packet observations or generated simulation traffic; serialization/Kafka adapters are available as separate components
- **Processing Layer**: The active API uses an in-process window aggregator to extract 30 features across 1s/5s/60s windows; the Spark-like processor is a simulated component
- **Detection Layer**: Ensemble ML pipeline with Isolation Forest (unsupervised), Gradient Boosting (supervised), and Autoencoder (reconstruction-error scoring)
- **Alert Layer**: Multi-tier classification, correlation, rate limiting, and integration routing
- **Presentation Layer**: Real-time WebSocket-powered SOC dashboard

### 1.1.1 Live TShark Capture

The default packet source is simulated traffic. To use live Wireshark/TShark capture, configure:

```env
CAPTURE_SOURCE=tshark
CAPTURE_INTERFACE=auto
CAPTURE_TARGET_HOST=10.0.1.100
CAPTURE_TARGET_PORTS=80,443
TSHARK_PATH=tshark
CAPTURE_BATCH_SIZE=200
```

Live capture filters traffic to the protected host and ports, parses TShark fields into the same raw packet schema as the simulator, then reuses the existing window aggregation and model pipeline. If TShark is not installed or is not in `PATH`, set `TSHARK_PATH` to the full executable path.

To monitor all local IP traffic on the selected adapter instead of a single protected host, leave `CAPTURE_TARGET_HOST` empty or set it to `all`:

```env
CAPTURE_SOURCE=tshark
CAPTURE_INTERFACE=auto
CAPTURE_TARGET_HOST=all
CAPTURE_TARGET_PORTS=
TSHARK_PATH=C:/Program Files/Wireshark/tshark.exe
CAPTURE_BATCH_SIZE=200
```

On Windows, `CAPTURE_INTERFACE=auto` resolves the adapter carrying the active default route by its stable interface name rather than by a changeable TShark number. `TSHARK_PATH=tshark` checks `PATH` first and then default Wireshark install locations such as `C:/Program Files/Wireshark/tshark.exe`. Use `tshark -D` or Admin `GET /api/admin/capture/diagnostics` only when an explicit capture interface is required. Run the API as Administrator and install Npcap through Wireshark. This capture reads packet metadata needed by the DDoS pipeline; encrypted application content such as HTTPS remains encrypted.

### 1.1.2 Local Wi-Fi/USB Threat Guard

The API also includes a local protection monitor for endpoint-side network threats:

- Rogue USB network gadgets, including suspicious USB Ethernet/RNDIS adapters and Pineapple-like `172.16.42.0/24` management ranges
- Evil Twin Wi-Fi indicators, including trusted SSIDs with unknown BSSIDs or conflicting security modes
- Captive portal or HTTP connectivity-check interception

Example configuration:

```env
LOCAL_THREAT_MONITOR_ENABLED=true
LOCAL_THREAT_SCAN_INTERVAL_SECONDS=30
LOCAL_THREAT_RESPONSE_MODE=monitor
LOCAL_THREAT_AUTO_DISCONNECT=false
LOCAL_THREAT_AUTO_DISABLE_ADAPTERS=false
TRUSTED_WIFI_SSIDS=Tectigon Ipko 5G
TRUSTED_WIFI_BSSIDS=Tectigon Ipko 5G=56:c2:50:cb:1f:69
TRUSTED_USB_ADAPTER_KEYWORDS=Realtek 8852BE,TP-Link Wireless USB Adapter,VirtualBox Host-Only
CAPTIVE_PORTAL_CHECK_ENABLED=true
WIRELESS_INTELLIGENCE_ENABLED=true
WIRELESS_OUI_DATABASE_PATH=./data/enterprise_oui.txt
WIRELESS_SUSPICIOUS_OUIS=00:13:37,D8:EB:46,00:C0:CA,00:8F:DF,6C:E8:73
WIRELESS_SUSPICIOUS_SSID_PATTERNS=Pineapple,Free Public WiFi,HACKED,Pwned,evil_twin,karma
WIRELESS_MULTI_SSID_THRESHOLD=3
```

Use `monitor` mode for alerts only. The following enforcement configuration describes
a future controlled rollout and must not be enabled in Release 1 while
`LOCAL_THREAT_ENFORCEMENT_ALLOWED=false`:

```env
LOCAL_THREAT_RESPONSE_MODE=enforce
LOCAL_THREAT_AUTO_DISCONNECT=true
LOCAL_THREAT_AUTO_DISABLE_ADAPTERS=true
```

In enforce mode, high-confidence Evil Twin or trusted-network captive portal findings trigger `netsh wlan disconnect`. Suspicious USB Ethernet/RNDIS gadgets trigger `Disable-NetAdapter` for the detected adapter. Adapters whose descriptions match `TRUSTED_USB_ADAPTER_KEYWORDS` are ignored.

Enterprise wireless intelligence is incorporated into the same scan loop without launching a second web server. It enriches visible access points from `netsh wlan show networks mode=bssid` using `data/enterprise_oui.txt` and raises review-only findings for monitored OUI prefixes, suspicious SSID patterns and one BSSID advertising multiple SSIDs. These heuristic findings do not perform automatic disconnect or adapter-disable actions.

On the current Windows sensor, this integration cannot reliably capture raw Wi-Fi management frames. Deauthentication-frame or Karma probe-response detection remains unavailable unless a monitor-mode 802.11 capture source is deployed.

The latest scan is available at `GET /api/local-security/status`; the response includes `wireless_capabilities` and `snapshot.wireless_sensor`. A manual scan can be triggered with `POST /api/local-security/scan`.

### 1.2 Data Flow

```
TShark / Traffic Simulator → Window Aggregation → Feature Store
                                                              ↓
                                                     ML Ensemble Model
                                                              ↓
                                                        Alert Engine
                                                              ↓
                                              Dashboard + Integrations
```

## 2. ML Detection Pipeline

### 2.1 Feature Engineering

30+ features extracted per time window:

| Category | Features | Count |
|----------|----------|-------|
| Volume | packet_rate, byte_rate | 2 |
| Protocol | tcp/udp/icmp/dns ratios | 4 |
| TCP Flags | syn/synack/ack/rst/fin ratios, syn-to-ack ratio | 6 |
| Entropy | src_ip, dst_ip, src_port, dst_port entropy | 4 |
| Statistics | avg/std/min/max packet size | 4 |
| Connections | unique src/dst IPs, ports, pairs | 5 |
| TTL | avg_ttl, ttl_diversity | 2 |
| Payload | avg_payload, zero_payload_ratio | 2 |
| Window | avg_window_size, small_window_ratio | 2 |
| Advanced | fragmentation, large_packet ratio | 2 |

### 2.2 Models

**Isolation Forest**: Unsupervised anomaly detection. Scores based on feature deviation from learned baseline distributions. Effective for zero-day and novel attacks.

**Gradient Boosting**: Supervised classifier implemented with scikit-learn `HistGradientBoostingClassifier`, using robust-scaled features and persisted trained artifacts for subsequent startup. Best for known attack patterns.

**Autoencoder**: Scikit-learn `MLPRegressor` reconstruction model. Normal traffic is reconstructed well; attacks produce higher reconstruction error.

**Ensemble**: Logistic Regression stacking model when trained artifacts are available, with weighted-score fallback. It combines base-model predictions with fingerprint matching and temporal reinforcement. Metrics generated during synthetic training must be validated with representative live captures before production claims.

### 2.2.1 Validation Metrics Shown in the Dashboard

The dashboard combines two distinct metric sources and must not present them as one
comparable benchmark:

| Model surface | Dataset / evaluation source | Displayed metrics | Runtime role |
|---|---|---|---|
| Isolation Forest | Separate labeled synthetic evaluation sample | Validation F1, precision, recall, tree count, contamination | Live packet-window ensemble member |
| Gradient Boosting | Held-out synthetic traffic | Accuracy and F1 | Live packet-window ensemble member |
| Autoencoder | Separate labeled synthetic evaluation sample evaluated through its reconstruction-error threshold | Validation F1, precision, recall, error threshold, normal MSE p95, attack MSE p50 | Live packet-window ensemble member |
| Stacking Ensemble | Held-out synthetic traffic | Accuracy | Live packet-window meta-model |
| CICDDoS Flow Classifier | Uploaded CICDDoS2019 CSV/ZIP labeled flow sample | Balanced accuracy and F1 | Offline flow artifact only |

Isolation Forest and Autoencoder remain unsupervised models during fitting. Their
displayed F1/precision/recall values are calculated after fitting by applying each
anomaly decision rule to separate labeled synthetic evaluation traffic. These values
are not results from the uploaded CICDDoS archive and are not a production guarantee.

### 2.2.2 Offline Tabular Training

The public **Model Training** panel accepts a labeled `.csv`, compressed CSV, or
`.zip` archive containing CSV files. ZIP input is read directly without extracting the
complete archive to disk, and nested ZIPs are inspected for CSV files. The training
service samples bounded rows per target class, trains an offline tabular classifier,
and persists:

```text
models/cicddos_flow_classifier.joblib
models/cicddos_flow_classifier.json
```

Only the latest completed upload is retained as the shared offline artifact. Uploading
a new dataset replaces the previous artifact and narrows or changes the displayed
source coverage.

The offline trainer is model-type agnostic across the supported scikit-learn
families. The dashboard and upload API can request `hist_gradient_boosting`,
`random_forest`, `extra_trees`, `logistic_regression`, `linear_svm`, `mlp`,
`gaussian_nb`, `knn`, or `auto`. Manual requests train that specific estimator.
`auto` trains the fast candidate set and persists the model with the best balanced
accuracy, using F1 as the tiebreaker. The persisted JSON metadata records both the
requested and selected model types. Generic datasets can provide `target_column`; if
omitted, common target names are detected automatically and the last CSV column is used
as fallback. Numeric features are imputed and optionally scaled; categorical features
are imputed and one-hot encoded.

This classifier cannot be injected into the current live pipeline: uploaded tabular
datasets may use arbitrary feature columns, while the TShark path supplies 30
packet-window features. A compatible live feature extractor and model-selection policy
are required before the uploaded artifact can participate in live detection.

### 2.3 Active Fingerprint Classification

The active API ensemble classifies these matching patterns:

1. **SYN flood** — High SYN and zero-payload ratios with distributed sources
2. **DNS amplification** — High DNS ratio combined with large packets
3. **UDP flood** — High UDP ratio combined with high packet rate
4. **HTTP flood** — TCP-heavy traffic with high distributed-source entropy
5. **Slowloris** — Small-packet TCP behavior with low payload size
6. **ICMP flood** — High ICMP ratio combined with high packet rate

Additional detector modules are present in `src/detection/detectors/` for future
pipeline extension; they are not invoked by the current live API detection loop.

## 3. Alert System

### 3.1 Classification

| Severity | Criteria | Response |
|----------|----------|----------|
| Emergency | Score ≥ 0.9 or PPS ≥ 50K | Immediate automated mitigation |
| Critical | Score ≥ 0.75 or PPS ≥ 30K | Page on-call + auto-response |
| Warning | Score ≥ 0.6 or PPS ≥ 15K | Slack notification |
| Info | Score < 0.6 | Log only |

The listed response outcomes are policy intents. In Release 1, monitor mode and the
mitigation activation gate prevent automatic blocking or disconnection actions.

### 3.2 Integrations

- PagerDuty (incident management)
- Slack (real-time notifications)
- SIEM (CEF format events)
- Email (escalation notifications)
- Webhook (custom integrations)
- Jira (ticket creation)

## 4. API Reference

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/health | Health check |
| GET | /api/metrics | System metrics |
| GET | /api/alerts | Alert history |
| GET | /api/alerts/active | Active alerts |
| POST | /api/alerts/{id}/acknowledge | Acknowledge alert |
| POST | /api/alerts/{id}/resolve | Resolve alert |
| GET | /api/detection/status | Detection pipeline status |
| GET | /api/traffic/history | Traffic history |
| GET | /api/features/latest | Latest feature vectors |
| GET | /api/training/cicddos/status | Offline training status and most recent artifact metrics |
| POST | /api/training/cicddos/upload?filename={dataset.csv\|dataset.zip} | Upload and queue shared offline CICDDoS training |
| GET | /api/models/validation | Dashboard validation metrics for live algorithms and offline flow artifact |
| GET | /api/system/stats | Full system statistics |

### WebSocket

Connect to `ws://host:port/ws` for real-time updates. Messages are JSON with `type: "update"` containing metrics, features, detection results, and alerts.

## 5. Deployment

See the operations runbook for deployment procedures.
