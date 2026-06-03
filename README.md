# 🛡️ Enterprise DDoS Attack Detection System

<p align="center">
  <strong>Real-time, ML-powered distributed denial-of-service attack detection and response platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/scikit--learn-1.3+-orange?style=flat-square&logo=scikitlearn" alt="scikit-learn">
  <img src="https://img.shields.io/badge/Kafka-3.5+-black?style=flat-square&logo=apachekafka" alt="Kafka">
  <img src="https://img.shields.io/badge/Kubernetes-1.28+-326CE5?style=flat-square&logo=kubernetes" alt="K8s">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License">
</p>

---

## 🎯 Overview

A DDoS monitoring and detection system designed for:

- **Live packet observation** through TShark on the Windows sensor
- **Automatic capture recovery** following active network-adapter changes
- **Three-model ensemble detection** over 30 network features
- **Passive wireless and local adapter review** in safe monitor mode

The live detection pipeline combines Isolation Forest, Gradient Boosting, and an Autoencoder through an ensemble scoring layer. It classifies active fingerprint patterns for SYN flood, DNS amplification, UDP flood, HTTP flood, Slowloris and ICMP flood.

On Windows, the Enterprise sensor supports live packet capture through Wireshark/TShark with automatic active-adapter recovery, plus passive Wireless Intelligence for nearby access-point review and local Wi-Fi/USB threat signals.

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Data Ingestion │ ──> │ Stream Processing│ ──> │  ML Detection       │
│  ─────────────  │     │  ──────────────  │     │  ─────────────────  │
│  Live TShark    │     │  Feature Engine  │     │  Isolation Forest   │
│  Traffic Sim.   │     │  Window Agg.     │     │  Gradient Boosting  │
│  Local Guard    │     │  Feature Store   │     │  Autoencoder        │
│                 │     │                 │     │  Fingerprints       │
└─────────────────┘     └──────────────────┘     │  + Ensemble         │
                                                  └──────────┬──────────┘
                                                             │
┌─────────────────┐     ┌──────────────────┐     ┌──────────▼──────────┐
│  Web Dashboard  │ <── │   API Server     │ <── │  Alert & Response   │
│  ─────────────  │     │  ──────────────  │     │  ─────────────────  │
│  Real-time UI   │     │  REST + WS API   │     │  Alert Engine       │
│  Forensics     │     │  JWT Auth        │     │  PagerDuty/Slack    │
│  Live Charts    │     │  Rate Limiting   │     │  SIEM Integration   │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- pip or Poetry

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/ddos-detection-system.git
cd ddos-detection-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env

# Run the system
make run
```

### Windows Live Sensor

Install Wireshark with Npcap, configure `.env` with `CAPTURE_SOURCE=tshark` and
`CAPTURE_INTERFACE=auto`, then double-click `nis_projektin.bat`. The launcher starts
the API with the active configuration and opens:

```text
http://localhost:8000/?ui=enterprise
```

When `TSHARK_PATH=tshark`, the backend first checks `PATH` and then the default
Windows Wireshark install locations. Admin users can confirm the live sensor with
`GET /api/admin/capture/diagnostics`, which lists TShark interfaces, the selected
adapter, and the active capture filter.

### Docker Quick Start

```bash
# Build and launch all services
docker-compose -f deploy/docker/docker-compose.yml up -d

# Access the dashboard
open http://localhost:8080
```

### Kubernetes Deployment

```bash
# Apply namespace and configs
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml

# Deploy with Helm
helm install ddos-detector deploy/helm/ -f deploy/helm/values-production.yaml
```

## 📊 Dashboard

The system includes an Enterprise dark-mode Security Operations Center (SOC) dashboard with:

- **Verified capture status** — Live, idle, switching and recovery states from the TShark supervisor
- **Live traffic charts** — Packet rate, anomaly score and bandwidth views
- **Alert management** — Severity filters and incident visibility
- **Detection engine status** — Live scores plus stored validation metrics for each algorithm
- **Network forensics** — Current protocol and packet-feature snapshot
- **Wireless intelligence** — Passive nearby access-point indicators exposed through local-security status
- **Model training** - Shared CSV/ZIP upload for an offline CICDDoS2019 flow classifier with training metrics

## 🧠 ML Models

| Model | Implementation | Purpose |
|-------|----------------|---------|
| Isolation Forest | scikit-learn `IsolationForest` | Unsupervised anomaly scoring |
| Gradient Boosting | scikit-learn `HistGradientBoostingClassifier` | Supervised attack classification |
| Autoencoder | scikit-learn `MLPRegressor` | Reconstruction-error anomaly scoring |
| **Ensemble** | Logistic-regression stacker with weighted fallback | Combines model scores and attack fingerprints |

### Active Attack Fingerprints

- **SYN flood**: Elevated SYN and zero-payload behavior from distributed sources
- **DNS amplification**: Elevated DNS ratio with large response-like packets
- **UDP flood**: Elevated UDP share with high packet rate
- **HTTP flood**: High TCP and source-entropy traffic pattern
- **Slowloris**: Very small TCP/payload pattern
- **ICMP flood**: Elevated ICMP share with high packet rate

Additional detector components exist under `src/detection/detectors/`, but the API's
live ensemble path currently classifies the fingerprint set listed above.

### Tabular CSV/ZIP Training

Any dashboard user can open **Model Training**, select a labeled `.csv`, compressed
CSV, or `.zip` archive, and start bounded background training. For an archive, the
server reads CSV files directly without extracting the full dataset to disk, including
CSV files inside nested ZIPs. The latest completed training job replaces the shared
offline classifier artifact. The server samples up to `TRAINING_MAX_ROWS_PER_CLASS`
rows per target class, saves `models/cicddos_flow_classifier.joblib`, and displays
accuracy, balanced accuracy, F1 score, target column, selected model, and algorithm
candidate metrics.
The upload API accepts `model_type` so the offline artifact can be trained with
`hist_gradient_boosting`, `random_forest`, `extra_trees`, `logistic_regression`,
`linear_svm`, `mlp`, `gaussian_nb`, `knn`, or `auto`. The `auto` option trains the
fast supported candidates and persists the highest-scoring model by balanced
accuracy, then F1 score. The target column can be supplied with `target_column`;
otherwise common target names are detected, with the last CSV column as fallback.

The CSV classifier is an offline tabular model. The active live ensemble consumes
packet-window features with a different schema, so uploaded datasets do not replace
the live detector until a compatible live feature extractor is implemented.

For the unsupervised live models, the dashboard reports threshold-based validation
metrics rather than labeling them as accuracy: Isolation Forest shows F1, precision,
recall, tree count and contamination; Autoencoder shows F1, precision, recall and
reconstruction-error threshold/distribution values. These figures use labeled
synthetic evaluation traffic, not the uploaded CICDDoS flow dataset.

The training upload endpoint is public in the current dashboard configuration and
updates one shared offline artifact. Do not expose this write capability to an
untrusted network without adding authentication/authorization or an approval workflow.

## 🔔 Alert Integrations

- PagerDuty (incident management)
- Slack (real-time notifications)
- SIEM (CEF format events)
- Email (escalation notifications)
- Webhook (custom integrations)
- Jira (ticket creation)

## 📦 Project Structure

```
ddos-detection-system/
├── src/                    # Python backend
│   ├── config/            # Configuration management
│   ├── ingestion/         # Data ingestion pipeline
│   ├── processing/        # Stream processing & features
│   ├── detection/         # ML detection pipeline
│   ├── alerting/          # Alert system & integrations
│   ├── response/          # Response automation
│   ├── local_security/    # Wireless and local adapter threat signals
│   ├── api/               # REST/WebSocket API
│   └── monitoring/        # Observability
├── dashboard/             # Web-based SOC dashboard
├── data/                  # Enterprise wireless OUI data
├── tests/                 # Test suite
├── deploy/                # Deployment configs
├── monitoring/            # Grafana/Prometheus configs
└── docs/                  # Documentation
```

## 📝 Documentation

- [Executive Summary](docs/executive_summary.md)
- [Technical Documentation](docs/technical_documentation.md)
- [Operations Runbook](docs/operations_runbook.md)
- [API Specification](docs/api_specification.md)

## 🧪 Testing

```bash
# Run all tests
make test

# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Performance/load tests
pytest tests/performance/ -v

# Coverage report
pytest --cov=src tests/ --cov-report=html
```

## 📈 Performance Goals

These figures are project targets or generated-data evaluation results. Validate them on
representative captured traffic before using them as production guarantees.

| Metric | Project Goal |
|--------|--------------|
| Throughput | 50,000 pps |
| Detection Latency | <200ms |
| True Positive Rate | >97% |
| False Positive Rate | <1% |
| API Response Time | <100ms |
| Dashboard Update | <500ms |

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
