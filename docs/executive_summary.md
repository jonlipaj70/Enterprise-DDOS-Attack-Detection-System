# Executive Summary — DDoS Detection System

## Overview

The Enterprise DDoS Attack Detection System is an ML-powered platform designed to detect, classify, and report distributed denial-of-service attacks in real time. Its active detection pipeline combines Isolation Forest, Gradient Boosting and Autoencoder scores through an ensemble layer.

The current Windows live-sensor release receives traffic through Wireshark/TShark, follows active adapter changes automatically, and adds Enterprise Wireless Intelligence for passive nearby-access-point review. Response enforcement remains gated in monitor mode by default.

The dashboard also supports shared upload-based training for an offline CICDDoS2019
flow classifier from CSV or ZIP data. This offline artifact is displayed with its own
balanced accuracy and F1 metrics, but it is not active in the live TShark packet-window
detection path because the feature schemas differ.

## Business Value

- **Mean Time to Detect (MTTD)**: < 5 seconds for volumetric attacks
- **False Positive Rate**: < 1%, reducing alert fatigue
- **Active fingerprint coverage**: SYN flood, DNS amplification, UDP flood, HTTP flood, Slowloris and ICMP flood
- **ROI**: Estimated 60% reduction in DDoS-related downtime costs

## Architecture

The system employs a streaming microservices architecture:

1. **Data Ingestion** — Live TShark capture or simulated packet input using the pipeline packet schema
2. **Stream Processing** — In-process 1s/5s/60s window aggregation and feature engineering in the live API path
3. **ML Detection** — Ensemble of Isolation Forest, Gradient Boosting, and Autoencoder models
4. **Alert & Response** — Multi-tier alerting with PagerDuty, Slack, SIEM, and automated mitigation
5. **Web Dashboard** — Enterprise SOC dashboard with live capture state and traffic visualization

## Performance Goals

These values are targets or generated-data evaluation results and require validation
against representative live captures before they can be treated as production metrics.
The dashboard's Isolation Forest and Autoencoder F1/precision/recall figures are also
generated-data evaluation values: the models fit without attack labels and are evaluated
afterward against labeled synthetic traffic using their anomaly thresholds.

| Metric | Project Goal |
|--------|--------------|
| Throughput | 50,000 pps |
| Detection Latency | < 200ms |
| True Positive Rate | > 97% |
| False Positive Rate | < 1% |
| System Uptime | 99.9% |

## Deployment

The system is containerized and deployable via:
- Docker Compose (development/staging)
- Kubernetes + Helm (production)
- Terraform IaC (AWS infrastructure)

## Recommendation

This system is recommended for immediate deployment to the staging environment for a 30-day validation period, followed by production rollout with gradual traffic migration.
