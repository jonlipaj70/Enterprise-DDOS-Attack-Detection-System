# API Specification - Release 1 Safe Live Mode

## Authentication

`POST /api/auth/login` returns a JWT session in the HTTP-only `ddos_session` cookie.
The cookie is `SameSite=Strict` and is marked `Secure` in production or whenever
`REQUIRE_HTTPS=true`.

Roles:

| Role | Permitted API surface |
| --- | --- |
| Public monitor | Dashboard, ready state, masked metrics, redacted live WebSocket stream and offline dataset training |
| Viewer | Same monitoring access through an authenticated session |
| Analyst | Viewer plus alert list, acknowledge and resolve |
| Admin | Analyst plus response controls, audit and local-security raw data |

Public monitor endpoints are `/`, `/api/health/live`, `/api/health`,
`/api/health/ready`, `/api/metrics`, `/api/detection/status`,
`/api/traffic/history`, `/api/features/latest`, `/api/training/cicddos/status`,
`/api/models/validation`, `POST /api/training/cicddos/upload` and `WS /ws`. Login remains available
only for protected operations.

## Health

### GET /api/health/live

Public liveness response:

```json
{ "status": "alive" }
```

### GET /api/health/ready

Public monitor readiness response:

```json
{
  "status": "ready",
  "ready": true,
  "model_ready": true,
  "pipeline_running": true,
  "capture_state": "receiving",
  "last_packet_at": 1730000000.1,
  "seconds_since_last_packet": 0.2,
  "response_mode": "monitor",
  "kill_switch": true
}
```

`capture_state` is one of `starting`, `receiving`, `idle`, `switching`,
`recovering`, or `failed`. With `CAPTURE_INTERFACE=auto`, route changes cause
`switching` followed by a fresh live capture session. Temporary capture failures
enter `recovering` and retry with bounded backoff instead of requiring a process
restart.

## Authentication Routes

- `POST /api/auth/login` body: `{ "username": "...", "password": "..." }`
- `POST /api/auth/logout` revokes the current session.
- `GET /api/auth/me` returns the authenticated user and role.

## Alert Routes

Analyst or Admin:

- `GET /api/alerts`
- `GET /api/alerts/active`
- `POST /api/alerts/{alert_id}/acknowledge`
- `POST /api/alerts/{alert_id}/resolve`

Non-Admin responses do not contain local adapter inventory or network configuration.

## Response Routes

Admin only:

- `POST /api/response/block-ip`
- `POST /api/response/unblock-ip`
- `GET /api/response/actions`
- `GET /api/response/status`
- `POST /api/admin/response/kill-switch`
- `POST /api/admin/response/mode`

Response state is persistent and fail-safe. For Release 1,
`MITIGATION_ACTIVATION_ALLOWED=false`, so enforcement and automatic block activation are
rejected even for Admin users.

Example kill-switch request:

```json
{ "enabled": true, "reason": "Acceptance test containment" }
```

Example enforcement attempt shape:

```json
{
  "mode": "enforce",
  "auto_block_enabled": true,
  "reason": "Approved future rollout",
  "confirmation": "ENABLE_ENFORCEMENT"
}
```

## Admin and Local Security Routes

Admin only:

- `GET /api/admin/audit?limit=&action=&since=`
- `GET /api/admin/capture/diagnostics`
- `GET /api/local-security/status`
- `POST /api/local-security/scan`
- `GET /api/system/stats`

`GET /api/local-security/status` reports `wireless_intelligence_enabled`,
`wireless_capabilities` and the latest `snapshot.wireless_sensor` metadata. The
integrated Enterprise wireless signals are passive review findings derived from visible
wireless network inventory and local OUI lookup; monitor-mode-only frame
detections are explicitly reported as unavailable on the Windows sensor.

Audit events are append-only and hash chained in SQLite.

`GET /api/admin/capture/diagnostics` validates the live packet sensor without
starting a new capture. It resolves `TSHARK_PATH`, lists interfaces from `tshark -D`,
shows the libpcap capture filter, and reports the resolved adapter for
`CAPTURE_INTERFACE=auto`.

Representative response:

```json
{
  "capture_source": "tshark",
  "configured_interface": "auto",
  "target_host": "all",
  "target_ports": [80, 443],
  "capture_filter": "ip or ip6",
  "tshark": {
    "configured_path": "tshark",
    "resolved_path": "C:/Program Files/Wireshark/tshark.exe",
    "available": true,
    "interfaces": [
      {
        "index": 1,
        "name": "Wi-Fi",
        "display_name": "\\Device\\NPF_{...} (Wi-Fi)"
      }
    ],
    "resolved_capture_interface": "Wi-Fi",
    "error": null
  }
}
```

## CICDDoS2019 Training Routes

Public:

- `POST /api/training/cicddos/upload?filename=DrDoS_DNS.csv`
- `POST /api/training/cicddos/upload?filename=CSV-01-12.zip`
- `POST /api/training/cicddos/upload?filename=DrDoS_DNS.csv&model_type=random_forest`
- `POST /api/training/cicddos/upload?filename=generic.csv&model_type=auto&target_column=outcome`
- `GET /api/training/cicddos/status`
- `GET /api/models/validation`

The upload route accepts a raw CSV, compressed CSV, or ZIP request body, queues bounded
background training and records audit events. ZIP archives are read without full
extraction, including nested ZIP files containing CSVs. It samples at most the
configured number of rows per target class and persists an offline
`cicddos_flow_classifier` artifact. This is a shared artifact: the latest completed
public training request replaces its predecessor.

`model_type` defaults to `hist_gradient_boosting`. Supported values are
`hist_gradient_boosting`, `random_forest`, `extra_trees`, `logistic_regression`,
`linear_svm`, `mlp`, `gaussian_nb`, `knn`, and `auto`. The `auto` option evaluates
fast supported candidates and persists the candidate with the best balanced accuracy,
using F1 score as the tiebreaker. `target_column` is optional; common target names are
detected automatically and the last CSV column is used as fallback. Completed results
include `target_column`, `accuracy`, `balanced_accuracy`, `f1_score`,
`requested_model_type`, `selected_model_type`, and per-candidate metrics.

This artifact is deliberately marked `live_model_active: false`: uploaded tabular
datasets expose arbitrary feature schemas, while the live ensemble currently evaluates
packet-window features.
The model validation route reports applicable saved metrics for each algorithm.
Classification accuracy is exposed for supervised or meta-models only. Unsupervised
Isolation Forest and Autoencoder entries show F1, precision and recall obtained by
applying their anomaly thresholds to separate labeled synthetic evaluation traffic;
Autoencoder also reports reconstruction-error calibration values.

Operational note: because `POST /api/training/cicddos/upload` is public and replaces a
shared artifact, it must be access-controlled before this deployment is exposed to an
untrusted network.

Representative `GET /api/models/validation` fields:

```json
{
  "models": [
    {
      "id": "isolation_forest",
      "primary_metric": "Validation F1",
      "primary_value": 0.9562,
      "secondary_metric": "Precision",
      "secondary_value": 0.9476,
      "details": [
        { "label": "Recall", "value": 0.965, "format": "percentage" }
      ]
    },
    {
      "id": "autoencoder",
      "primary_metric": "Validation F1",
      "details": [
        { "label": "Error threshold", "value": 0.127865, "format": "decimal" },
        { "label": "Attack MSE p50", "value": 5.65852, "format": "decimal" }
      ]
    }
  ]
}
```

## WebSocket

`WS /ws` supplies a redacted public monitor stream without a session cookie. When an
authenticated session is present, its role controls additional visibility. Use `wss://`
outside localhost development. Messages include capture state, response mode and kill
switch state; suppression details remain limited to authorized operational roles.

The current detection model stream contains scores for Isolation Forest, Gradient
Boosting and Autoencoder. A `random_forest_score` response field may remain as a
backward-compatible alias of `gradient_boosting_score`; it does not identify an
additional model in the active ensemble.
