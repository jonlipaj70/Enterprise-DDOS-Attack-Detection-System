# Operations Runbook - Release 1 Safe Live Mode

## Supported Deployment

Release 1 supports one Windows sensor host running TShark, the local firewall integration,
and one SQLite control-plane database. Do not run API replicas or enable Kubernetes
deployment for a live sensor in this release.

## Mandatory Containment Configuration

Before any live restart or test, verify the active `.env` contains:

```env
RESPONSE_MODE=monitor
AUTO_BLOCK_ENABLED=false
RESPONSE_KILL_SWITCH=true
MITIGATION_ACTIVATION_ALLOWED=false
LOCAL_THREAT_RESPONSE_MODE=monitor
LOCAL_THREAT_AUTO_DISCONNECT=false
LOCAL_THREAT_AUTO_DISABLE_ADAPTERS=false
LOCAL_THREAT_ENFORCEMENT_ALLOWED=false
```

If a running process was launched previously with enforcement active, stop that process
with Administrator privileges and restart it after verifying these values. A process
already in memory is not made safe by editing `.env`.

The startup guard refuses unsafe response or local-security settings while either release
gate is `false`.

## First Start

The monitor dashboard works without an administrator account. To operate protected
response controls or inspect audit events later, create the initial administrator once:

```powershell
python -m src.cli.create_admin
```

Then start or restart the application using `nis_projektin.bat`. The script intentionally
restarts an existing API process so that new safety configuration is applied, then opens
`http://localhost:8000/?ui=enterprise`.

Public liveness check:

```powershell
Invoke-WebRequest http://localhost:8000/api/health/live
```

Open the dashboard and verify the visible banner reads `LIVE CAPTURE`,
`WAITING FOR LIVE TRAFFIC`, `CAPTURE IDLE`, or `SIMULATION`. It must not read
`RESPONSE ENFORCEMENT ACTIVE` in Release 1.

If the dashboard connects but all metrics stay at zero, inspect the live interface map:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D
```

Admins can also inspect the sensor through the API without starting a separate
capture:

```powershell
Invoke-WebRequest http://localhost:8000/api/admin/capture/diagnostics `
  -WebSession $session
```

The response shows whether TShark was found, which `tshark -D` interfaces are visible,
the active capture filter, and the adapter selected by `CAPTURE_INTERFACE=auto`.

Set `CAPTURE_INTERFACE=auto` and restart the service. On Windows this chooses the
adapter carrying the active default route by name, avoiding stale TShark adapter
numbers after network-device changes. Set an explicit name or number only when
monitoring an adapter that is intentionally not the default route.

## Roles

| Role | Access |
| --- | --- |
| Public monitor | Dashboard, ready state, masked metrics, non-sensitive model stream, shared offline dataset training |
| Viewer | Same monitoring access through an authenticated session |
| Analyst | Viewer access plus alert review, acknowledge and resolve |
| Admin | Analyst access plus response controls, audit events and local-security raw status |

The dashboard and WebSocket default to public monitor-only output with sensitive fields
removed. Protected mutation/admin APIs use an HTTP-only JWT session cookie.

## Response Controls

The authoritative runtime state is stored in SQLite and starts as:

```text
mode=monitor, auto_block_enabled=false, kill_switch=true
```

Admin operations are audited:

- `POST /api/admin/response/kill-switch` requires `{ "enabled": true|false, "reason": "..." }`.
- `POST /api/admin/response/mode` requires a reason; any enforcement attempt also requires
  `"confirmation": "ENABLE_ENFORCEMENT"`.
- `GET /api/admin/audit` returns append-only control and authorization events.

`MITIGATION_ACTIVATION_ALLOWED=false` is mandatory in Release 1, therefore attempts to
enable `enforce` mode or automatic blocking are rejected and recorded in audit.

## Capture Status

- `/api/health/live` means only that the server responds.
- `/api/health/ready` is public and reports whether the model and capture pipeline
  are operational.
- `capture_state=receiving` means packets have actually reached detection.
- `capture_state=idle` means no packet was processed within the configured idle timeout.
- `capture_state=switching` means an automatic adapter route change was detected and capture is restarting.
- `capture_state=recovering` means TShark or the adapter is temporarily unavailable and capture is retrying automatically.
- `capture_state=failed` includes `last_capture_error`.

When a live model anomaly is suppressed by the live filter, authenticated Analysts and
Admins can receive the suppression details; the public monitor remains redacted.

## Offline Dataset Training and Model Metrics

The dashboard's **Model Training** panel currently exposes a shared public upload
workflow:

1. Prefer uploading a complete CICDDoS2019 ZIP archive, such as `CSV-01-12.zip`, when
   the intent is to retain coverage across all attack files in that archive. Generic
   labeled CSV/ZIP datasets are also supported.
2. Uploading a new dataset replaces the previous shared offline artifact, including a
   model previously trained from a ZIP.
3. Pick a model type in the dashboard, or pass `model_type` to the upload API. Supported
   values are `hist_gradient_boosting`, `random_forest`, `extra_trees`,
   `logistic_regression`, `linear_svm`, `mlp`, `gaussian_nb`, `knn`, and `auto`.
   For generic CSVs, provide `target_column` if the target is not named like `label`,
   `class`, `target`, `outcome`, or similar.
4. Confirm the completed job using `GET /api/training/cicddos/status`; review
   `result.filename`, `source_files`, `requested_model_type`, `selected_model_type`,
   `target_column`, `rows_used`, `feature_count`, `accuracy`, `balanced_accuracy`,
   `f1_score`, and `candidate_metrics`.
5. Confirm algorithm display data using `GET /api/models/validation`.

The uploaded classifier is an offline tabular artifact and is reported with
`live_model_active=false`. It does not alter TShark packet-window alerts or automated
response decisions.

Interpret the algorithm cards carefully:

- `CICDDoS Flow Classifier` metrics are calculated from the uploaded labeled flow data.
- `Gradient Boosting` and `Stacking Ensemble` metrics use synthetic held-out data for
  the live packet-window model family.
- `Isolation Forest` and `Autoencoder` are fitted without attack labels; their
  F1/precision/recall values apply their anomaly thresholds to separate labeled
  synthetic evaluation traffic.

Because any public dashboard user can replace the shared offline artifact, do not
publish the upload endpoint to an untrusted network. Before broader deployment, place
`POST /api/training/cicddos/upload` behind authenticated authorization and an audit or
approval policy.

## Security Operations

- Keep `REQUIRE_HTTPS=true` outside localhost development and terminate TLS at the
  supported single-host ingress/reverse proxy.
- Use explicit `API_CORS_ORIGINS`; wildcard CORS is not allowed with authenticated sessions.
- Review `GET /api/admin/audit` after each manual control test.
- Restrict public access to offline training uploads before exposing the dashboard outside a controlled environment.
- Verify no firewall, Wi-Fi disconnect, or adapter-disable action is executed during
  Release 1 acceptance testing.

## Recovery

If the response banner indicates enforcement unexpectedly:

1. Stop the elevated service process immediately.
2. Confirm all mandatory containment variables above.
3. Restart the service.
4. Sign in as Admin and inspect the append-only audit log.
5. Do not resume live testing until the cause is recorded and resolved.
