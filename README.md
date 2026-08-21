# Thread Monitoring

Monitor an ESP WROOM Thread topology endpoint with a small Prometheus and
Grafana stack.

The stack collects `GET /router-neighbors`, exports Prometheus metrics, ships
starter alerts, and serves a live topology view for quickly checking routers,
children, link quality, and missing diagnostics.

The ESP topology endpoint is provided by
[esp-thread-probe](https://github.com/andylee830914/esp-thread-probe).

## What It Runs

- Thread exporter: http://localhost:9108
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001

Grafana is provisioned with the Prometheus datasource, dashboard definitions,
and alerting rules from this repository.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Then open:

- Live topology: http://localhost:9108/topology
- Exporter metrics: http://localhost:9108/metrics
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001

Default Grafana login:

- Username: `admin`
- Password: `admin`

Change the Grafana credentials in `.env` before publishing this outside a local
or trusted network.

## Configuration

The main setting is the WROOM base URL:

```text
WROOM_BASE_URL=http://192.168.2.153
```

Edit `.env` if the ESP WROOM address changes.

Common settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `WROOM_BASE_URL` | `http://192.168.2.153` | ESP WROOM HTTP endpoint |
| `SCAN_INTERVAL_SECONDS` | `10` in `.env.example` | Delay between successful collections |
| `ERROR_RETRY_INTERVAL_SECONDS` | `5` in `.env.example` | Delay before retrying failed collections |
| `POLL_INTERVAL_SECONDS` | `1` | Poll interval while waiting for scan data |
| `SCAN_TIMEOUT_SECONDS` | `30` | Maximum scan wait time |
| `HTTP_TIMEOUT_SECONDS` | `5` | HTTP request timeout |
| `SCAN_ON_COLLECT` | `true` | Trigger scan collection from the exporter loop |
| `EXPECTED_CHILD_COUNT` | `7` in Docker Compose | Baseline for missing child alerts |
| `LOG_LEVEL` | `INFO` | Exporter logging level |
| `GRAFANA_ADMIN_USER` | `admin` | Grafana admin username |
| `GRAFANA_ADMIN_PASSWORD` | `admin` | Grafana admin password |

The exporter reads `/router-neighbors` only. The ESP32 controls the underlying
scan behavior; the exporter interval controls how quickly Prometheus and
Grafana see the latest available snapshot.

Successful collections use `SCAN_INTERVAL_SECONDS`. Failed collections use
`ERROR_RETRY_INTERVAL_SECONDS`, so short WROOM outages are retried faster.

## Device Map

Human-readable device names live in:

```text
config/device-map.json
```

Use the example as a starting point:

```bash
cp config/device-map.example.json config/device-map.json
```

Each key can be a Thread extended address. Metrics also fall back to `rloc16`
when no extended-address entry matches.

```json
{
  "66883c9998341936": {
    "name": "Living Room Sensor",
    "location": "1F Living Room",
    "notes": "Near the window"
  },
  "5c00": {
    "name": "Temporary Router",
    "location": "Lab",
    "notes": "Example using rloc16"
  },
  "7ebee63681a7f3f9": "Doorbell Button"
}
```

The topology page uses this map for router and child labels. The exporter also
publishes it through the `thread_device_name` metric.

## Topology View

Open:

```text
http://localhost:9108/topology
```

The page refreshes every 30 seconds and uses the latest completed scan. It can
group routers by location or signal state, draw children under their current
parent, and show details such as `child_id`, `rloc16`, link margin, RSSI,
queued messages, and table status.

## Metrics

The most useful high-level metrics are:

```text
thread_probe_up
thread_probe_last_success_timestamp_seconds
thread_pending
thread_router_count
thread_router_ok_count
thread_child_count
thread_expected_child_count
thread_child_missing_count
thread_stored_child_count
```

Router metrics include role, child counts, table status, signal state, graph
health, and neighbor diagnostics:

```text
thread_router_role{router_id,rloc16,ext_address,role}
thread_router_child_count{router_id,rloc16,ext_address}
thread_router_table_status{router_id,rloc16,ext_address,table,status}
thread_router_signal_status{router_id,rloc16,ext_address,status}
thread_router_graph_health_info{router_id,rloc16,ext_address,status,reliable_neighbors,leader_route_cost,weak_edge_ratio}
thread_router_neighbor_link_quality{source_router,target_router,target_rloc16,target_ext_address}
thread_router_neighbor_link_margin_db{source_router,target_router,target_rloc16,target_ext_address}
thread_router_neighbor_average_rssi_dbm{source_router,target_router,target_rloc16,target_ext_address}
```

Child metrics include parent mapping, link quality, timeout/age, RSSI, queued
messages, mode flags, and optional error rates:

```text
thread_child_parent_info{child_id,child_rloc16,child_ext_address,parent_router,parent_rloc16,parent_ext_address}
thread_child_link_quality{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_link_margin_db{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_average_rssi_dbm{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_timeout_seconds{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_age_seconds{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_queued_messages{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_mode{parent_router,child_id,child_rloc16,child_ext_address,flag}
```

Optional diagnostic fields are exported only when the JSON includes them. Use
`thread_router_neighbor_diagnostic_present` and `thread_child_diagnostic_present`
to tell missing diagnostics apart from real zero values.

`link_quality` is tracked as a diagnostic field, but weak-router alerts use the
same graph-health evaluation as the built-in topology page. A device can report
low `link_quality` while still reporting healthy link margin; those cases are
treated as link-quality mismatch signals instead of weak radio links.

## Alerts

Prometheus loads alert rules from:

```text
prometheus/rules/thread-alerts.yml
```

Included starter alerts cover:

- WROOM API unreachable
- scan pending for too long
- router count below the expected baseline
- child count below `EXPECTED_CHILD_COUNT`
- child low margin or low RSSI
- link-quality mismatch with healthy margin
- missing neighbor diagnostic fields
- router table timeouts
- router graph health classified as weak
- child queued messages or near-timeout age

Tune router and child baselines after a few days of normal traffic.

## Repository Layout

```text
config/                         Device name map
exporter/                       Python exporter and topology page template
grafana/                        Provisioned dashboards, datasource, alerts
prometheus/                     Prometheus scrape config and rules
docker-compose.yml              Local monitoring stack
```

## Development

Run a quick syntax check after exporter changes:

```bash
python3 -m py_compile exporter/thread_exporter.py
```

Rebuild the stack after Dockerfile, dependency, or template changes:

```bash
docker compose up --build
```
