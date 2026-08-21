# Thread Monitoring

This stack monitors the ESP WROOM Thread topology API:

- `GET /router-neighbors`

It runs:

- a Python Prometheus exporter on port `9108`
- Prometheus on port `9090`
- Grafana on port `3000`

## Start

```bash
cp .env.example .env
docker compose up --build
```

Open:

- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090
- Exporter metrics: http://localhost:9108/metrics
- Live topology: http://localhost:9108/topology

Default Grafana login:

- username: `admin`
- password: `admin`

## Configuration

The default WROOM endpoint is already set:

```text
WROOM_BASE_URL=http://192.168.2.153
```

Edit `.env` if the WROOM IP changes.

Useful settings:

```text
SCAN_INTERVAL_SECONDS=10
ERROR_RETRY_INTERVAL_SECONDS=5
POLL_INTERVAL_SECONDS=1
SCAN_TIMEOUT_SECONDS=30
HTTP_TIMEOUT_SECONDS=5
SCAN_ON_COLLECT=true
EXPECTED_CHILD_COUNT=7
```

The exporter reads `/router-neighbors` only. The ESP32 controls scan cadence,
so exporter interval controls how quickly dashboards/metrics reflect the latest
available snapshot.

Successful collections follow `SCAN_INTERVAL_SECONDS`. Failed collections use
`ERROR_RETRY_INTERVAL_SECONDS`, so transient WROOM outages are retried faster.

## Device Names

Maintain human-readable names in:

```text
config/device-map.json
```

Example:

```json
{
  "66883c9998341936": {
    "name": "Living Room Sensor",
    "location": "Living room",
    "notes": "Near the window"
  }
}
```

The topology page uses this table for router and child labels. The exporter also
publishes the mapping as `thread_device_name`.

## Topology View

The exporter also serves a live topology page:

```text
http://localhost:9108/topology
```

It uses the latest completed scan and refreshes every 30 seconds. Routers can be
grouped by role or location; child devices are drawn under their parent router
and show their real `child_id` / `rloc16` details.

## Main Metrics

```text
thread_probe_up
thread_pending
thread_router_count
thread_router_ok_count
thread_child_count
thread_expected_child_count
thread_child_missing_count
thread_router_role{router_id,rloc16,ext_address,role}
thread_router_child_count{router_id,rloc16,ext_address}
thread_router_link_quality_count{router_id,rloc16,ext_address,quality}
thread_router_table_status{router_id,rloc16,ext_address,table,status}
thread_router_signal_status{router_id,rloc16,ext_address,status}
thread_router_graph_health_info{router_id,rloc16,ext_address,status,reliable_neighbors,leader_route_cost,weak_edge_ratio}
thread_router_reliable_neighbor_count{router_id,rloc16,ext_address}
thread_router_leader_route_cost{router_id,rloc16,ext_address}
thread_router_weak_edge_ratio{router_id,rloc16,ext_address}
thread_router_neighbor_diagnostic_present{source_router,target_router,target_rloc16,target_ext_address,field}
thread_router_neighbor_link_quality{source_router,target_router,target_rloc16,target_ext_address}
thread_router_neighbor_link_margin_db{source_router,target_router,target_rloc16,target_ext_address}
thread_router_neighbor_average_rssi_dbm{source_router,target_router,target_rloc16,target_ext_address}
thread_router_neighbor_frame_error_rate{source_router,target_router,target_rloc16,target_ext_address}
thread_router_neighbor_message_error_rate{source_router,target_router,target_rloc16,target_ext_address}
thread_child_parent_router{child_id,child_rloc16,child_ext_address}
thread_child_parent_info{child_id,child_rloc16,child_ext_address,parent_router,parent_rloc16,parent_ext_address}
thread_child_link_quality{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_diagnostic_present{parent_router,child_id,child_rloc16,child_ext_address,field}
thread_child_link_margin_db{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_average_rssi_dbm{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_timeout_seconds{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_age_seconds{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_queued_messages{parent_router,child_id,child_rloc16,child_ext_address}
thread_child_mode{parent_router,child_id,child_rloc16,child_ext_address,flag}
```

Optional diagnostic fields are exported only when the JSON includes them. Use
`thread_router_neighbor_diagnostic_present` and `thread_child_diagnostic_present`
to distinguish missing data from real zero values. `link_quality` is tracked as
a diagnostic field, but router weak alerts use the same graph-health status as
the built-in topology page. Some devices can report low `link_quality` while
also reporting healthy link margin; those cases are treated as link-quality
mismatch signals rather than weak radio links.

## Alerts

Prometheus loads starter alert rules from:

```text
prometheus/rules/thread-alerts.yml
```

Current starter rules:

- WROOM API unreachable
- scan pending for too long
- router count below `11`
- child count below `EXPECTED_CHILD_COUNT`
- child low margin or low RSSI
- link quality mismatches where LQ is low but margin is healthy
- missing neighbor diagnostic fields when the neighbor table otherwise completed
- router table detail timeouts
- router topology graph status classified as weak
- child queued messages or near-timeout age

Tune the thresholds after a few days of baseline data.
