import logging
import os
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, Info, generate_latest


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
WROOM_BASE_URL = os.getenv("WROOM_BASE_URL", "http://192.168.2.153").rstrip("/")
EXPORTER_PORT = int(os.getenv("EXPORTER_PORT", "9108"))
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "10"))
ERROR_RETRY_INTERVAL_SECONDS = int(os.getenv("ERROR_RETRY_INTERVAL_SECONDS", "5"))
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "1"))
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "30"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "5"))
SCAN_ON_COLLECT = os.getenv("SCAN_ON_COLLECT", "true").lower() not in {"0", "false", "no"}
DEVICE_MAP_PATH = os.getenv("DEVICE_MAP_PATH", "/config/device-map.json")
EXPECTED_CHILD_COUNT = int(os.getenv("EXPECTED_CHILD_COUNT", "7"))

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("thread-exporter")
latest_payload: dict[str, Any] = {}
latest_error = ""
payload_lock = threading.Lock()

scan_info = Info("thread_probe_scan", "Last Thread router-neighbor scan metadata")
up = Gauge("thread_probe_up", "1 when the WROOM API can be reached")
last_success = Gauge("thread_probe_last_success_timestamp_seconds", "Unix timestamp of the last complete scrape")
scan_duration = Gauge("thread_probe_scan_duration_seconds", "Seconds spent waiting for a scan result")
pending = Gauge("thread_pending", "Pending routers in the latest router-neighbor scan")
router_count = Gauge("thread_router_count", "Routers listed in the latest scan")
router_ok_count = Gauge("thread_router_ok_count", "Routers with status ok in the latest scan")
child_count = Gauge("thread_child_count", "Child devices listed in the latest scan")
expected_child_count = Gauge("thread_expected_child_count", "Expected child device baseline")
child_missing_count = Gauge("thread_child_missing_count", "Expected children not listed in the latest scan")
stored_child_count = Gauge("thread_stored_child_count", "Stored child count reported by routers")

router_present = Gauge("thread_router_present", "Router is present in latest scan", ["router_id", "rloc16", "ext_address", "status"])
router_responded = Gauge("thread_router_responded", "Router responded to latest scan", ["router_id", "rloc16", "ext_address"])
router_role = Gauge("thread_router_role", "Router role flag", ["router_id", "rloc16", "ext_address", "role"])
router_child_count = Gauge("thread_router_child_count", "Child count reported by router", ["router_id", "rloc16", "ext_address"])
router_stored_child_count = Gauge("thread_router_stored_child_count", "Stored child count reported by router", ["router_id", "rloc16", "ext_address"])
router_lq_count = Gauge("thread_router_link_quality_count", "Router link quality bucket count", ["router_id", "rloc16", "ext_address", "quality"])
router_table_status = Gauge("thread_router_table_status", "Router table collection status, 1 for ok and 0 otherwise", ["router_id", "rloc16", "ext_address", "table", "status"])
router_signal_status = Gauge("thread_router_signal_status", "Topology router signal status, matching the built-in topology page", ["router_id", "rloc16", "ext_address", "status"])
router_graph_health_info = Gauge("thread_router_graph_health_info", "Router topology graph-health fields for dashboard tables", ["router_id", "rloc16", "ext_address", "status", "reliable_neighbors", "leader_route_cost", "weak_edge_ratio"])
router_reliable_neighbor_count = Gauge("thread_router_reliable_neighbor_count", "Reliable router-neighbor count from topology graph evaluation", ["router_id", "rloc16", "ext_address"])
router_leader_route_cost = Gauge("thread_router_leader_route_cost", "Shortest route cost from the Thread leader in the topology graph", ["router_id", "rloc16", "ext_address"])
router_weak_edge_ratio = Gauge("thread_router_weak_edge_ratio", "Ratio of incident router-neighbor edges classified as weak by topology graph evaluation", ["router_id", "rloc16", "ext_address"])

router_neighbor_link_quality = Gauge("thread_router_neighbor_link_quality", "Router neighbor link quality reported from source router to target router", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_diagnostic_present = Gauge("thread_router_neighbor_diagnostic_present", "1 when a router neighbor diagnostic field is present in the latest scan", ["source_router", "target_router", "target_rloc16", "target_ext_address", "field"])
router_neighbor_link_margin = Gauge("thread_router_neighbor_link_margin_db", "Router neighbor link margin in dB", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_average_rssi = Gauge("thread_router_neighbor_average_rssi_dbm", "Router neighbor average RSSI in dBm", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_last_rssi = Gauge("thread_router_neighbor_last_rssi_dbm", "Router neighbor last RSSI in dBm", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_connection_time = Gauge("thread_router_neighbor_connection_time_seconds", "Router neighbor connection time in seconds", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_error_rate_supported = Gauge("thread_router_neighbor_error_rate_supported", "1 when router neighbor diagnostics include error rates", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_frame_error_rate = Gauge("thread_router_neighbor_frame_error_rate", "Router neighbor frame error rate as reported by Thread diagnostics", ["source_router", "target_router", "target_rloc16", "target_ext_address"])
router_neighbor_message_error_rate = Gauge("thread_router_neighbor_message_error_rate", "Router neighbor message error rate as reported by Thread diagnostics", ["source_router", "target_router", "target_rloc16", "target_ext_address"])

child_present = Gauge("thread_child_present", "Child device is present in latest scan", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_parent_router = Gauge("thread_child_parent_router", "Current parent router id for a child device", ["child_id", "child_rloc16", "child_ext_address"])
child_parent_info = Gauge("thread_child_parent_info", "Current parent router labels for a child device", ["child_id", "child_rloc16", "child_ext_address", "parent_router", "parent_rloc16", "parent_ext_address"])
child_link_quality = Gauge("thread_child_link_quality", "Child link quality reported by parent router", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_diagnostic_present = Gauge("thread_child_diagnostic_present", "1 when a child diagnostic field is present in the latest scan", ["parent_router", "child_id", "child_rloc16", "child_ext_address", "field"])
child_timeout = Gauge("thread_child_timeout_seconds", "Child timeout in seconds", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_age = Gauge("thread_child_age_seconds", "Child age in seconds since last heard by parent router", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_connection_time = Gauge("thread_child_connection_time_seconds", "Child connection time in seconds", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_link_margin = Gauge("thread_child_link_margin_db", "Child link margin in dB", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_average_rssi = Gauge("thread_child_average_rssi_dbm", "Child average RSSI in dBm", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_last_rssi = Gauge("thread_child_last_rssi_dbm", "Child last RSSI in dBm", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_queued_messages = Gauge("thread_child_queued_messages", "Queued message count for sleepy child devices", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_error_rate_supported = Gauge("thread_child_error_rate_supported", "1 when child diagnostics include error rates", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_frame_error_rate = Gauge("thread_child_frame_error_rate", "Child frame error rate as reported by Thread diagnostics", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_message_error_rate = Gauge("thread_child_message_error_rate", "Child message error rate as reported by Thread diagnostics", ["parent_router", "child_id", "child_rloc16", "child_ext_address"])
child_mode = Gauge("thread_child_mode", "Child mode flags", ["parent_router", "child_id", "child_rloc16", "child_ext_address", "flag"])
device_name = Gauge("thread_device_name", "Device name mapping from configured ext_address table; value is update timestamp", ["ext_address", "rloc16", "name", "location", "kind"])


def get_json(path: str) -> dict[str, Any]:
    response = requests.get(f"{WROOM_BASE_URL}{path}", timeout=HTTP_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def load_device_map() -> dict[str, dict[str, str]]:
    if not DEVICE_MAP_PATH:
        return {}
    try:
        with open(DEVICE_MAP_PATH, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return {}
    except Exception:
        logger.exception("failed to read device map: %s", DEVICE_MAP_PATH)
        return {}

    if not isinstance(raw, dict):
        logger.warning("device map root must be an object: %s", DEVICE_MAP_PATH)
        return {}

    normalized: dict[str, dict[str, str]] = {}
    for rloc16, value in raw.items():
        key = str(rloc16).lower()
        if isinstance(value, str):
            normalized[key] = {"name": value, "location": "", "notes": ""}
        elif isinstance(value, dict):
            normalized[key] = {
                "name": str(value.get("name") or rloc16),
                "location": str(value.get("location") or ""),
                "notes": str(value.get("notes") or ""),
            }
    return normalized


def run_scan() -> dict[str, Any]:
    started = time.monotonic()

    payload = get_json("/router-neighbors")
    scan_duration.set(time.monotonic() - started)
    return payload


def clear_router_metrics() -> None:
    for metric in [
        router_present,
        router_responded,
        router_role,
        router_child_count,
        router_stored_child_count,
        router_lq_count,
        router_table_status,
        router_signal_status,
        router_graph_health_info,
        router_reliable_neighbor_count,
        router_leader_route_cost,
        router_weak_edge_ratio,
        router_neighbor_link_quality,
        router_neighbor_diagnostic_present,
        router_neighbor_link_margin,
        router_neighbor_average_rssi,
        router_neighbor_last_rssi,
        router_neighbor_connection_time,
        router_neighbor_error_rate_supported,
        router_neighbor_frame_error_rate,
        router_neighbor_message_error_rate,
        child_present,
        child_parent_router,
        child_parent_info,
        child_link_quality,
        child_diagnostic_present,
        child_timeout,
        child_age,
        child_connection_time,
        child_link_margin,
        child_average_rssi,
        child_last_rssi,
        child_queued_messages,
        child_error_rate_supported,
        child_frame_error_rate,
        child_message_error_rate,
        child_mode,
        device_name,
    ]:
        metric.clear()


def numeric_value(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def int_value(value: Any, default: int) -> int:
    numeric = numeric_value(value)
    return default if numeric is None else int(numeric)


def set_optional_metric(metric: Gauge, value: Any, *labels: str) -> None:
    numeric = numeric_value(value)
    if numeric is not None:
        metric.labels(*labels).set(numeric)


def link_quality_from_margin(margin: float | None) -> int | None:
    if margin is None:
        return None
    if margin > 20:
        return 3
    if margin > 10:
        return 2
    if margin > 2:
        return 1
    return 0


def cost_for_link_quality(quality: float | None) -> int | None:
    if quality is None:
        return None
    if quality >= 3:
        return 1
    if quality == 2:
        return 2
    if quality == 1:
        return 4
    return None


def report_severity(report: dict[str, float | None] | None) -> int:
    if not report:
        return 0
    link_margin = report.get("link_margin")
    average_rssi = report.get("average_rssi")
    link_quality = report.get("link_quality")
    if (link_margin is not None and link_margin > 0 and link_margin <= 12) or (average_rssi is not None and average_rssi <= -100):
        return 3
    if link_quality is not None and link_quality <= 1 and link_margin is not None and link_margin >= 20:
        return 2
    if (link_margin is not None and link_margin > 0 and link_margin <= 20) or (average_rssi is not None and average_rssi <= -95) or (link_quality is not None and link_quality <= 1):
        return 1
    return 0


def shortest_paths(router_ids: list[str], adjacency: dict[str, list[dict[str, int]]], start_id: str | None) -> dict[str, float]:
    distances = {router_id: float("inf") for router_id in router_ids}
    if start_id is None or start_id not in distances:
        return distances
    distances[start_id] = 0
    queue = [{"id": start_id, "cost": 0}]
    while queue:
        queue.sort(key=lambda item: item["cost"])
        current = queue.pop(0)
        current_id = str(current["id"])
        current_cost = current["cost"]
        if current_cost != distances[current_id]:
            continue
        for next_hop in adjacency.get(current_id, []):
            cost = current_cost + next_hop["cost"]
            next_id = next_hop["to"]
            if cost < distances[next_id]:
                distances[next_id] = cost
                queue.append({"id": next_id, "cost": cost})
    return distances


def set_topology_graph_metrics(routers: list[dict[str, Any]]) -> None:
    router_by_id = {str(router.get("router_id", "")): router for router in routers}
    edge_by_key: dict[str, dict[str, Any]] = {}

    for router in routers:
        source_id = str(router.get("router_id", ""))
        for neighbor in router.get("router_neighbors", []) or []:
            target_id = str(neighbor.get("router_id", ""))
            if target_id not in router_by_id:
                continue
            key = "-".join(sorted([source_id, target_id]))
            report = {
                "from": source_id,
                "to": target_id,
                "link_quality": numeric_value(neighbor.get("link_quality")),
                "link_margin": numeric_value(neighbor.get("link_margin")),
                "average_rssi": numeric_value(neighbor.get("average_rssi")),
            }
            if key not in edge_by_key:
                edge_by_key[key] = {"source": source_id, "target": target_id, "reports": []}
            edge_by_key[key]["reports"].append(report)

    mesh_links = []
    for link in edge_by_key.values():
        reports = link["reports"]
        margins = [report["link_margin"] for report in reports if report["link_margin"] is not None]
        diagnostic_reports = [
            report for report in reports
            if report["link_quality"] is not None or report["link_margin"] is not None or report["average_rssi"] is not None
        ]
        effective_lqs = [
            report["link_quality"] if report["link_quality"] is not None else link_quality_from_margin(report["link_margin"])
            for report in reports
        ]
        effective_lqs = [quality for quality in effective_lqs if quality is not None]
        worst_report = sorted(
            diagnostic_reports or reports,
            key=lambda report: (-report_severity(report), report["link_margin"] if report["link_margin"] is not None else 999, report["link_quality"] if report["link_quality"] is not None else 999),
        )[0] if reports else None
        two_way_lq = min(effective_lqs) if effective_lqs else None
        route_cost = cost_for_link_quality(two_way_lq)
        min_margin = min(margins) if margins else None
        mesh_links.append({
            **link,
            "route_cost": route_cost,
            "reliable": route_cost is not None and route_cost <= 2 and (min_margin is None or min_margin >= 10),
            "severity": report_severity(worst_report),
        })

    router_ids = list(router_by_id.keys())
    adjacency = {router_id: [] for router_id in router_ids}
    for edge in mesh_links:
        if edge["route_cost"] is None:
            continue
        adjacency[edge["source"]].append({"to": edge["target"], "cost": edge["route_cost"]})
        adjacency[edge["target"]].append({"to": edge["source"], "cost": edge["route_cost"]})

    leader = next((router for router in routers if router.get("leader") and str(router.get("status", "")) == "ok"), routers[0] if routers else None)
    leader_costs = shortest_paths(router_ids, adjacency, str(leader.get("router_id", "")) if leader else None)

    for router in routers:
        router_id = str(router.get("router_id", ""))
        rloc16 = str(router.get("rloc16", ""))
        ext_address = str(router.get("ext_address", ""))
        labels = (router_id, rloc16, ext_address)
        incident = [edge for edge in mesh_links if edge["source"] == router_id or edge["target"] == router_id]
        weak_edges = [edge for edge in incident if edge["severity"] >= 3]
        reliable_count = len([edge for edge in incident if edge["reliable"]])
        weak_ratio = len(weak_edges) / len(incident) if incident else 1
        leader_cost = leader_costs.get(router_id, float("inf"))
        data_incomplete = str(router.get("child_table_status", "unknown")) != "ok" or str(router.get("router_neighbor_table_status", "unknown")) != "ok"

        if data_incomplete:
            status = "data_incomplete"
        elif reliable_count == 0 or not leader_cost < float("inf"):
            status = "weak"
        elif reliable_count == 1 or leader_cost > 4 or weak_ratio > 0.5:
            status = "watch"
        else:
            status = "ok"

        router_reliable_neighbor_count.labels(*labels).set(reliable_count)
        if leader_cost < float("inf"):
            router_leader_route_cost.labels(*labels).set(leader_cost)
        router_weak_edge_ratio.labels(*labels).set(weak_ratio)
        router_graph_health_info.labels(
            router_id,
            rloc16,
            ext_address,
            status,
            str(reliable_count),
            str(int(leader_cost)) if leader_cost < float("inf") else "unreachable",
            f"{round(weak_ratio * 100)}%",
        ).set(1)
        for candidate in ["data_incomplete", "weak", "watch", "ok"]:
            router_signal_status.labels(*labels, candidate).set(1 if candidate == status else 0)


def set_metrics(payload: dict[str, Any]) -> None:
    global latest_error
    clear_router_metrics()
    names = load_device_map()
    device_name_timestamp = time.time()
    routers = payload.get("routers", [])
    children_total = 0
    stored_children_total = 0
    ok_total = 0

    scan_info.info({
        "scan_id": str(payload.get("scan_id", "")),
        "scan_started_ms": str(payload.get("scan_started_ms", "")),
        "scan_age_ms": str(payload.get("scan_age_ms", "")),
        "wroom_base_url": WROOM_BASE_URL,
    })
    pending.set(int(payload.get("pending_total", payload.get("pending", 0)) or 0))
    router_count.set(len(routers))
    expected_child_count.set(EXPECTED_CHILD_COUNT)

    for router in routers:
        router_id = str(router.get("router_id", ""))
        rloc16 = str(router.get("rloc16", ""))
        ext_address = str(router.get("ext_address", ""))
        status = str(router.get("status", "unknown"))
        if status == "ok":
            ok_total += 1

        children = router.get("children", []) or []
        child_total = int_value(router.get("child_count"), len(children))
        stored_child_total = int_value(router.get("stored_child_count"), child_total)
        children_total += len(children)
        stored_children_total += stored_child_total

        router_present.labels(router_id, rloc16, ext_address, status).set(1)
        entry = names.get(ext_address.lower()) or names.get(rloc16.lower())
        if entry:
            device_name.labels(ext_address, rloc16, entry["name"], entry["location"], "router").set(device_name_timestamp)
        router_responded.labels(router_id, rloc16, ext_address).set(1 if router.get("responded") else 0)
        router_role.labels(router_id, rloc16, ext_address, "leader").set(1 if router.get("leader") else 0)
        router_role.labels(router_id, rloc16, ext_address, "border_router").set(1 if router.get("border_router") else 0)
        router_role.labels(router_id, rloc16, ext_address, "this_device").set(1 if router.get("this_device") else 0)
        router_role.labels(router_id, rloc16, ext_address, "this_device_parent").set(1 if router.get("this_device_parent") else 0)
        router_child_count.labels(router_id, rloc16, ext_address).set(child_total)
        router_stored_child_count.labels(router_id, rloc16, ext_address).set(stored_child_total)

        for table in ["child_table", "router_neighbor_table"]:
            status_value = str(router.get(f"{table}_status", "unknown"))
            router_table_status.labels(router_id, rloc16, ext_address, table, status_value).set(1 if status_value == "ok" else 0)

        lq_counts = router.get("link_quality_counts", {}) or {}
        if not lq_counts:
            lq_counts = {"lq1": 0, "lq2": 0, "lq3": 0}
            for neighbor in router.get("router_neighbors", []) or []:
                try:
                    quality = int(neighbor.get("link_quality"))
                except (TypeError, ValueError):
                    continue
                if quality >= 3:
                    lq_counts["lq3"] += 1
                elif quality == 2:
                    lq_counts["lq2"] += 1
                else:
                    lq_counts["lq1"] += 1
        lq_counts["missing"] = 0
        for neighbor in router.get("router_neighbors", []) or []:
            if "link_quality" not in neighbor or neighbor.get("link_quality") is None:
                lq_counts["missing"] += 1
        for quality in ["lq1", "lq2", "lq3", "missing"]:
            router_lq_count.labels(router_id, rloc16, ext_address, quality).set(int(lq_counts.get(quality, 0) or 0))

        for neighbor in router.get("router_neighbors", []) or []:
            target = str(neighbor.get("router_id", ""))
            target_rloc16 = str(neighbor.get("rloc16", ""))
            target_ext_address = str(neighbor.get("ext_address", ""))
            labels = (router_id, target, target_rloc16, target_ext_address)
            for field in [
                "link_quality",
                "link_margin",
                "average_rssi",
                "last_rssi",
                "connection_time",
                "supports_error_rate",
                "frame_error_rate",
                "message_error_rate",
            ]:
                router_neighbor_diagnostic_present.labels(*labels, field).set(1 if field in neighbor and neighbor.get(field) is not None else 0)
            set_optional_metric(router_neighbor_link_quality, neighbor.get("link_quality"), *labels)
            set_optional_metric(router_neighbor_link_margin, neighbor.get("link_margin"), *labels)
            set_optional_metric(router_neighbor_average_rssi, neighbor.get("average_rssi"), *labels)
            set_optional_metric(router_neighbor_last_rssi, neighbor.get("last_rssi"), *labels)
            set_optional_metric(router_neighbor_connection_time, neighbor.get("connection_time"), *labels)
            if "supports_error_rate" in neighbor and neighbor.get("supports_error_rate") is not None:
                router_neighbor_error_rate_supported.labels(*labels).set(1 if neighbor.get("supports_error_rate") else 0)
            set_optional_metric(router_neighbor_frame_error_rate, neighbor.get("frame_error_rate"), *labels)
            set_optional_metric(router_neighbor_message_error_rate, neighbor.get("message_error_rate"), *labels)

        for child in children:
            child_id = str(child.get("child_id", ""))
            child_rloc16 = str(child.get("rloc16", ""))
            child_ext_address = str(child.get("ext_address", ""))
            name_entry = names.get(child_ext_address.lower()) or names.get(child_rloc16.lower())
            child_present.labels(router_id, child_id, child_rloc16, child_ext_address).set(1)
            set_optional_metric(child_parent_router, router_id, child_id, child_rloc16, child_ext_address)
            child_parent_info.labels(child_id, child_rloc16, child_ext_address, router_id, rloc16, ext_address).set(1)
            if name_entry:
                device_name.labels(child_ext_address, child_rloc16, name_entry["name"], name_entry["location"], "child").set(device_name_timestamp)
            child_labels = (router_id, child_id, child_rloc16, child_ext_address)
            for field in [
                "link_quality",
                "timeout",
                "age",
                "connection_time",
                "link_margin",
                "average_rssi",
                "last_rssi",
                "queued_message_count",
                "supports_error_rate",
                "frame_error_rate",
                "message_error_rate",
            ]:
                child_diagnostic_present.labels(*child_labels, field).set(1 if field in child and child.get(field) is not None else 0)
            set_optional_metric(child_link_quality, child.get("link_quality"), *child_labels)
            set_optional_metric(child_timeout, child.get("timeout"), *child_labels)
            set_optional_metric(child_age, child.get("age"), *child_labels)
            set_optional_metric(child_connection_time, child.get("connection_time"), *child_labels)
            set_optional_metric(child_link_margin, child.get("link_margin"), *child_labels)
            set_optional_metric(child_average_rssi, child.get("average_rssi"), *child_labels)
            set_optional_metric(child_last_rssi, child.get("last_rssi"), *child_labels)
            set_optional_metric(child_queued_messages, child.get("queued_message_count"), *child_labels)
            if "supports_error_rate" in child and child.get("supports_error_rate") is not None:
                child_error_rate_supported.labels(*child_labels).set(1 if child.get("supports_error_rate") else 0)
            set_optional_metric(child_frame_error_rate, child.get("frame_error_rate"), *child_labels)
            set_optional_metric(child_message_error_rate, child.get("message_error_rate"), *child_labels)
            mode = child.get("mode", {}) or {}
            child_mode.labels(router_id, child_id, child_rloc16, child_ext_address, "rx_on_when_idle").set(1 if mode.get("rx_on_when_idle") else 0)
            child_mode.labels(router_id, child_id, child_rloc16, child_ext_address, "full_thread_device").set(1 if mode.get("full_thread_device") else 0)
            child_mode.labels(router_id, child_id, child_rloc16, child_ext_address, "full_network_data").set(1 if mode.get("full_network_data") else 0)

    set_topology_graph_metrics(routers)
    router_ok_count.set(ok_total)
    child_count.set(children_total)
    child_missing_count.set(max(0, EXPECTED_CHILD_COUNT - children_total))
    stored_child_count.set(stored_children_total)
    up.set(1)
    last_success.set(time.time())
    with payload_lock:
        latest_payload.clear()
        latest_payload.update(payload)
        latest_error = ""


def topology_page() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Thread Topology</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
  <style>
    :root {
      color-scheme: light dark;
      --bg: Canvas;
      --fg: CanvasText;
      --muted: color-mix(in srgb, CanvasText 62%, Canvas);
      --border: color-mix(in srgb, CanvasText 18%, Canvas);
      --card: color-mix(in srgb, Canvas 92%, CanvasText);
      --router: #3b82f6;
      --leader: #22c55e;
      --child: #f59e0b;
      --lq3: #22c55e;
      --lq2: #f59e0b;
      --lq1: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      background: var(--bg);
      color: var(--fg);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 18px;
    }
    header {
      align-items: end;
      display: flex;
      flex-wrap: wrap;
      gap: 8px 18px;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    h1 { font-size: 20px; font-weight: 600; margin: 0; }
    .muted { color: var(--muted); }
    .stats {
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(5, minmax(120px, 1fr));
      margin-bottom: 12px;
    }
    .stat {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
    }
    .label { color: var(--muted); font-size: 12px; }
    .value { font-size: 18px; font-weight: 600; margin-top: 2px; }
    .legend {
      align-items: center;
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 10px 14px;
      font-size: 13px;
      margin-bottom: 8px;
    }
    .legend span { align-items: center; display: inline-flex; gap: 6px; }
    .swatch { border-radius: 999px; display: inline-block; height: 10px; width: 24px; }
    .toolbar {
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .segmented {
      align-items: center;
      border: 1px solid var(--border);
      border-radius: 8px;
      display: inline-flex;
      overflow: hidden;
    }
    .segmented button {
      background: transparent;
      border: 0;
      color: var(--fg);
      cursor: pointer;
      font: inherit;
      padding: 7px 10px;
    }
    .segmented button.active {
      background: var(--router);
      color: white;
    }
    .graph {
      border: 1px solid var(--border);
      border-radius: 8px;
      min-height: 720px;
      overflow: hidden;
    }
    svg { display: block; height: 720px; width: 100%; }
    .band-line { stroke: var(--border); stroke-width: 1; }
    .band-label, .edge-label, .sub { fill: var(--muted); font-size: 12px; }
    .mesh-edge, .child-edge, .direction-edge { fill: none; stroke-linecap: round; }
    .child-edge { stroke-dasharray: 3 3; }
    .direction-edge {
      animation: flow 1.1s linear infinite;
      opacity: 0.95;
      pointer-events: none;
      stroke-dasharray: 8 7;
    }
    @keyframes flow {
      to { stroke-dashoffset: -30; }
    }
    .router-node, .child-node, .mesh-edge, .child-edge { cursor: pointer; }
    .router-node circle, .child-node circle { stroke: var(--bg); stroke-width: 2px; }
    .router-node text, .child-node text { fill: var(--fg); pointer-events: none; }
    .main { font-weight: 600; }
    .name-label { fill: var(--fg); font-size: 11px; font-weight: 600; paint-order: stroke; stroke: var(--bg); stroke-width: 3px; }
    .br-badge rect { fill: var(--child); opacity: 0.92; stroke: var(--bg); stroke-width: 1.5px; }
    .br-badge text { fill: var(--fg); font-size: 9px; font-weight: 600; }
    .dim { opacity: 0.16; }
    .signal-table {
      border-collapse: collapse;
      margin-top: 8px;
      width: 100%;
    }
    .signal-table th, .signal-table td {
      border-top: 1px solid var(--border);
      font-size: 12px;
      padding: 5px 6px;
      text-align: left;
      white-space: nowrap;
    }
    .signal-table th { color: var(--muted); font-weight: 600; }
    .signal-table .num { text-align: right; }
    .detail {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-top: 10px;
      min-height: 44px;
      padding: 10px 12px;
    }
    @media (max-width: 760px) {
      body { padding: 10px; }
      .stats { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
      .graph { min-height: 640px; }
      svg { height: 640px; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Thread Topology</h1>
      <div class="muted" id="subtitle">Loading latest scan...</div>
    </div>
    <div class="muted">auto refresh: 30s</div>
  </header>
  <section class="stats">
    <div class="stat"><div class="label">Probe</div><div class="value" id="probe">-</div></div>
    <div class="stat"><div class="label">Routers</div><div class="value" id="routers">-</div></div>
    <div class="stat"><div class="label">Children</div><div class="value" id="children">-</div></div>
    <div class="stat"><div class="label">Pending</div><div class="value" id="pending">-</div></div>
    <div class="stat"><div class="label">Links</div><div class="value" id="links">-</div></div>
  </section>
  <div class="toolbar">
    <div class="legend">
      <span><i class="swatch" style="background:var(--lq3)"></i>LQ 3</span>
      <span><i class="swatch" style="background:var(--lq2)"></i>LQ 2</span>
      <span><i class="swatch" style="background:var(--lq1)"></i>LQ 0-1</span>
      <span><i class="swatch" style="background:var(--child)"></i>Child / BR</span>
    </div>
    <div class="segmented" aria-label="layout mode">
      <button type="button" class="active" data-layout="location">Location</button>
      <button type="button" data-layout="signal">Signal</button>
    </div>
  </div>
  <main class="graph"><svg aria-label="Thread topology"></svg></main>
  <div class="detail" id="detail">Select a router, child, or link.</div>
  <script>
    const svg = d3.select("svg");
    const detail = document.getElementById("detail");
    const color = (lq) => lq >= 3 ? "var(--lq3)" : lq === 2 ? "var(--lq2)" : "var(--lq1)";
    const numOrNull = (value) => value == null || value === "" || !Number.isFinite(Number(value)) ? null : Number(value);
    const fmt = (value, suffix = "") => value == null ? "-" : `${value}${suffix}`;
    const esc = (value) => String(value ?? "-").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
    const reportSeverity = (report) => {
      if (!report) return 0;
      const linkMargin = report.linkMargin;
      const averageRssi = report.averageRssi;
      const linkQuality = report.linkQuality;
      if ((linkMargin != null && linkMargin > 0 && linkMargin <= 12) || (averageRssi != null && averageRssi <= -100)) return 3;
      if (linkQuality != null && linkQuality <= 1 && linkMargin != null && linkMargin >= 20) return 2;
      if ((linkMargin != null && linkMargin > 0 && linkMargin <= 20) || (averageRssi != null && averageRssi <= -95) || (linkQuality != null && linkQuality <= 1)) return 1;
      return 0;
    };
    const severityColor = (severity) => severity >= 3 ? "var(--lq1)" : severity === 2 ? "var(--lq2)" : "var(--lq3)";
    const severityLabel = (severity) => severity >= 3 ? "Weak" : severity === 2 ? "LQ mismatch" : severity === 1 ? "Watch" : "OK";
    const linkQualityFromMargin = (margin) => {
      if (margin == null) return null;
      if (margin > 20) return 3;
      if (margin > 10) return 2;
      if (margin > 2) return 1;
      return 0;
    };
    const costForLinkQuality = (quality) => {
      if (quality == null) return null;
      if (quality >= 3) return 1;
      if (quality === 2) return 2;
      if (quality === 1) return 4;
      return null;
    };
    const effectiveLinkQuality = (report) => report.linkQuality ?? linkQualityFromMargin(report.linkMargin);
    const routerSignalLabel = (router) => router.dataIncomplete ? "Data Incomplete" : router.signalStatus;
    let layoutMode = "location";
    let latestBody = null;

    document.querySelectorAll("[data-layout]").forEach((button) => {
      button.addEventListener("click", () => {
        layoutMode = button.dataset.layout;
        document.querySelectorAll("[data-layout]").forEach((item) => item.classList.toggle("active", item === button));
        if (latestBody) draw(latestBody.payload, latestBody.last_success, latestBody.error, latestBody.device_map || {}, latestBody.expected_child_count);
      });
    });

    async function load() {
      const response = await fetch("/topology.json", { cache: "no-store" });
      const body = await response.json();
      if (!body.payload || !body.payload.routers) {
        document.getElementById("probe").textContent = "down";
        document.getElementById("subtitle").textContent = body.error || "No scan data yet";
        return;
      }
      latestBody = body;
      draw(body.payload, body.last_success, body.error, body.device_map || {}, body.expected_child_count);
    }

    function draw(raw, lastSuccess, error, deviceMap, expectedChildCount) {
      svg.selectAll("*").remove();
      const mapKey = (rloc16) => String(rloc16 || "").toLowerCase();
      const deviceInfo = (extAddress) => deviceMap[mapKey(extAddress)] || null;
      const deviceName = (extAddress, fallback) => {
        const info = deviceInfo(extAddress);
        return info && info.name ? info.name : fallback;
      };
      const compactName = (name) => {
        const cleaned = String(name || "").replace(/\\b(Thread|Router|Sensor|Controller)\\b/g, "").replace(/\\s+/g, " ").trim();
        const firstWords = cleaned.split(" ").slice(0, 2).join(" ") || name;
        return firstWords.length > 13 ? `${firstWords.slice(0, 12)}…` : firstWords;
      };
      const routers = raw.routers.map((router) => ({
        id: router.router_id,
        rloc16: router.rloc16,
        extAddress: router.ext_address,
        name: deviceName(router.ext_address || router.rloc16, `Router ${router.router_id}`),
        info: deviceInfo(router.ext_address || router.rloc16),
        status: router.status,
        leader: Boolean(router.leader),
        borderRouter: Boolean(router.border_router),
        childTableStatus: router.child_table_status || "unknown",
        routerNeighborTableStatus: router.router_neighbor_table_status || "unknown",
        children: router.children || [],
        childCount: router.child_count || 0,
        neighbors: router.router_neighbors || []
      }));
      for (const router of routers) {
        const counts = { lq1: 0, lq2: 0, lq3: 0, missing: 0 };
        for (const neighbor of router.neighbors) {
          const quality = numOrNull(neighbor.link_quality);
          if (quality == null) {
            counts.missing += 1;
            continue;
          }
          if (quality >= 3) counts.lq3 += 1;
          else if (quality === 2) counts.lq2 += 1;
          else counts.lq1 += 1;
        }
        router.counts = counts;
      }
      const routerById = new Map(routers.map((router) => [router.id, router]));
      const edgeByKey = new Map();
      for (const router of routers) {
        for (const neighbor of router.neighbors) {
          if (!routerById.has(neighbor.router_id)) continue;
          const a = Math.min(router.id, neighbor.router_id);
          const b = Math.max(router.id, neighbor.router_id);
          const key = `${a}-${b}`;
          const report = {
            from: router.id,
            to: neighbor.router_id,
            linkQuality: numOrNull(neighbor.link_quality),
            linkMargin: numOrNull(neighbor.link_margin),
            averageRssi: numOrNull(neighbor.average_rssi),
            lastRssi: numOrNull(neighbor.last_rssi),
            frameErrorRate: numOrNull(neighbor.frame_error_rate),
            messageErrorRate: numOrNull(neighbor.message_error_rate)
          };
          if (!edgeByKey.has(key)) edgeByKey.set(key, { source: a, target: b, reports: [] });
          edgeByKey.get(key).reports.push(report);
        }
      }
      const meshLinks = Array.from(edgeByKey.values()).map((link) => {
        const lqs = link.reports.map((report) => report.linkQuality).filter((value) => value != null);
        const margins = link.reports.map((report) => report.linkMargin).filter((value) => value != null);
        const diagnosticReports = link.reports.filter((report) => report.linkQuality != null || report.linkMargin != null || report.averageRssi != null);
        const effectiveLqs = link.reports.map(effectiveLinkQuality).filter((value) => value != null);
        const worstReport = (diagnosticReports.length ? diagnosticReports : link.reports)
          .slice()
          .sort((a, b) => reportSeverity(b) - reportSeverity(a) || (a.linkMargin ?? 999) - (b.linkMargin ?? 999) || (a.linkQuality ?? 999) - (b.linkQuality ?? 999))[0];
        const twoWayLq = effectiveLqs.length >= 2 ? Math.min(...effectiveLqs) : (effectiveLqs.length === 1 ? effectiveLqs[0] : null);
        const routeCost = costForLinkQuality(twoWayLq);
        const minMargin = margins.length ? Math.min(...margins) : null;
        return {
          ...link,
          source: routerById.get(link.source),
          target: routerById.get(link.target),
          bestLq: lqs.length ? Math.max(...lqs) : null,
          bestMargin: margins.length ? Math.max(...margins) : null,
          twoWayLq,
          routeCost,
          reliable: routeCost != null && routeCost <= 2 && (minMargin == null || minMargin >= 10),
          worstReport,
          severity: reportSeverity(worstReport)
        };
      });
      const adjacency = new Map(routers.map((router) => [router.id, []]));
      for (const edge of meshLinks) {
        if (edge.routeCost == null) continue;
        adjacency.get(edge.source.id)?.push({ to: edge.target.id, cost: edge.routeCost });
        adjacency.get(edge.target.id)?.push({ to: edge.source.id, cost: edge.routeCost });
      }
      function shortestPathsFrom(startId) {
        const distances = new Map(routers.map((router) => [router.id, Infinity]));
        if (startId == null || !distances.has(startId)) return distances;
        distances.set(startId, 0);
        const queue = [{ id: startId, cost: 0 }];
        while (queue.length) {
          queue.sort((a, b) => a.cost - b.cost);
          const current = queue.shift();
          if (current.cost !== distances.get(current.id)) continue;
          for (const next of adjacency.get(current.id) || []) {
            const cost = current.cost + next.cost;
            if (cost < distances.get(next.to)) {
              distances.set(next.to, cost);
              queue.push({ id: next.to, cost });
            }
          }
        }
        return distances;
      }
      const leaderRouter = routers.find((router) => router.leader && router.status === "ok") || routers[0];
      const leaderCosts = shortestPathsFrom(leaderRouter && leaderRouter.id);
      for (const router of routers) {
        const incident = meshLinks.filter((edge) => edge.source.id === router.id || edge.target.id === router.id);
        const weakEdges = incident.filter((edge) => edge.severity >= 3).length;
        router.reliableNeighborCount = incident.filter((edge) => edge.reliable).length;
        router.weakEdgeRatio = incident.length ? weakEdges / incident.length : 1;
        router.leaderRouteCost = leaderCosts.get(router.id);
        router.dataIncomplete = router.childTableStatus !== "ok" || router.routerNeighborTableStatus !== "ok";
        if (router.dataIncomplete) {
          router.signalStatus = "Data Incomplete";
          router.signalSeverity = 3;
        } else if (router.reliableNeighborCount === 0 || !Number.isFinite(router.leaderRouteCost)) {
          router.signalStatus = "Weak";
          router.signalSeverity = 3;
        } else if (router.reliableNeighborCount === 1 || router.leaderRouteCost > 4 || router.weakEdgeRatio > 0.5) {
          router.signalStatus = "Watch";
          router.signalSeverity = 1;
        } else {
          router.signalStatus = "OK";
          router.signalSeverity = 0;
        }
      }
      const childNodes = routers.flatMap((router) => router.children.map((child, index) => ({
        id: child.ext_address || `${router.id}-${child.rloc16}`,
        childId: child.child_id,
        rloc16: child.rloc16,
        extAddress: child.ext_address,
        name: deviceName(child.ext_address || child.rloc16, `Child ${child.child_id}`),
        info: deviceInfo(child.ext_address || child.rloc16),
        timeout: child.timeout,
        linkQuality: numOrNull(child.link_quality),
        linkMargin: numOrNull(child.link_margin),
        averageRssi: numOrNull(child.average_rssi),
        lastRssi: numOrNull(child.last_rssi),
        queuedMessages: numOrNull(child.queued_message_count),
        mode: child.mode || {},
        parent: router,
        index
      })));
      const leader = leaderRouter;

      document.getElementById("probe").textContent = error ? "degraded" : "up";
      document.getElementById("routers").textContent = routers.length;
      document.getElementById("children").textContent = expectedChildCount ? `${childNodes.length}/${expectedChildCount}` : childNodes.length;
      document.getElementById("pending").textContent = raw.pending_total ?? raw.pending ?? 0;
      document.getElementById("links").textContent = meshLinks.length;
      const scanAge = raw.scan_age_ms != null ? `${(raw.scan_age_ms / 1000).toFixed(raw.scan_age_ms >= 10000 ? 0 : 1)}s old` : "age unknown";
      document.getElementById("subtitle").textContent = `scan ${raw.scan_id ?? "-"} · ${scanAge} · ${lastSuccess ? new Date(lastSuccess * 1000).toLocaleString() : "waiting"}`;

      const box = svg.node().getBoundingClientRect();
      const width = Math.max(720, box.width || 720);
      const height = box.height || 720;
      const margin = { top: 48, right: 34, bottom: 64, left: 34 };
      svg.attr("viewBox", `0 0 ${width} ${height}`);

      const locationOrder = ["1F", "2F", "3F", "4F"];
      const signalOrder = ["Data Incomplete", "Weak", "Watch", "OK"];
      const bandValues = layoutMode === "location" ? locationOrder : signalOrder;
      const bandGap = (height - margin.top - margin.bottom) / bandValues.length;
      const bandLabels = layoutMode === "location"
        ? new Map(locationOrder.map((item) => [item, item]))
        : new Map(signalOrder.map((item) => [item, item]));
      const bandIndex = new Map(bandValues.map((item, index) => [item, index]));
      const routerRole = (router) => router.leader ? "Leader" : (router.borderRouter ? "Border Router" : "Router");
      const groupKey = (router) => {
        if (layoutMode === "location") return (router.info && router.info.location) || "Unknown";
        return routerSignalLabel(router);
      };
      const groups = d3.group(routers, groupKey);
      for (const [groupValue, group] of groups) {
        const sorted = group.sort((a, b) => a.id - b.id);
        const idx = bandIndex.has(groupValue) ? bandIndex.get(groupValue) : bandValues.length - 1;
        const y = margin.top + idx * bandGap;
        sorted.forEach((router, index) => {
          router.x = margin.left + ((index + 1) * (width - margin.left - margin.right)) / (sorted.length + 1);
          router.y = y;
        });
      }
      if (layoutMode === "location") {
        // In location mode, distribute children across their own floor level, below routers
        const childGroups = d3.group(childNodes, (child) => (child.info && child.info.location) || "Unknown");
        for (const [groupValue, group] of childGroups) {
          const idx = bandIndex.has(groupValue) ? bandIndex.get(groupValue) : bandValues.length - 1;
          const y = margin.top + idx * bandGap + 62;
          const sorted = group.sort((a, b) => String(a.extAddress || a.rloc16).localeCompare(String(b.extAddress || b.rloc16)));
          sorted.forEach((child, index) => {
            child.x = margin.left + ((index + 1) * (width - margin.left - margin.right)) / (sorted.length + 1);
            child.y = y;
          });
        }
      } else {
        // In signal mode, place children below their parent
        for (const child of childNodes) {
          const count = child.parent.children.length;
          const spread = (count - 1) * 48;
          child.x = child.parent.x - spread / 2 + child.index * 48;
          child.y = child.parent.y + 62;
        }
      }

      const bandLayer = svg.append("g");
      const meshLayer = svg.append("g");
      const directionLayer = svg.append("g");
      const childLayer = svg.append("g");
      const nodeLayer = svg.append("g");

      const defs = svg.append("defs");
      [
        ["ok", "var(--lq3)"],
        ["watch", "var(--lq2)"],
        ["weak", "var(--lq1)"]
      ].forEach(([name, fill]) => {
        defs.append("marker")
          .attr("id", `arrow-${name}`)
          .attr("viewBox", "0 0 10 10")
          .attr("refX", 8)
          .attr("refY", 5)
          .attr("markerWidth", 6)
          .attr("markerHeight", 6)
          .attr("orient", "auto-start-reverse")
          .append("path")
          .attr("d", "M 0 0 L 10 5 L 0 10 z")
          .attr("fill", fill);
      });

      bandValues.forEach((bandValue, index) => {
        const y = margin.top + index * bandGap;
        bandLayer.append("line").attr("class", "band-line").attr("x1", margin.left).attr("x2", width - margin.right).attr("y1", y).attr("y2", y);
        bandLayer.append("text").attr("class", "band-label").attr("x", margin.left).attr("y", y - 12).text(bandLabels.get(bandValue) || String(bandValue));
      });

      function curve(edge) {
        const midX = (edge.source.x + edge.target.x) / 2;
        const midY = (edge.source.y + edge.target.y) / 2;
        const lift = edge.source.y === edge.target.y ? -36 : 0;
        return `M${edge.source.x},${edge.source.y} Q${midX},${midY + lift} ${edge.target.x},${edge.target.y}`;
      }

      function reportCurve(report) {
        const source = routerById.get(report.from);
        const target = routerById.get(report.to);
        if (!source || !target) return "";
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const distance = Math.max(1, Math.hypot(dx, dy));
        const trim = 28;
        const startX = source.x + (dx / distance) * trim;
        const startY = source.y + (dy / distance) * trim;
        const endX = target.x - (dx / distance) * trim;
        const endY = target.y - (dy / distance) * trim;
        const midX = (startX + endX) / 2;
        const midY = (startY + endY) / 2;
        const lift = Math.abs(source.y - target.y) < 1 ? -36 : 0;
        return `M${startX},${startY} Q${midX},${midY + lift} ${endX},${endY}`;
      }

      function markerFor(report) {
        const severity = reportSeverity(report);
        if (severity >= 3) return "url(#arrow-weak)";
        if (severity >= 1) return "url(#arrow-watch)";
        return "url(#arrow-ok)";
      }

      function showDirections(reports) {
        directionLayer.selectAll("path").data(reports, (report) => `${report.from}-${report.to}`).join("path")
          .attr("class", "direction-edge")
          .attr("stroke", (report) => severityColor(reportSeverity(report)))
          .attr("stroke-width", (report) => Math.max(2.2, Math.min(5.5, 2 + (report.linkMargin || 0) / 16)))
          .attr("marker-end", markerFor)
          .attr("d", reportCurve);
      }

      function clearDirections() {
        directionLayer.selectAll("*").remove();
      }

      const mesh = meshLayer.selectAll("path").data(meshLinks).join("path")
        .attr("class", "mesh-edge")
        .attr("stroke", (edge) => severityColor(edge.severity))
        .attr("stroke-width", (edge) => Math.max(1.5, Math.min(5, 1.5 + (edge.bestMargin || 0) / 18)))
        .attr("opacity", (edge) => edge.severity >= 3 ? 0.5 : 0.62)
        .attr("d", curve)
        .on("click", (event, edge) => {
          event.stopPropagation();
          selectMesh(edge);
        });

      const childLinks = childLayer.selectAll("line").data(childNodes).join("line")
        .attr("class", "child-edge")
        .attr("stroke", (child) => severityColor(reportSeverity(child)))
        .attr("stroke-width", 1.8)
        .attr("opacity", 0.74)
        .attr("x1", (child) => child.parent.x)
        .attr("y1", (child) => child.parent.y + 23)
        .attr("x2", (child) => child.x)
        .attr("y2", (child) => child.y - 14)
        .on("click", (event, child) => {
          event.stopPropagation();
          selectChild(child);
        });

      const routerNode = nodeLayer.selectAll("g.router-node").data(routers).join("g")
        .attr("class", "router-node")
        .attr("transform", (router) => `translate(${router.x},${router.y})`)
        .on("click", (event, router) => {
          event.stopPropagation();
          selectRouter(router);
        });
      routerNode.append("circle").attr("r", (router) => router.id === leader.id ? 25 : 22).attr("fill", (router) => router.id === leader.id ? "var(--leader)" : "var(--router)").attr("opacity", 0.9);
      routerNode.append("text").attr("class", "main").attr("text-anchor", "middle").attr("dy", "-0.1em").text((router) => router.id);
      routerNode.append("text").attr("class", "sub").attr("text-anchor", "middle").attr("dy", "1.2em").text((router) => router.children.length ? `+${router.children.length}` : "");
      routerNode.append("text").attr("class", "name-label").attr("text-anchor", "middle").attr("dy", "3.25em").text((router) => compactName(router.name));
      const brBadge = routerNode.filter((router) => router.borderRouter).append("g").attr("class", "br-badge").attr("transform", "translate(14,-28)");
      brBadge.append("rect").attr("x", -8).attr("y", -6).attr("width", 21).attr("height", 13).attr("rx", 4);
      brBadge.append("text").attr("text-anchor", "middle").attr("x", 2.5).attr("y", 4).text("BR");

      const childNode = nodeLayer.selectAll("g.child-node").data(childNodes).join("g")
        .attr("class", "child-node")
        .attr("transform", (child) => `translate(${child.x},${child.y})`)
        .on("click", (event, child) => {
          event.stopPropagation();
          selectChild(child);
        });
      childNode.append("circle").attr("r", 15).attr("fill", "var(--child)").attr("opacity", 0.86);
      childNode.append("text").attr("class", "main").attr("text-anchor", "middle").attr("dy", "0.35em").text((child) => child.childId);
      childNode.append("text").attr("class", "name-label").attr("text-anchor", "middle").attr("dy", "2.85em").text((child) => compactName(child.name));

      function reset() {
        routerNode.classed("dim", false);
        childNode.classed("dim", false);
        mesh.classed("dim", false);
        childLinks.classed("dim", false);
        clearDirections();
        detail.textContent = "Select a router, child, or link.";
      }
      function selectRouter(router) {
        const related = new Set([router.id]);
        meshLinks.forEach((edge) => {
          if (edge.source.id === router.id || edge.target.id === router.id) {
            related.add(edge.source.id);
            related.add(edge.target.id);
          }
        });
        routerNode.classed("dim", (item) => !related.has(item.id));
        childNode.classed("dim", (item) => item.parent.id !== router.id);
        mesh.classed("dim", (edge) => edge.source.id !== router.id && edge.target.id !== router.id);
        childLinks.classed("dim", (child) => child.parent.id !== router.id);
        const extras = router.info ? [router.info.location, router.info.notes].filter(Boolean).join(" · ") : "";
        const reports = [];
        for (const edge of meshLinks) {
          for (const report of edge.reports) {
            if (report.from === router.id) {
              reports.push({ ...report, severity: reportSeverity(report), targetName: deviceName(routerById.get(report.to)?.extAddress, `Router ${report.to}`) });
            }
          }
        }
        reports.sort((a, b) => reportSeverity(b) - reportSeverity(a) || (a.linkMargin ?? 999) - (b.linkMargin ?? 999) || a.to - b.to);
        showDirections(reports);
        const rows = reports.map((report) => `
          <tr>
            <td>${esc(severityLabel(report.severity))}</td>
            <td>r${esc(report.to)}</td>
            <td>${esc(report.targetName)}</td>
            <td class="num">${esc(fmt(report.linkQuality))}</td>
            <td class="num">${esc(fmt(report.linkMargin, "dB"))}</td>
            <td class="num">${esc(fmt(report.averageRssi, "dBm"))}</td>
            <td class="num">${esc(fmt(report.lastRssi, "dBm"))}</td>
            <td class="num">${esc(fmt(report.frameErrorRate))}</td>
            <td class="num">${esc(fmt(report.messageErrorRate))}</td>
          </tr>
        `).join("");
        const table = rows ? `<table class="signal-table"><thead><tr><th>Status</th><th>To</th><th>Name</th><th class="num">LQ</th><th class="num">Margin</th><th class="num">Avg RSSI</th><th class="num">Last RSSI</th><th class="num">FER</th><th class="num">MER</th></tr></thead><tbody>${rows}</tbody></table>` : "";
        detail.innerHTML = `<b>${esc(router.name)}</b> Router ${esc(router.id)} · ${esc(routerRole(router))} · signal ${esc(routerSignalLabel(router))} · reliable neighbors ${esc(router.reliableNeighborCount)} · leader route cost ${esc(fmt(router.leaderRouteCost))} · weak edge ratio ${esc(Math.round(router.weakEdgeRatio * 100))}% · ext ${esc(router.extAddress || "-")} · rloc16 ${esc(router.rloc16)} · children ${router.children.length}/${router.childCount} · child table ${esc(router.childTableStatus)} · neighbor table ${esc(router.routerNeighborTableStatus)} · LQ1 ${router.counts.lq1 ?? 0}, LQ2 ${router.counts.lq2 ?? 0}, LQ3 ${router.counts.lq3 ?? 0}, LQ missing ${router.counts.missing ?? 0}${extras ? " · " + esc(extras) : ""}${table}`;
      }
      function selectChild(child) {
        routerNode.classed("dim", (router) => router.id !== child.parent.id);
        childNode.classed("dim", (item) => item.id !== child.id);
        mesh.classed("dim", true);
        childLinks.classed("dim", (item) => item.id !== child.id);
        clearDirections();
        const extras = child.info ? [child.info.location, child.info.notes].filter(Boolean).join(" · ") : "";
        detail.innerHTML = `<b>${esc(child.name)}</b> Child ${esc(child.childId)} · ext ${esc(child.extAddress || "-")} · rloc16 ${esc(child.rloc16)} · parent ${esc(child.parent.name)} · status ${esc(severityLabel(reportSeverity(child)))} · LQ ${esc(fmt(child.linkQuality))} · margin ${esc(fmt(child.linkMargin, "dB"))} · RSSI ${esc(fmt(child.averageRssi))}/${esc(fmt(child.lastRssi, "dBm"))} · queued ${esc(fmt(child.queuedMessages))} · timeout ${esc(child.timeout)}${extras ? " · " + esc(extras) : ""}`;
      }
      function selectMesh(edge) {
        routerNode.classed("dim", (router) => router.id !== edge.source.id && router.id !== edge.target.id);
        childNode.classed("dim", true);
        mesh.classed("dim", (item) => item !== edge);
        childLinks.classed("dim", true);
        showDirections(edge.reports);
        const rows = edge.reports
          .slice()
          .sort((a, b) => a.from - b.from)
          .map((report) => `
            <tr>
              <td>r${esc(report.from)} → r${esc(report.to)}</td>
              <td>${esc(deviceName(routerById.get(report.from)?.extAddress, `Router ${report.from}`))}</td>
              <td>${esc(deviceName(routerById.get(report.to)?.extAddress, `Router ${report.to}`))}</td>
              <td>${esc(severityLabel(reportSeverity(report)))}</td>
              <td class="num">${esc(fmt(report.linkQuality))}</td>
              <td class="num">${esc(fmt(report.linkMargin, "dB"))}</td>
              <td class="num">${esc(fmt(report.averageRssi, "dBm"))}</td>
              <td class="num">${esc(fmt(report.lastRssi, "dBm"))}</td>
              <td class="num">${esc(fmt(report.frameErrorRate))}</td>
              <td class="num">${esc(fmt(report.messageErrorRate))}</td>
            </tr>
          `).join("");
        detail.innerHTML = `<b>Router ${esc(edge.source.id)} ↔ ${esc(edge.target.id)}</b> two-way LQ ${esc(fmt(edge.twoWayLq))}, route cost ${esc(fmt(edge.routeCost))}, best margin ${esc(fmt(edge.bestMargin, "dB"))}, best LQ ${esc(fmt(edge.bestLq))}<table class="signal-table"><thead><tr><th>Direction</th><th>From</th><th>To</th><th>Status</th><th class="num">LQ</th><th class="num">Margin</th><th class="num">Avg RSSI</th><th class="num">Last RSSI</th><th class="num">FER</th><th class="num">MER</th></tr></thead><tbody>${rows}</tbody></table>`;
      }
      svg.on("click", reset);
    }

    load();
    setInterval(load, 30000);
  </script>
</body>
</html>"""


class ExporterHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/metrics":
            body = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/topology.json":
            with payload_lock:
                body = json.dumps({
                    "payload": latest_payload,
                    "error": latest_error,
                    "last_success": last_success._value.get(),
                    "expected_child_count": EXPECTED_CHILD_COUNT,
                    "device_map": load_device_map(),
                }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path in {"/", "/topology"}:
            body = topology_page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(format, *args)


def main() -> None:
    logger.info("starting exporter on :%s for %s", EXPORTER_PORT, WROOM_BASE_URL)
    logger.info(
        "scan_on_collect=%s scan_interval_seconds=%s error_retry_interval_seconds=%s http_timeout_seconds=%s",
        SCAN_ON_COLLECT,
        SCAN_INTERVAL_SECONDS,
        ERROR_RETRY_INTERVAL_SECONDS,
        HTTP_TIMEOUT_SECONDS,
    )
    server = ThreadingHTTPServer(("", EXPORTER_PORT), ExporterHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        loop_started = time.monotonic()
        next_interval = SCAN_INTERVAL_SECONDS
        try:
            payload = run_scan()
            set_metrics(payload)
            logger.info(
                "scan_id=%s pending_total=%s routers=%s children=%s",
                payload.get("scan_id"),
                payload.get("pending_total", payload.get("pending")),
                len(payload.get("routers", [])),
                sum(len(router.get("children", []) or []) for router in payload.get("routers", [])),
            )
        except Exception as exc:
            global latest_error
            up.set(0)
            next_interval = ERROR_RETRY_INTERVAL_SECONDS
            with payload_lock:
                latest_error = f"{type(exc).__name__}: {exc}"
            logger.exception("failed to collect Thread topology")

        elapsed = time.monotonic() - loop_started
        sleep_for = max(1, next_interval - elapsed)
        logger.info("next collection in %.1f seconds", sleep_for)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
