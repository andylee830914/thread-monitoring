import logging
import os
import json
import re
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

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
DEVICE_CACHE_PATH = os.getenv("DEVICE_CACHE_PATH", "/data/device-cache.json")
EXPECTED_CHILD_COUNT = int(os.getenv("EXPECTED_CHILD_COUNT", "7"))
TOPOLOGY_TEMPLATE_PATH = Path(__file__).with_name("templates") / "topology.html"

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("thread-exporter")
latest_payload: dict[str, Any] = {}
latest_error = ""
payload_lock = threading.Lock()
child_ext_address_by_rloc16: dict[str, str] = {}
router_ext_address_by_rloc16: dict[str, str] = {}
device_detail_by_rloc16: dict[str, dict[str, Any]] = {}
device_cache_lock = threading.Lock()
device_cache_dirty = False

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

child_labels = ["child_key", "parent_router", "child_id", "child_rloc16", "child_ext_address"]
child_present = Gauge("thread_child_present", "Child device is present in latest scan", child_labels)
child_parent_router = Gauge("thread_child_parent_router", "Current parent router id for a child device", ["child_key", "child_id", "child_rloc16", "child_ext_address"])
child_parent_info = Gauge("thread_child_parent_info", "Current parent router labels for a child device", ["child_key", "child_id", "child_rloc16", "child_ext_address", "parent_router", "parent_rloc16", "parent_ext_address"])
child_link_quality = Gauge("thread_child_link_quality", "Child link quality reported by parent router", child_labels)
child_diagnostic_present = Gauge("thread_child_diagnostic_present", "1 when a child diagnostic field is present in the latest scan", [*child_labels, "field"])
child_timeout = Gauge("thread_child_timeout_seconds", "Child timeout in seconds", child_labels)
child_age = Gauge("thread_child_age_seconds", "Child age in seconds since last heard by parent router", child_labels)
child_connection_time = Gauge("thread_child_connection_time_seconds", "Child connection time in seconds", child_labels)
child_link_margin = Gauge("thread_child_link_margin_db", "Child link margin in dB", child_labels)
child_average_rssi = Gauge("thread_child_average_rssi_dbm", "Child average RSSI in dBm", child_labels)
child_last_rssi = Gauge("thread_child_last_rssi_dbm", "Child last RSSI in dBm", child_labels)
child_queued_messages = Gauge("thread_child_queued_messages", "Queued message count for sleepy child devices", child_labels)
child_error_rate_supported = Gauge("thread_child_error_rate_supported", "1 when child diagnostics include error rates", child_labels)
child_frame_error_rate = Gauge("thread_child_frame_error_rate", "Child frame error rate as reported by Thread diagnostics", child_labels)
child_message_error_rate = Gauge("thread_child_message_error_rate", "Child message error rate as reported by Thread diagnostics", child_labels)
child_mode = Gauge("thread_child_mode", "Child mode flags", [*child_labels, "flag"])
device_name = Gauge("thread_device_name", "Device display name from device map or generated fallback; value is update timestamp", ["device_key", "ext_address", "rloc16", "name", "location", "kind"])


def get_json(path: str) -> dict[str, Any]:
    response = requests.get(f"{WROOM_BASE_URL}{path}", timeout=HTTP_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def get_device_json(device_id: str) -> dict[str, Any]:
    return get_json(f"/device/{quote(device_id, safe='')}")


def get_ping_json(target: str) -> dict[str, Any]:
    ping_target = quote(target, safe=":")
    return get_json(f"/ping/{ping_target}")


def normalize_device_id(device_id: str) -> str:
    text = optional_text(device_id).lower()
    return text[2:] if text.startswith("0x") else text


def rloc16_api_id(device_id: str) -> str:
    key = normalize_device_id(device_id)
    if not key or not re.fullmatch(r"[0-9a-f]{1,4}", key):
        raise ValueError("invalid rloc16")
    return f"0x{key.zfill(4)}"


def ping_device_rloc(device_id: str) -> dict[str, Any]:
    device_rloc = rloc16_api_id(device_id)
    result = get_ping_json(device_rloc)
    return {"device_id": device_id, "target": device_rloc, "ping": result}


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


def display_entry(names: dict[str, dict[str, str]], ext_address: str, rloc16: str, fallback_name: str) -> dict[str, str]:
    entry = names.get(ext_address.lower()) or names.get(rloc16.lower())
    if entry:
        return entry
    return {"name": fallback_name, "location": "Unknown", "notes": ""}


def text_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def optional_text(value: Any) -> str:
    text = text_value(value)
    if text.lower() in {"none", "null", "undefined", "-"}:
        return ""
    return text


def normalize_cache(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized = {}
    for rloc16, ext_address in value.items():
        key = optional_text(rloc16).lower()
        address = optional_text(ext_address)
        if key and address:
            normalized[key] = address
    return normalized


def normalize_device_detail_cache(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    normalized = {}
    for device_id, entry in value.items():
        key = normalize_device_id(str(device_id))
        if not key or not isinstance(entry, dict) or not isinstance(entry.get("data"), dict):
            continue
        normalized[key] = {
            "data": entry["data"],
            "updated_at": int_value(entry.get("updated_at"), 0),
        }
    return normalized


def cache_device_detail(device_id: str, device: dict[str, Any]) -> dict[str, Any]:
    global device_cache_dirty
    key = normalize_device_id(device_id)
    if not key:
        raise ValueError("missing device id")
    entry = {"data": device, "updated_at": int(time.time())}
    with device_cache_lock:
        device_detail_by_rloc16[key] = entry
        device_cache_dirty = True
    return entry


def cached_device_detail(device_id: str) -> dict[str, Any]:
    key = normalize_device_id(device_id)
    with device_cache_lock:
        entry = device_detail_by_rloc16.get(key)
    if not entry:
        raise ValueError("device detail is not cached")
    return entry


def refresh_device_detail(device_id: str) -> dict[str, Any]:
    device = get_device_json(device_id)
    entry = cache_device_detail(device_id, device)
    save_device_cache_if_dirty()
    return entry


def load_device_cache() -> None:
    if not DEVICE_CACHE_PATH:
        return
    path = Path(DEVICE_CACHE_PATH)
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return
    except Exception:
        logger.exception("failed to read device cache: %s", DEVICE_CACHE_PATH)
        return

    if not isinstance(raw, dict):
        logger.warning("device cache root must be an object: %s", DEVICE_CACHE_PATH)
        return

    with device_cache_lock:
        child_ext_address_by_rloc16.update(normalize_cache(raw.get("children")))
        router_ext_address_by_rloc16.update(normalize_cache(raw.get("routers")))
        device_detail_by_rloc16.update(normalize_device_detail_cache(raw.get("devices")))


def save_device_cache_if_dirty() -> None:
    global device_cache_dirty
    if not DEVICE_CACHE_PATH:
        return
    with device_cache_lock:
        if not device_cache_dirty:
            return
        payload = {
            "children": dict(sorted(child_ext_address_by_rloc16.items())),
            "devices": dict(sorted(device_detail_by_rloc16.items())),
            "routers": dict(sorted(router_ext_address_by_rloc16.items())),
            "updated_at": int(time.time()),
        }
        device_cache_dirty = False

    path = Path(DEVICE_CACHE_PATH)
    tmp_path = path.with_name(f"{path.name}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        tmp_path.replace(path)
    except Exception:
        with device_cache_lock:
            device_cache_dirty = True
        logger.exception("failed to write device cache: %s", DEVICE_CACHE_PATH)


def stable_ext_address(cache: dict[str, str], rloc16: str, ext_address: str) -> str:
    global device_cache_dirty
    if ext_address:
        if rloc16:
            key = rloc16.lower()
            with device_cache_lock:
                if cache.get(key) != ext_address:
                    cache[key] = ext_address
                    device_cache_dirty = True
        return ext_address
    if rloc16:
        with device_cache_lock:
            return cache.get(rloc16.lower(), "")
    return ""


def parse_int(value: Any, base: int = 10) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, base)
    except ValueError:
        return None


def parse_rloc16(value: Any) -> int | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text.startswith("0x"):
        text = text[2:]
    try:
        return int(text, 16)
    except ValueError:
        return None


def derive_child_rloc16(parent_rloc16: str, parent_router_id: str, child_id: str) -> str:
    child_id_value = parse_int(child_id)
    if child_id_value is None or child_id_value < 0 or child_id_value > 0x3ff:
        return ""

    parent_rloc16_value = parse_rloc16(parent_rloc16)
    if parent_rloc16_value is not None:
        return f"{(parent_rloc16_value & 0xfc00) | child_id_value:04x}"

    parent_router_id_value = parse_int(parent_router_id)
    if parent_router_id_value is None or parent_router_id_value < 0 or parent_router_id_value > 0x3f:
        return ""
    return f"{(parent_router_id_value << 10) | child_id_value:04x}"


def stable_device_key(ext_address: str, rloc16: str) -> str:
    if ext_address:
        return f"ext:{ext_address.lower()}"
    if rloc16:
        return f"rloc16:{rloc16.lower()}"
    return "unknown"


def stable_child_key(ext_address: str, rloc16: str, parent_router: str, child_id: str) -> str:
    if ext_address:
        return f"ext:{ext_address.lower()}"
    if rloc16:
        return f"rloc16:{rloc16.lower()}"
    if parent_router or child_id:
        return f"parent:{parent_router}:child:{child_id}"
    return "unknown"


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
    router_by_id = {text_value(router.get("router_id")): router for router in routers}
    edge_by_key: dict[str, dict[str, Any]] = {}

    for router in routers:
        source_id = text_value(router.get("router_id"))
        for neighbor in router.get("router_neighbors", []) or []:
            target_id = text_value(neighbor.get("router_id"))
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
    leader_costs = shortest_paths(router_ids, adjacency, text_value(leader.get("router_id")) if leader else None)

    for router in routers:
        router_id = text_value(router.get("router_id"))
        rloc16 = optional_text(router.get("rloc16"))
        ext_address = optional_text(router.get("ext_address"))
        labels = (router_id, rloc16, ext_address)
        own_reports = [
            {
                "from": router_id,
                "to": text_value(neighbor.get("router_id")),
                "link_quality": numeric_value(neighbor.get("link_quality")),
                "link_margin": numeric_value(neighbor.get("link_margin")),
                "average_rssi": numeric_value(neighbor.get("average_rssi")),
            }
            for neighbor in router.get("router_neighbors", []) or []
        ]
        weak_reports = [report for report in own_reports if report_severity(report) >= 3]
        reliable_reports = []
        for report in own_reports:
            effective_lq = report["link_quality"] if report["link_quality"] is not None else link_quality_from_margin(report["link_margin"])
            route_cost = cost_for_link_quality(effective_lq)
            if route_cost is not None and route_cost <= 2 and (report["link_margin"] is None or report["link_margin"] >= 10):
                reliable_reports.append(report)
        reliable_count = len(reliable_reports)
        weak_ratio = len(weak_reports) / len(own_reports) if own_reports else 1
        leader_cost = leader_costs.get(router_id, float("inf"))
        neighbor_table_status = str(router.get("router_neighbor_table_status", "unknown"))
        has_own_route = any(
            cost_for_link_quality(
                report["link_quality"] if report["link_quality"] is not None else link_quality_from_margin(report["link_margin"])
            ) is not None
            for report in own_reports
        )
        data_incomplete = neighbor_table_status != "ok" and not has_own_route

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
        router_id = text_value(router.get("router_id"))
        rloc16 = optional_text(router.get("rloc16"))
        ext_address = stable_ext_address(router_ext_address_by_rloc16, rloc16, optional_text(router.get("ext_address")))
        status = str(router.get("status", "unknown"))
        if status == "ok":
            ok_total += 1

        children = router.get("children", []) or []
        child_total = int_value(router.get("child_count"), len(children))
        stored_child_total = int_value(router.get("stored_child_count"), child_total)
        children_total += len(children)
        stored_children_total += stored_child_total

        router_present.labels(router_id, rloc16, ext_address, status).set(1)
        entry = display_entry(names, ext_address, rloc16, f"Router {router_id}")
        device_name.labels(stable_device_key(ext_address, rloc16), ext_address, rloc16, entry["name"], entry["location"], "router").set(device_name_timestamp)
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
            target = text_value(neighbor.get("router_id"))
            target_rloc16 = optional_text(neighbor.get("rloc16"))
            target_ext_address = stable_ext_address(router_ext_address_by_rloc16, target_rloc16, optional_text(neighbor.get("ext_address")))
            target_entry = display_entry(names, target_ext_address, target_rloc16, f"Router {target}")
            device_name.labels(stable_device_key(target_ext_address, target_rloc16), target_ext_address, target_rloc16, target_entry["name"], target_entry["location"], "router").set(device_name_timestamp)
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
            child_id = text_value(child.get("child_id"))
            child_rloc16 = optional_text(child.get("rloc16")) or derive_child_rloc16(rloc16, router_id, child_id)
            child_ext_address = stable_ext_address(child_ext_address_by_rloc16, child_rloc16, optional_text(child.get("ext_address")))
            child_key = stable_child_key(child_ext_address, child_rloc16, router_id, child_id)
            name_entry = display_entry(names, child_ext_address, child_rloc16, f"Child {child_id}")
            child_present.labels(child_key, router_id, child_id, child_rloc16, child_ext_address).set(1)
            set_optional_metric(child_parent_router, router_id, child_key, child_id, child_rloc16, child_ext_address)
            child_parent_info.labels(child_key, child_id, child_rloc16, child_ext_address, router_id, rloc16, ext_address).set(1)
            device_name.labels(child_key, child_ext_address, child_rloc16, name_entry["name"], name_entry["location"], "child").set(device_name_timestamp)
            child_metric_labels = (child_key, router_id, child_id, child_rloc16, child_ext_address)
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
                child_diagnostic_present.labels(*child_metric_labels, field).set(1 if field in child and child.get(field) is not None else 0)
            set_optional_metric(child_link_quality, child.get("link_quality"), *child_metric_labels)
            set_optional_metric(child_timeout, child.get("timeout"), *child_metric_labels)
            set_optional_metric(child_age, child.get("age"), *child_metric_labels)
            set_optional_metric(child_connection_time, child.get("connection_time"), *child_metric_labels)
            set_optional_metric(child_link_margin, child.get("link_margin"), *child_metric_labels)
            set_optional_metric(child_average_rssi, child.get("average_rssi"), *child_metric_labels)
            set_optional_metric(child_last_rssi, child.get("last_rssi"), *child_metric_labels)
            set_optional_metric(child_queued_messages, child.get("queued_message_count"), *child_metric_labels)
            if "supports_error_rate" in child and child.get("supports_error_rate") is not None:
                child_error_rate_supported.labels(*child_metric_labels).set(1 if child.get("supports_error_rate") else 0)
            set_optional_metric(child_frame_error_rate, child.get("frame_error_rate"), *child_metric_labels)
            set_optional_metric(child_message_error_rate, child.get("message_error_rate"), *child_metric_labels)
            mode = child.get("mode", {}) or {}
            child_mode.labels(*child_metric_labels, "rx_on_when_idle").set(1 if mode.get("rx_on_when_idle") else 0)
            child_mode.labels(*child_metric_labels, "full_thread_device").set(1 if mode.get("full_thread_device") else 0)
            child_mode.labels(*child_metric_labels, "full_network_data").set(1 if mode.get("full_network_data") else 0)

    set_topology_graph_metrics(routers)
    router_ok_count.set(ok_total)
    child_count.set(children_total)
    child_missing_count.set(max(0, EXPECTED_CHILD_COUNT - children_total))
    stored_child_count.set(stored_children_total)
    up.set(1)
    last_success.set(time.time())
    save_device_cache_if_dirty()
    with payload_lock:
        latest_payload.clear()
        latest_payload.update(payload)
        latest_error = ""


def topology_page() -> str:
    return TOPOLOGY_TEMPLATE_PATH.read_text(encoding="utf-8")


class ExporterHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed_path = urlparse(self.path).path

        if parsed_path == "/metrics":
            body = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed_path == "/topology.json":
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

        if parsed_path.startswith("/device/") and parsed_path.endswith("/ping"):
            device_id = unquote(parsed_path.removeprefix("/device/").removesuffix("/ping")).strip("/")
            if not device_id:
                body = json.dumps({"error": "missing device id"}).encode("utf-8")
                self.send_response(400)
            else:
                try:
                    body = json.dumps(ping_device_rloc(device_id)).encode("utf-8")
                    self.send_response(200)
                except ValueError as exc:
                    body = json.dumps({"error": str(exc)}).encode("utf-8")
                    self.send_response(400)
                except Exception as exc:
                    logger.exception("failed to ping device rloc: %s", device_id)
                    body = json.dumps({"error": f"{type(exc).__name__}: {exc}"}).encode("utf-8")
                    self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed_path.startswith("/device/") and parsed_path.endswith("/refresh"):
            device_id = unquote(parsed_path.removeprefix("/device/").removesuffix("/refresh")).strip("/")
            if not device_id:
                body = json.dumps({"error": "missing device id"}).encode("utf-8")
                self.send_response(400)
            else:
                try:
                    entry = refresh_device_detail(device_id)
                    body = json.dumps({
                        "device_id": device_id,
                        "cached": False,
                        "updated_at": entry["updated_at"],
                        "device": entry["data"],
                    }).encode("utf-8")
                    self.send_response(200)
                except Exception as exc:
                    logger.exception("failed to refresh device detail: %s", device_id)
                    body = json.dumps({"error": f"{type(exc).__name__}: {exc}"}).encode("utf-8")
                    self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed_path.startswith("/device/"):
            device_id = unquote(parsed_path.removeprefix("/device/")).strip()
            if not device_id:
                body = json.dumps({"error": "missing device id"}).encode("utf-8")
                self.send_response(400)
            else:
                try:
                    entry = cached_device_detail(device_id)
                    body = json.dumps({
                        "device_id": device_id,
                        "cached": True,
                        "updated_at": entry["updated_at"],
                        "device": entry["data"],
                    }).encode("utf-8")
                    self.send_response(200)
                except ValueError as exc:
                    body = json.dumps({"error": str(exc)}).encode("utf-8")
                    self.send_response(404)
                except Exception as exc:
                    logger.exception("failed to fetch cached device detail: %s", device_id)
                    body = json.dumps({"error": f"{type(exc).__name__}: {exc}"}).encode("utf-8")
                    self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed_path in {"/", "/topology"}:
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
    load_device_cache()
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
