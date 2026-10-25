"""
Pipeline Stage 1 & 2: Log Parsing, Cleaning, and Normalization
Validates timestamps, IP addresses, event types, and required fields across CSV and JSON inputs.
"""

import json
import csv
import io
import re
from datetime import datetime, timezone
import ipaddress
from typing import List, Dict, Any, Tuple, Optional


STANDARD_EVENT_TYPES = {
    # Auth Failures
    "auth_failure": "AUTH_FAILURE",
    "login_failure": "AUTH_FAILURE",
    "failed_login": "AUTH_FAILURE",
    "ssh_failure": "AUTH_FAILURE",
    "bad_password": "AUTH_FAILURE",
    "401": "AUTH_FAILURE",
    "authentication_failed": "AUTH_FAILURE",

    # Auth Success
    "auth_success": "AUTH_SUCCESS",
    "login_success": "AUTH_SUCCESS",
    "successful_login": "AUTH_SUCCESS",
    "ssh_login": "AUTH_SUCCESS",

    # Port Scanning / Recon
    "port_scan": "PORT_SCAN",
    "syn_scan": "PORT_SCAN",
    "reconnaissance": "PORT_SCAN",
    "network_sweep": "PORT_SCAN",

    # Firewall Dropped
    "firewall_block": "FIREWALL_BLOCK",
    "firewall_drop": "FIREWALL_BLOCK",
    "packet_drop": "FIREWALL_BLOCK",
    "connection_refused": "FIREWALL_BLOCK",

    # Privilege Escalation
    "privilege_escalation": "PRIVILEGE_ESCALATION",
    "sudo_failure": "PRIVILEGE_ESCALATION",
    "sudo_abuse": "PRIVILEGE_ESCALATION",
    "unauthorized_admin": "PRIVILEGE_ESCALATION",

    # Data Exfiltration
    "data_exfiltration": "DATA_EXFILTRATION",
    "high_volume_outbound": "DATA_EXFILTRATION",
    "large_transfer": "DATA_EXFILTRATION",

    # C2 / Beaconing
    "c2_beacon": "C2_BEACON",
    "c2_traffic": "C2_BEACON",
    "botnet_heartbeat": "C2_BEACON",
    "malicious_callback": "C2_BEACON",

    # Web Attacks
    "web_attack": "WEB_ATTACK",
    "sqli": "WEB_ATTACK",
    "xss": "WEB_ATTACK",
    "path_traversal": "WEB_ATTACK",
    "rce_attempt": "WEB_ATTACK"
}


class LogParser:
    """Parses and normalizes security logs from CSV or JSON files."""

    def __init__(self):
        self.supported_formats = ["csv", "json"]

    def parse_content(self, content_str: str, file_type: str = "auto") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Parses raw string content (CSV or JSON)."""
        content_str = content_str.strip()
        if not content_str:
            return [], {"total": 0, "valid": 0, "dropped": 0, "reasons": {"empty_file": 1}}

        # Detect format if auto
        if file_type == "auto":
            if content_str.startswith("{") or content_str.startswith("["):
                file_type = "json"
            else:
                file_type = "csv"

        if file_type == "json":
            return self._parse_json(content_str)
        else:
            return self._parse_csv(content_str)

    def _parse_json(self, raw_json: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        raw_items = []
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, list):
                raw_items = parsed
            elif isinstance(parsed, dict):
                # In case logs are wrapped in an object like {"logs": [...]}
                for key in ["logs", "events", "data", "records"]:
                    if key in parsed and isinstance(parsed[key], list):
                        raw_items = parsed[key]
                        break
                if not raw_items:
                    raw_items = [parsed]
        except json.JSONDecodeError:
            # Try newline-delimited JSON
            for line in raw_json.splitlines():
                line = line.strip()
                if line:
                    try:
                        raw_items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return self._clean_records(raw_items)

    def _parse_csv(self, raw_csv: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        raw_items = []
        try:
            reader = csv.DictReader(io.StringIO(raw_csv))
            for row in reader:
                raw_items.append(dict(row))
        except Exception:
            return [], {"total": 0, "valid": 0, "dropped": 0, "reasons": {"csv_parse_error": 1}}

        return self._clean_records(raw_items)

    def _clean_records(self, raw_items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        cleaned_records = []
        stats = {
            "total_records": len(raw_items),
            "valid_records": 0,
            "dropped_records": 0,
            "reasons": {},
            "event_breakdown": {},
            "earliest_timestamp": None,
            "latest_timestamp": None,
            "unique_src_ips": 0,
            "unique_dest_ips": 0
        }

        unique_src = set()
        unique_dest = set()

        for idx, row in enumerate(raw_items, start=1):
            normalized_row, drop_reason = self._normalize_single_record(row, idx)
            if drop_reason:
                stats["dropped_records"] += 1
                stats["reasons"][drop_reason] = stats["reasons"].get(drop_reason, 0) + 1
                continue

            cleaned_records.append(normalized_row)
            unique_src.add(normalized_row["src_ip"])
            unique_dest.add(normalized_row["dest_ip"])

            evt = normalized_row["event_type"]
            stats["event_breakdown"][evt] = stats["event_breakdown"].get(evt, 0) + 1

            # Track earliest/latest timestamp
            t_iso = normalized_row["timestamp"]
            if stats["earliest_timestamp"] is None or t_iso < stats["earliest_timestamp"]:
                stats["earliest_timestamp"] = t_iso
            if stats["latest_timestamp"] is None or t_iso > stats["latest_timestamp"]:
                stats["latest_timestamp"] = t_iso

        stats["valid_records"] = len(cleaned_records)
        stats["unique_src_ips"] = len(unique_src)
        stats["unique_dest_ips"] = len(unique_dest)

        # Sort chronologically
        cleaned_records.sort(key=lambda x: x["timestamp"])

        return cleaned_records, stats

    def _normalize_single_record(self, row: Dict[str, Any], record_idx: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        # Case insensitive mapping
        lowered = {k.lower().strip(): v for k, v in row.items() if k is not None}

        # 1. Source IP
        src_ip_val = lowered.get("src_ip") or lowered.get("source_ip") or lowered.get("client_ip") or lowered.get("ip") or lowered.get("src")
        if not src_ip_val:
            return None, "missing_source_ip"
        
        src_ip_clean = str(src_ip_val).strip()
        is_valid_src, src_ip_obj, src_type = self._validate_ip(src_ip_clean)
        if not is_valid_src:
            return None, f"invalid_source_ip: {src_ip_clean}"

        # 2. Destination IP
        dest_ip_val = lowered.get("dest_ip") or lowered.get("destination_ip") or lowered.get("server_ip") or lowered.get("target_ip") or lowered.get("dst") or "10.0.0.1"
        dest_ip_clean = str(dest_ip_val).strip()
        is_valid_dst, dest_ip_obj, dst_type = self._validate_ip(dest_ip_clean)
        if not is_valid_dst:
            dest_ip_clean = "10.0.0.1"
            is_valid_dst, dest_ip_obj, dst_type = self._validate_ip(dest_ip_clean)

        # 3. Timestamp Validation
        ts_val = lowered.get("timestamp") or lowered.get("time") or lowered.get("date") or lowered.get("@timestamp") or lowered.get("event_time")
        parsed_ts = self._parse_timestamp(ts_val)
        if not parsed_ts:
            return None, "invalid_timestamp"

        # 4. Event Type Normalization
        raw_evt = lowered.get("event_type") or lowered.get("action") or lowered.get("event") or lowered.get("category") or lowered.get("type") or "network_connection"
        norm_evt = self._normalize_event_type(str(raw_evt))

        # 5. Extract Ports and Protocols
        try:
            src_port = int(lowered.get("src_port") or lowered.get("source_port") or 0)
        except (ValueError, TypeError):
            src_port = 0

        try:
            dest_port = int(lowered.get("dest_port") or lowered.get("destination_port") or lowered.get("port") or 80)
        except (ValueError, TypeError):
            dest_port = 80

        protocol = str(lowered.get("protocol") or lowered.get("proto") or "TCP").upper()

        # 6. User / Identity
        user = str(lowered.get("user") or lowered.get("username") or lowered.get("account") or lowered.get("src_user") or "anonymous").strip()

        # 7. Status / Response Code
        status = str(lowered.get("status") or lowered.get("result") or lowered.get("status_code") or "SUCCESS").upper()
        if norm_evt == "AUTH_FAILURE":
            status = "FAILURE"

        # 8. Bytes sent / received
        try:
            bytes_sent = int(lowered.get("bytes_sent") or lowered.get("bytes_out") or lowered.get("bytes") or 0)
        except (ValueError, TypeError):
            bytes_sent = 0

        try:
            bytes_recv = int(lowered.get("bytes_received") or lowered.get("bytes_in") or 0)
        except (ValueError, TypeError):
            bytes_recv = 0

        # 9. Additional context
        message = str(lowered.get("message") or lowered.get("details") or lowered.get("payload") or f"{norm_evt} from {src_ip_clean}").strip()
        user_agent = str(lowered.get("user_agent") or lowered.get("agent") or "").strip()

        record = {
            "log_id": f"LOG-{record_idx:06d}",
            "timestamp": parsed_ts.isoformat(),
            "timestamp_epoch": int(parsed_ts.timestamp()),
            "src_ip": src_ip_clean,
            "src_ip_is_private": src_type == "private",
            "src_ip_is_global": src_type == "global",
            "dest_ip": dest_ip_clean,
            "dest_ip_is_private": dst_type == "private",
            "src_port": src_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "user": user,
            "event_type": norm_evt,
            "raw_event_type": str(raw_evt),
            "status": status,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "message": message,
            "user_agent": user_agent
        }

        return record, None

    def _validate_ip(self, ip_str: str) -> Tuple[bool, Optional[Any], str]:
        """Validates IPv4 or IPv6 address and returns type."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                return True, ip_obj, "private"
            elif ip_obj.is_loopback:
                return True, ip_obj, "loopback"
            elif ip_obj.is_global:
                return True, ip_obj, "global"
            else:
                return True, ip_obj, "other"
        except ValueError:
            return False, None, "invalid"

    def _parse_timestamp(self, ts_val: Any) -> Optional[datetime]:
        """Flexible timestamp parser supporting ISO, epoch, and standard formats."""
        if ts_val is None:
            return datetime.now(timezone.utc)

        # Numeric epoch
        if isinstance(ts_val, (int, float)):
            try:
                # If milliseconds
                if ts_val > 1e11:
                    ts_val = ts_val / 1000.0
                return datetime.fromtimestamp(ts_val, tz=timezone.utc)
            except Exception:
                return None

        ts_str = str(ts_val).strip()
        if not ts_str:
            return datetime.now(timezone.utc)

        # Try numeric string
        if ts_str.isdigit():
            val = float(ts_str)
            if val > 1e11:
                val = val / 1000.0
            return datetime.fromtimestamp(val, tz=timezone.utc)

        # ISO 8601 variations
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
            "%b %d %H:%M:%S", # Syslog format
            "%d/%b/%Y:%H:%M:%S %z" # Web server log format
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        # If syslog without year, attach current year
        try:
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            now = datetime.now(timezone.utc)
            return dt.replace(year=now.year, tzinfo=timezone.utc)
        except ValueError:
            pass

        return None

    def _normalize_event_type(self, raw_evt: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", raw_evt.lower().strip())
        for pattern, std_type in STANDARD_EVENT_TYPES.items():
            if pattern in cleaned:
                return std_type
        return cleaned.upper()
