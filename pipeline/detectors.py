"""
Pipeline Stage 4: Detection Engine & Suspicious Pattern Analytics
Identifies brute force, credential stuffing, port scans, data exfiltration,
off-hours privileged access, web exploits, and C2 beaconing with MITRE ATT&CK mapping.
"""

from collections import defaultdict
from datetime import datetime
import re
from typing import List, Dict, Any


class DetectionEngine:
    """Analyzes normalized logs to flag suspicious cyber activity."""

    def __init__(self):
        pass

    def run_detections(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Runs all detection rules across the parsed logs and returns alerts."""
        if not logs:
            return []

        alerts = []
        alert_counter = 1

        # 1. Group logs by source IP and by destination IP
        by_src_ip = defaultdict(list)
        by_user = defaultdict(list)
        by_pair = defaultdict(list)

        for log in logs:
            by_src_ip[log["src_ip"]].append(log)
            if log["user"] and log["user"] != "anonymous":
                by_user[log["user"]].append(log)
            by_pair[(log["src_ip"], log["dest_ip"])].append(log)

        # Rule 1 & 2: Brute Force & Credential Stuffing
        for src_ip, ip_logs in by_src_ip.items():
            fail_logs = [l for l in ip_logs if l["event_type"] == "AUTH_FAILURE" or l["status"] == "FAILURE"]
            if len(fail_logs) >= 3:
                targeted_users = list(set(l["user"] for l in fail_logs if l["user"] != "anonymous"))
                
                # If multiple distinct users -> Credential Stuffing / Password Spraying
                if len(targeted_users) >= 3:
                    alerts.append({
                        "alert_id": f"ALT-{alert_counter:04d}",
                        "title": f"Distributed Credential Stuffing / Password Spray",
                        "rule_id": "RULE_CRED_STUFFING",
                        "severity": "CRITICAL" if len(fail_logs) >= 10 else "HIGH",
                        "mitre_attack": {
                            "tactic": "Credential Access",
                            "tactic_id": "TA0006",
                            "technique_id": "T1110.004",
                            "technique_name": "Brute Force: Password Spraying"
                        },
                        "source_ip": src_ip,
                        "dest_ip": fail_logs[0]["dest_ip"],
                        "target_user": f"{len(targeted_users)} accounts ({', '.join(targeted_users[:4])}...)",
                        "description": f"Source IP {src_ip} attempted {len(fail_logs)} failed logins across {len(targeted_users)} distinct user accounts.",
                        "evidence_count": len(fail_logs),
                        "log_ids": [l["log_id"] for l in fail_logs],
                        "indicators": {
                            "failed_attempts": len(fail_logs),
                            "targeted_accounts": targeted_users,
                            "attack_duration_seconds": max(1, fail_logs[-1]["timestamp_epoch"] - fail_logs[0]["timestamp_epoch"])
                        },
                        "first_seen": fail_logs[0]["timestamp"],
                        "last_seen": fail_logs[-1]["timestamp"],
                        "confidence": 95
                    })
                    alert_counter += 1
                elif len(fail_logs) >= 5:
                    # Single/few user brute force
                    primary_user = targeted_users[0] if targeted_users else "root/admin"
                    alerts.append({
                        "alert_id": f"ALT-{alert_counter:04d}",
                        "title": f"Authentication Brute-Force Attack",
                        "rule_id": "RULE_AUTH_BRUTE_FORCE",
                        "severity": "HIGH",
                        "mitre_attack": {
                            "tactic": "Credential Access",
                            "tactic_id": "TA0006",
                            "technique_id": "T1110.001",
                            "technique_name": "Brute Force: Password Guessing"
                        },
                        "source_ip": src_ip,
                        "dest_ip": fail_logs[0]["dest_ip"],
                        "target_user": primary_user,
                        "description": f"Detected {len(fail_logs)} repeated authentication failures targeting account '{primary_user}' from {src_ip}.",
                        "evidence_count": len(fail_logs),
                        "log_ids": [l["log_id"] for l in fail_logs],
                        "indicators": {
                            "failed_attempts": len(fail_logs),
                            "target_account": primary_user,
                            "attack_duration_seconds": max(1, fail_logs[-1]["timestamp_epoch"] - fail_logs[0]["timestamp_epoch"])
                        },
                        "first_seen": fail_logs[0]["timestamp"],
                        "last_seen": fail_logs[-1]["timestamp"],
                        "confidence": 90
                    })
                    alert_counter += 1

        # Rule 3: Port Scanning & Reconnaissance
        for src_ip, ip_logs in by_src_ip.items():
            scanned_ports = set()
            scan_logs = []
            for l in ip_logs:
                if l["event_type"] in ["PORT_SCAN", "FIREWALL_BLOCK"] or (l["status"] in ["BLOCKED", "DENIED", "DROPPED"]):
                    scanned_ports.add(l["dest_port"])
                    scan_logs.append(l)
                elif len(ip_logs) > 6 and l["dest_port"] in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080]:
                    scanned_ports.add(l["dest_port"])
                    scan_logs.append(l)

            if len(scanned_ports) >= 4 or (len(scan_logs) >= 6 and len(scanned_ports) >= 2):
                sensitive_targets = [p for p in scanned_ports if p in [22, 3389, 445, 1433, 3306, 8080]]
                alerts.append({
                    "alert_id": f"ALT-{alert_counter:04d}",
                    "title": f"Network Port Scanning & Reconnaissance",
                    "rule_id": "RULE_PORT_SCAN",
                    "severity": "HIGH" if len(sensitive_targets) >= 2 else "MEDIUM",
                    "mitre_attack": {
                        "tactic": "Discovery",
                        "tactic_id": "TA0007",
                        "technique_id": "T1046",
                        "technique_name": "Network Service Discovery"
                    },
                    "source_ip": src_ip,
                    "dest_ip": scan_logs[0]["dest_ip"] if scan_logs else "Various",
                    "target_user": "N/A (Network Service)",
                    "description": f"Source {src_ip} probed {len(scanned_ports)} distinct ports ({', '.join(str(p) for p in sorted(list(scanned_ports))[:6])}).",
                    "evidence_count": len(scan_logs),
                    "log_ids": [l["log_id"] for l in scan_logs],
                    "indicators": {
                        "distinct_ports_scanned": len(scanned_ports),
                        "ports": sorted(list(scanned_ports)),
                        "sensitive_ports_hit": sensitive_targets
                    },
                    "first_seen": scan_logs[0]["timestamp"],
                    "last_seen": scan_logs[-1]["timestamp"],
                    "confidence": 88
                })
                alert_counter += 1

        # Rule 4: Data Exfiltration / Anomaly Transfer
        for (src_ip, dest_ip), pair_logs in by_pair.items():
            total_bytes = sum(l.get("bytes_sent", 0) for l in pair_logs)
            exfil_logs = [l for l in pair_logs if l.get("bytes_sent", 0) >= 3000000 or l["event_type"] == "DATA_EXFILTRATION"]
            
            if total_bytes >= 10000000 or len(exfil_logs) > 0:
                evid = exfil_logs if exfil_logs else pair_logs
                mb_transferred = round(total_bytes / (1024 * 1024), 2)
                alerts.append({
                    "alert_id": f"ALT-{alert_counter:04d}",
                    "title": f"Potential Data Exfiltration / High Egress Spike",
                    "rule_id": "RULE_DATA_EXFILTRATION",
                    "severity": "CRITICAL" if mb_transferred >= 25 else "HIGH",
                    "mitre_attack": {
                        "tactic": "Exfiltration",
                        "tactic_id": "TA0010",
                        "technique_id": "T1048",
                        "technique_name": "Exfiltration Over Alternative Protocol"
                    },
                    "source_ip": src_ip,
                    "dest_ip": dest_ip,
                    "target_user": evid[0].get("user", "System"),
                    "description": f"Abnormal outbound data transfer detected: {mb_transferred} MB transferred from {src_ip} to external host {dest_ip}.",
                    "evidence_count": len(evid),
                    "log_ids": [l["log_id"] for l in evid],
                    "indicators": {
                        "total_megabytes": mb_transferred,
                        "transfer_events": len(evid),
                        "destination_endpoint": dest_ip
                    },
                    "first_seen": evid[0]["timestamp"],
                    "last_seen": evid[-1]["timestamp"],
                    "confidence": 92
                })
                alert_counter += 1

        # Rule 5: C2 Beaconing / Periodic Callbacks
        for (src_ip, dest_ip), pair_logs in by_pair.items():
            c2_logs = [l for l in pair_logs if l["event_type"] == "C2_BEACON"]
            # Or if more than 5 logs between external and internal with regular heartbeat
            if len(c2_logs) >= 2 or (len(pair_logs) >= 8 and not pair_logs[0]["dest_ip_is_private"]):
                target_logs = c2_logs if c2_logs else pair_logs
                alerts.append({
                    "alert_id": f"ALT-{alert_counter:04d}",
                    "title": f"Command and Control (C2) Beaconing Pattern",
                    "rule_id": "RULE_C2_BEACONING",
                    "severity": "CRITICAL",
                    "mitre_attack": {
                        "tactic": "Command and Control",
                        "tactic_id": "TA0011",
                        "technique_id": "T1071.001",
                        "technique_name": "Application Layer Protocol: Web Protocols"
                    },
                    "source_ip": src_ip,
                    "dest_ip": dest_ip,
                    "target_user": target_logs[0].get("user", "System"),
                    "description": f"Repetitive outbound beaconing callbacks observed connecting to suspicious remote host {dest_ip}.",
                    "evidence_count": len(target_logs),
                    "log_ids": [l["log_id"] for l in target_logs],
                    "indicators": {
                        "callback_count": len(target_logs),
                        "remote_c2_ip": dest_ip,
                        "protocol": target_logs[0]["protocol"]
                    },
                    "first_seen": target_logs[0]["timestamp"],
                    "last_seen": target_logs[-1]["timestamp"],
                    "confidence": 94
                })
                alert_counter += 1

        # Rule 6: Web Exploit Injections (SQLi, XSS, Path Traversal, Log4j)
        web_exploit_regex = re.compile(
            r"(union\s+select|'\s*or\s*'?1'?='?1|<script|etc/passwd|\.\./\.\.|jndi:|cmd\.exe|/bin/bash|wget\s+http|curl\s+http)",
            re.IGNORECASE
        )
        for src_ip, ip_logs in by_src_ip.items():
            exploit_logs = []
            for l in ip_logs:
                msg = f"{l.get('message', '')} {l.get('user_agent', '')}"
                if l["event_type"] == "WEB_ATTACK" or web_exploit_regex.search(msg):
                    exploit_logs.append(l)

            if exploit_logs:
                alerts.append({
                    "alert_id": f"ALT-{alert_counter:04d}",
                    "title": f"Web Application Exploitation Attempt",
                    "rule_id": "RULE_WEB_EXPLOIT",
                    "severity": "HIGH",
                    "mitre_attack": {
                        "tactic": "Initial Access",
                        "tactic_id": "TA0001",
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application"
                    },
                    "source_ip": src_ip,
                    "dest_ip": exploit_logs[0]["dest_ip"],
                    "target_user": exploit_logs[0].get("user", "Web Server"),
                    "description": f"Source {src_ip} delivered malicious web injection payloads (SQLi / Traversal / RCE signatures).",
                    "evidence_count": len(exploit_logs),
                    "log_ids": [l["log_id"] for l in exploit_logs],
                    "indicators": {
                        "detected_payloads": [l.get("message", "")[:80] for l in exploit_logs[:3]],
                        "request_count": len(exploit_logs)
                    },
                    "first_seen": exploit_logs[0]["timestamp"],
                    "last_seen": exploit_logs[-1]["timestamp"],
                    "confidence": 91
                })
                alert_counter += 1

        # Rule 7: Off-Hours Privileged Access Anomaly
        privileged_users = ["root", "admin", "administrator", "sysadmin", "svc_backup"]
        for log in logs:
            if log["user"].lower() in privileged_users and log["event_type"] in ["AUTH_SUCCESS", "PRIVILEGE_ESCALATION"]:
                # Check hour (00 to 05 UTC or off-hours)
                try:
                    dt = datetime.fromisoformat(log["timestamp"])
                    if 0 <= dt.hour <= 4:
                        alerts.append({
                            "alert_id": f"ALT-{alert_counter:04d}",
                            "title": f"Unusual Off-Hours Privileged Access ({log['user']})",
                            "rule_id": "RULE_OFF_HOURS_PRIVILEGED",
                            "severity": "MEDIUM",
                            "mitre_attack": {
                                "tactic": "Defense Evasion",
                                "tactic_id": "TA0005",
                                "technique_id": "T1078.001",
                                "technique_name": "Valid Accounts: Default Accounts"
                            },
                            "source_ip": log["src_ip"],
                            "dest_ip": log["dest_ip"],
                            "target_user": log["user"],
                            "description": f"Privileged administrative account '{log['user']}' logged in at unusual time ({dt.strftime('%H:%M:%S UTC')}).",
                            "evidence_count": 1,
                            "log_ids": [log["log_id"]],
                            "indicators": {
                                "account": log["user"],
                                "timestamp": log["timestamp"],
                                "source_origin": log["src_ip"]
                            },
                            "first_seen": log["timestamp"],
                            "last_seen": log["timestamp"],
                            "confidence": 75
                        })
                        alert_counter += 1
                except Exception:
                    pass

        # Rule 8: Suspicious Privilege Escalation / Sudo Abuse
        priv_logs = [l for l in logs if l["event_type"] == "PRIVILEGE_ESCALATION" or "sudo" in l.get("message", "").lower()]
        if priv_logs:
            by_priv_user = defaultdict(list)
            for l in priv_logs:
                by_priv_user[l["user"]].append(l)

            for u, u_logs in by_priv_user.items():
                alerts.append({
                    "alert_id": f"ALT-{alert_counter:04d}",
                    "title": f"Suspicious Privilege Escalation Attempt by '{u}'",
                    "rule_id": "RULE_PRIV_ESCALATION",
                    "severity": "HIGH",
                    "mitre_attack": {
                        "tactic": "Privilege Escalation",
                        "tactic_id": "TA0004",
                        "technique_id": "T1548.003",
                        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
                    },
                    "source_ip": u_logs[0]["src_ip"],
                    "dest_ip": u_logs[0]["dest_ip"],
                    "target_user": u,
                    "description": f"User '{u}' triggered unauthorized privilege elevation attempts or sudo violations.",
                    "evidence_count": len(u_logs),
                    "log_ids": [l["log_id"] for l in u_logs],
                    "indicators": {
                        "user": u,
                        "attempts": len(u_logs),
                        "sample_command": u_logs[0].get("message", "sudo execution")
                    },
                    "first_seen": u_logs[0]["timestamp"],
                    "last_seen": u_logs[-1]["timestamp"],
                    "confidence": 89
                })
                alert_counter += 1

        return alerts
