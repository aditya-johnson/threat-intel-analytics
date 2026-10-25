"""
Pipeline Stage 2 (Synthetic Data): Realistic Security Log Scenarios Generator
Creates high-fidelity CSV and JSON datasets simulating real-world cyber incidents.
"""

import json
import csv
import os
from datetime import datetime, timezone, timedelta
import random


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SAMPLES_DIR = os.path.join(BASE_DIR, "data", "samples")


def generate_all_samples(output_dir: str = None):
    if output_dir is None:
        output_dir = DEFAULT_SAMPLES_DIR
    os.makedirs(output_dir, exist_ok=True)
    now = datetime.now(timezone.utc)

    # ----------------------------------------------------
    # SCENARIO 1: APT29 Multi-Stage Intrusion (CSV)
    # ----------------------------------------------------
    apt_logs = []
    base_t = now - timedelta(hours=2)

    # Phase 1: Port Scan from 194.26.29.112
    ports = [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080, 8443]
    for i, port in enumerate(ports):
        t = base_t + timedelta(seconds=i * 5)
        apt_logs.append({
            "timestamp": t.isoformat(),
            "src_ip": "194.26.29.112",
            "dest_ip": "10.0.0.15",
            "src_port": 49152 + i,
            "dest_port": port,
            "protocol": "TCP",
            "user": "anonymous",
            "event_type": "port_scan",
            "status": "BLOCKED" if port not in [22, 443, 8080] else "ACCEPTED",
            "bytes_sent": 64,
            "bytes_received": 0,
            "message": f"TCP SYN scan probing port {port}",
            "user_agent": "Nmap NSE Engine"
        })

    # Phase 2: SSH Brute Force against port 22
    bf_base_t = base_t + timedelta(minutes=15)
    users = ["admin", "root", "devops", "svc_api", "deploy", "root", "root"]
    for i, u in enumerate(users):
        t = bf_base_t + timedelta(seconds=i * 12)
        status = "FAILURE" if i < len(users) - 1 else "SUCCESS"
        evt = "auth_failure" if status == "FAILURE" else "auth_success"
        apt_logs.append({
            "timestamp": t.isoformat(),
            "src_ip": "194.26.29.112",
            "dest_ip": "10.0.0.15",
            "src_port": 51200 + i,
            "dest_port": 22,
            "protocol": "SSH",
            "user": u,
            "event_type": evt,
            "status": status,
            "bytes_sent": 1240,
            "bytes_received": 420,
            "message": f"SSH authentication {status.lower()} for user {u}",
            "user_agent": "OpenSSH_8.9p1"
        })

    # Phase 3: Privilege Escalation
    pe_t = bf_base_t + timedelta(minutes=5)
    apt_logs.append({
        "timestamp": pe_t.isoformat(),
        "src_ip": "10.0.0.15",
        "dest_ip": "10.0.0.15",
        "src_port": 0,
        "dest_port": 0,
        "protocol": "LOCAL",
        "user": "svc_api",
        "event_type": "privilege_escalation",
        "status": "SUCCESS",
        "bytes_sent": 0,
        "bytes_received": 0,
        "message": "sudo: /usr/bin/find . -exec /bin/sh -p ; [UID=0:root elevated]",
        "user_agent": "bash"
    })

    # Phase 4: C2 Heartbeats
    c2_base_t = pe_t + timedelta(minutes=10)
    for i in range(10):
        t = c2_base_t + timedelta(seconds=i * 60)
        apt_logs.append({
            "timestamp": t.isoformat(),
            "src_ip": "10.0.0.15",
            "dest_ip": "194.26.29.112",
            "src_port": 40100 + i,
            "dest_port": 443,
            "protocol": "HTTPS",
            "user": "root",
            "event_type": "c2_beacon",
            "status": "ESTABLISHED",
            "bytes_sent": 512,
            "bytes_received": 1024,
            "message": "Outbound TLS session with periodic 60s jitter (Cobalt Strike malleable C2)",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })

    # Phase 5: Exfiltration to second IP
    exfil_t = c2_base_t + timedelta(minutes=15)
    apt_logs.append({
        "timestamp": exfil_t.isoformat(),
        "src_ip": "10.0.0.15",
        "dest_ip": "91.240.118.172",
        "src_port": 44210,
        "dest_port": 443,
        "protocol": "HTTPS",
        "user": "root",
        "event_type": "data_exfiltration",
        "status": "COMPLETED",
        "bytes_sent": 28450000, # ~28 MB
        "bytes_received": 12000,
        "message": "High-volume encrypted archive stream exported via POST /api/v2/telemetry",
        "user_agent": "curl/7.88.1"
    })

    # Save CSV
    csv_path = os.path.join(output_dir, "apt_intrusion_sample.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(apt_logs[0].keys()))
        writer.writeheader()
        writer.writerows(apt_logs)

    # ----------------------------------------------------
    # SCENARIO 2: Global Credential Stuffing Campaign (JSON)
    # ----------------------------------------------------
    stuffing_logs = []
    base_t2 = now - timedelta(hours=1)
    target_users = ["jdoe", "asmith", "admin", "sales_team", "billing", "mross", "tlee", "hclark", "bwayne", "cstark", "peterp", "clarkk", "support", "finance_lead"]
    bot_ips = ["103.251.167.22", "198.51.100.23", "203.0.113.88"]

    for i in range(45):
        t = base_t2 + timedelta(seconds=i * 15)
        attacker_ip = bot_ips[i % len(bot_ips)]
        usr = target_users[i % len(target_users)]
        stuffing_logs.append({
            "timestamp": t.isoformat(),
            "source_ip": attacker_ip,
            "target_ip": "10.0.0.50",
            "port": 443,
            "protocol": "HTTPS",
            "username": usr,
            "event": "auth_failure",
            "result": "FAILURE",
            "bytes_in": 780,
            "bytes_out": 350,
            "details": f"API login authentication failed: invalid credentials for {usr}",
            "user_agent": "Python-requests/2.31.0"
        })

    json_path = os.path.join(output_dir, "credential_stuffing_sample.json")
    with open(json_path, "w") as f:
        json.dump(stuffing_logs, f, indent=2)

    # ----------------------------------------------------
    # SCENARIO 3: Internal Lateral Reconnaissance (CSV)
    # ----------------------------------------------------
    recon_logs = []
    base_t3 = now - timedelta(hours=3)
    attacker_workstation = "10.0.1.45"
    for host_id in range(1, 26):
        target_ip = f"10.0.1.{host_id}"
        t = base_t3 + timedelta(seconds=host_id * 8)
        for target_port in [445, 3389, 1433]:
            recon_logs.append({
                "timestamp": t.isoformat(),
                "src_ip": attacker_workstation,
                "dest_ip": target_ip,
                "src_port": 53000 + host_id,
                "dest_port": target_port,
                "protocol": "TCP",
                "user": "compromised_clerk",
                "event_type": "port_scan",
                "status": "BLOCKED" if host_id % 3 != 0 else "ACCEPTED",
                "bytes_sent": 128,
                "bytes_received": 0,
                "message": f"Internal SMB/RDP discovery sweep against {target_ip}:{target_port}",
                "user_agent": "BloodHound/SharpHound"
            })

    recon_csv = os.path.join(output_dir, "port_scan_lateral_sample.csv")
    with open(recon_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(recon_logs[0].keys()))
        writer.writeheader()
        writer.writerows(recon_logs)

    # ----------------------------------------------------
    # SCENARIO 4: Enterprise Mixed Traffic (JSON)
    # ----------------------------------------------------
    enterprise_logs = []
    base_t4 = now - timedelta(hours=4)

    # Benign normal enterprise users
    benign_users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    benign_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.15"]
    for i in range(50):
        t = base_t4 + timedelta(minutes=i * 4)
        usr = random.choice(benign_users)
        ip = random.choice(benign_ips)
        enterprise_logs.append({
            "timestamp": t.isoformat(),
            "src_ip": ip,
            "dest_ip": "10.0.0.100",
            "src_port": 50000 + i,
            "dest_port": 443,
            "protocol": "TCP",
            "user": usr,
            "event_type": "auth_success",
            "status": "SUCCESS",
            "bytes_sent": random.randint(1200, 8500),
            "bytes_received": random.randint(5000, 45000),
            "message": f"Normal session token refresh for employee {usr}",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        })

    # Infiltrated Web Exploit (SQLi + Path Traversal) from 162.243.100.54
    exploit_payloads = [
        "GET /products.php?id=1%27%20UNION%20SELECT%20username,password_hash%20FROM%20users--",
        "POST /api/v1/auth - payload: admin' OR '1'='1",
        "GET /download?file=../../../../etc/passwd",
        "GET /cgi-bin/.%2e/.%2e/.%2e/bin/sh"
    ]
    for idx, payload in enumerate(exploit_payloads):
        t = base_t4 + timedelta(minutes=30 + idx * 2)
        enterprise_logs.append({
            "timestamp": t.isoformat(),
            "src_ip": "162.243.100.54",
            "dest_ip": "10.0.0.100",
            "src_port": 48900 + idx,
            "dest_port": 443,
            "protocol": "HTTPS",
            "user": "anonymous",
            "event_type": "web_attack",
            "status": "BLOCKED",
            "bytes_sent": 950,
            "bytes_received": 210,
            "message": f"WAF trigger: Malicious payload detected: {payload}",
            "user_agent": "sqlmap/1.7.2#stable"
        })

    # Off-hours unauthorized access from Tor Exit Node (185.220.101.5)
    off_hours_t = base_t4.replace(hour=2, minute=15)
    enterprise_logs.append({
        "timestamp": off_hours_t.isoformat(),
        "src_ip": "185.220.101.5",
        "dest_ip": "10.0.0.100",
        "src_port": 44122,
        "dest_port": 22,
        "protocol": "SSH",
        "user": "root",
        "event_type": "auth_success",
        "status": "SUCCESS",
        "bytes_sent": 2100,
        "bytes_received": 1500,
        "message": "Privileged root session established via Tor Exit Relay node during non-business hours",
        "user_agent": "SSH-2.0-OpenSSH_9.0"
    })

    ent_json = os.path.join(output_dir, "enterprise_mixed_sample.json")
    with open(ent_json, "w") as f:
        json.dump(enterprise_logs, f, indent=2)

    print(f"Generated 4 realistic security sample datasets in {output_dir}")


if __name__ == "__main__":
    generate_all_samples()
