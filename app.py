"""
Threat Intelligence & Detection Analytics Web Application
FastAPI Server orchestrating parsing, detection, threat enrichment, scoring, and UI.
"""

import os
import io
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from collections import defaultdict, Counter

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline.parser import LogParser
from pipeline.detectors import DetectionEngine
from pipeline.threat_intel import ThreatIntelEnricher
from pipeline.risk_scorer import RiskScorer
from pipeline.report_generator import ReportGenerator

app = FastAPI(
    title="AEGIS Threat Intelligence & Detection Analytics Pipeline",
    description="Automated log parsing, multi-factor detection, threat intel enrichment, and incident triage.",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pipeline instances
parser = LogParser()
detector = DetectionEngine()
enricher = ThreatIntelEnricher()
scorer = RiskScorer()
reporter = ReportGenerator()

# In-memory session state
APP_STATE: Dict[str, Any] = {
    "dataset_name": "None",
    "analyzed_at": None,
    "logs": [],
    "stats": {},
    "alerts": []
}

# Resolve base project directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "data", "samples")
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class TriageUpdate(BaseModel):
    status: str # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    notes: Optional[str] = ""


class ApiKeyConfig(BaseModel):
    abuseipdb_key: Optional[str] = None
    virustotal_key: Optional[str] = None


def run_full_pipeline(content_str: str, file_type: str = "auto", dataset_label: str = "Uploaded Dataset"):
    """Executes the complete 8-step pipeline."""
    # Step 3: Parse and clean logs
    cleaned_logs, stats = parser.parse_content(content_str, file_type)
    if not cleaned_logs:
        raise HTTPException(status_code=400, detail="No valid log entries could be extracted from input.")

    # Step 4: Detect suspicious activity
    raw_alerts = detector.run_detections(cleaned_logs)

    # Step 5: Enrich IP addresses with Threat Intelligence
    enriched_alerts = enricher.enrich_alerts(raw_alerts)

    # Step 6: Calculate explainable risk scores
    scored_alerts = scorer.score_all_alerts(enriched_alerts)

    APP_STATE["dataset_name"] = dataset_label
    APP_STATE["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    APP_STATE["logs"] = cleaned_logs
    APP_STATE["stats"] = stats
    APP_STATE["alerts"] = scored_alerts

    return scored_alerts, stats


def build_analytics_payload() -> Dict[str, Any]:
    """Assembles all data needed by the visual analytics dashboard."""
    alerts = APP_STATE.get("alerts", [])
    logs = APP_STATE.get("logs", [])
    stats = APP_STATE.get("stats", {})

    # KPIs
    crit_count = sum(1 for a in alerts if a.get("risk_level") == "CRITICAL")
    high_count = sum(1 for a in alerts if a.get("risk_level") == "HIGH")
    med_count = sum(1 for a in alerts if a.get("risk_level") == "MEDIUM")
    low_count = sum(1 for a in alerts if a.get("risk_level") in ["LOW", "INFO"])
    
    unique_malicious_ips = set()
    for a in alerts:
        ti = a.get("threat_intel", {})
        if ti.get("is_malicious") or ti.get("abuse_confidence_score", 0) > 40:
            unique_malicious_ips.add(a.get("source_ip"))
        dest_ti = a.get("dest_intel", {})
        if dest_ti.get("is_malicious") or dest_ti.get("abuse_confidence_score", 0) > 40:
            unique_malicious_ips.add(a.get("dest_ip"))

    avg_risk = round(sum(a.get("risk_score", 0) for a in alerts) / max(1, len(alerts)), 1) if alerts else 0
    max_risk = max((a.get("risk_score", 0) for a in alerts), default=0)

    # MITRE ATT&CK coverage
    mitre_summary = defaultdict(lambda: {"count": 0, "techniques": set()})
    for a in alerts:
        m = a.get("mitre_attack", {})
        tactic = m.get("tactic", "Unspecified")
        tech = f"{m.get('technique_id', '')} - {m.get('technique_name', '')}"
        mitre_summary[tactic]["count"] += 1
        if m.get("technique_id"):
            mitre_summary[tactic]["techniques"].add(tech)

    mitre_data = []
    for tactic, val in mitre_summary.items():
        mitre_data.append({
            "tactic": tactic,
            "count": val["count"],
            "techniques": list(val["techniques"])
        })

    # Attack Rule breakdown
    rule_counts = Counter(a.get("title") for a in alerts)
    attack_breakdown = [{"name": k, "count": v} for k, v in rule_counts.most_common()]

    # Timeline / Activity series (bucketed by time)
    timeline_map = defaultdict(lambda: {"total": 0, "alerts": 0, "failures": 0})
    for l in logs:
        # Group into 15-minute or hourly buckets
        ts = l.get("timestamp", "")[:16] # YYYY-MM-DDTHH:MM
        timeline_map[ts]["total"] += 1
        if l.get("event_type") == "AUTH_FAILURE" or l.get("status") == "FAILURE":
            timeline_map[ts]["failures"] += 1

    for a in alerts:
        ts = a.get("first_seen", "")[:16]
        if ts in timeline_map:
            timeline_map[ts]["alerts"] += 1
        else:
            timeline_map[ts] = {"total": 1, "alerts": 1, "failures": 0}

    sorted_timeline = sorted(timeline_map.items())
    timeline_series = {
        "labels": [k.replace("T", " ") for k, _ in sorted_timeline],
        "events": [v["total"] for _, v in sorted_timeline],
        "alerts": [v["alerts"] for _, v in sorted_timeline],
        "failures": [v["failures"] for _, v in sorted_timeline]
    }

    # Geo Map Markers (Unique Attacker & C2 IPs)
    geo_threats = []
    seen_ips = set()
    for a in alerts:
        src_ip = a.get("source_ip")
        if src_ip and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            ti = a.get("threat_intel", {})
            geo_threats.append({
                "ip": src_ip,
                "role": "Source Attacker",
                "risk_score": a.get("risk_score"),
                "risk_level": a.get("risk_level"),
                "classification": ti.get("threat_classification", "External Host"),
                "threat_actor": ti.get("threat_actor"),
                "abuse_score": ti.get("abuse_confidence_score", 0),
                "country": ti.get("country_name", "Unknown"),
                "city": ti.get("city", "Unknown"),
                "latitude": ti.get("latitude", 20.0),
                "longitude": ti.get("longitude", 0.0),
                "isp": ti.get("isp", "Unknown ISP"),
                "alert_title": a.get("title")
            })

        # Also add destination if external C2
        dest_ip = a.get("dest_ip")
        if dest_ip and not a.get("dest_ip_is_private", False) and dest_ip not in seen_ips:
            seen_ips.add(dest_ip)
            dest_ti = a.get("dest_intel", {})
            if dest_ti.get("is_malicious") or dest_ti.get("abuse_confidence_score", 0) > 40:
                geo_threats.append({
                    "ip": dest_ip,
                    "role": "C2 / Drop Site",
                    "risk_score": a.get("risk_score"),
                    "risk_level": a.get("risk_level"),
                    "classification": dest_ti.get("threat_classification", "C2 Node"),
                    "threat_actor": dest_ti.get("threat_actor"),
                    "abuse_score": dest_ti.get("abuse_confidence_score", 0),
                    "country": dest_ti.get("country_name", "Unknown"),
                    "city": dest_ti.get("city", "Unknown"),
                    "latitude": dest_ti.get("latitude", 20.0),
                    "longitude": dest_ti.get("longitude", 0.0),
                    "isp": dest_ti.get("isp", "External ISP"),
                    "alert_title": f"C2 Endpoint: {a.get('title')}"
                })

    # Top Suspicious IPs Leaderboard
    ip_stats = defaultdict(lambda: {"alerts": 0, "max_score": 0, "ti": {}, "attack_types": set()})
    for a in alerts:
        ip = a.get("source_ip")
        if ip:
            ip_stats[ip]["alerts"] += 1
            ip_stats[ip]["max_score"] = max(ip_stats[ip]["max_score"], a.get("risk_score", 0))
            ip_stats[ip]["ti"] = a.get("threat_intel", {})
            ip_stats[ip]["attack_types"].add(a.get("title"))

    top_ips = []
    for ip, d in sorted(ip_stats.items(), key=lambda x: (x[1]["max_score"], x[1]["alerts"]), reverse=True):
        top_ips.append({
            "ip": ip,
            "max_risk_score": d["max_score"],
            "alert_count": d["alerts"],
            "classification": d["ti"].get("threat_classification", "Unclassified"),
            "threat_actor": d["ti"].get("threat_actor"),
            "abuse_score": d["ti"].get("abuse_confidence_score", 0),
            "country": d["ti"].get("country_name", "Unknown"),
            "country_code": d["ti"].get("country_code", "XX"),
            "city": d["ti"].get("city", "Unknown"),
            "isp": d["ti"].get("isp", "Unknown"),
            "blacklists": d["ti"].get("blacklists", []),
            "attacks": list(d["attack_types"])
        })

    return {
        "dataset_name": APP_STATE["dataset_name"],
        "analyzed_at": APP_STATE["analyzed_at"],
        "stats": stats,
        "kpis": {
            "total_logs": stats.get("valid_records", len(logs)),
            "total_alerts": len(alerts),
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "malicious_ips": len(unique_malicious_ips),
            "avg_risk": avg_risk,
            "max_risk": max_risk
        },
        "alerts": alerts,
        "attack_breakdown": attack_breakdown,
        "mitre_matrix": mitre_data,
        "timeline": timeline_series,
        "geo_threats": geo_threats,
        "top_ips": top_ips,
        "raw_logs_sample": logs[:150]
    }


@app.on_event("startup")
def startup_event():
    """Initializes with default APT scenario so dashboard is loaded on launch."""
    default_sample = os.path.join(SAMPLES_DIR, "apt_intrusion_sample.csv")
    if os.path.exists(default_sample):
        try:
            with open(default_sample, "r") as f:
                content = f.read()
            run_full_pipeline(content, "csv", "APT29 Multi-Stage Intrusion (Preset)")
            print("Successfully loaded default APT29 intrusion dataset.")
        except Exception as e:
            print(f"Error preloading default dataset: {e}")


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    """Serves the main Threat Intelligence & Detection Analytics Dashboard."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h2>Threat Intelligence & Detection Analytics Dashboard Loading...</h2>")


@app.get("/api/results")
def get_results():
    """Returns the current state and analytics payload."""
    return build_analytics_payload()


@app.get("/api/samples")
def get_sample_list():
    """Returns available pre-configured realistic synthetic datasets."""
    return [
        {
            "id": "apt_intrusion",
            "name": "APT29 Multi-Stage Cyber Intrusion",
            "file": "apt_intrusion_sample.csv",
            "format": "csv",
            "description": "Port scanning, SSH password spray, root sudo privilege escalation, Cobalt Strike C2 beaconing, and 28MB encrypted exfiltration.",
            "tags": ["APT29", "Brute-Force", "C2 Beacon", "Exfiltration", "Critical"]
        },
        {
            "id": "credential_stuffing",
            "name": "Distributed Credential Stuffing Campaign",
            "file": "credential_stuffing_sample.json",
            "format": "json",
            "description": "High-velocity password spraying across 14 employee accounts from multi-nation botnet IPs (Lazarus & Mirai clusters).",
            "tags": ["Credential Access", "Botnet", "Password Spray", "High"]
        },
        {
            "id": "port_scan_lateral",
            "name": "Internal Network Sweep & Lateral Recon",
            "file": "port_scan_lateral_sample.csv",
            "format": "csv",
            "description": "Compromised internal workstation probing SMB (445), RDP (3389), and database services across internal subnet.",
            "tags": ["Reconnaissance", "Discovery", "Internal Threat", "Lateral Movement"]
        },
        {
            "id": "enterprise_mixed",
            "name": "Enterprise Production Traffic (Mixed Infiltration)",
            "file": "enterprise_mixed_sample.json",
            "format": "json",
            "description": "Normal employee API traffic blended with stealthy SQLi, path traversal, and off-hours administrative SSH login via Tor exit node.",
            "tags": ["Web Exploit", "Tor Exit Node", "Off-Hours Privileged", "Stealth"]
        }
    ]


@app.post("/api/sample/{scenario_id}")
def load_sample_dataset(scenario_id: str):
    """Loads and runs the pipeline on a selected synthetic scenario."""
    file_map = {
        "apt_intrusion": ("apt_intrusion_sample.csv", "csv", "APT29 Multi-Stage Intrusion"),
        "credential_stuffing": ("credential_stuffing_sample.json", "json", "Distributed Credential Stuffing"),
        "port_scan_lateral": ("port_scan_lateral_sample.csv", "csv", "Internal Network Sweep & Lateral Recon"),
        "enterprise_mixed": ("enterprise_mixed_sample.json", "json", "Enterprise Production Traffic (Mixed)")
    }

    if scenario_id not in file_map:
        raise HTTPException(status_code=404, detail="Requested scenario dataset not found.")

    filename, file_format, label = file_map[scenario_id]
    filepath = os.path.join(SAMPLES_DIR, filename)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Sample file {filename} does not exist.")

    with open(filepath, "r") as f:
        content = f.read()

    run_full_pipeline(content, file_format, label)
    return build_analytics_payload()


@app.post("/api/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """Uploads and analyzes a security log file (CSV or JSON)."""
    filename = file.filename or "uploaded_logs"
    file_ext = filename.split(".")[-1].lower() if "." in filename else "auto"

    content_bytes = await file.read()
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = content_bytes.decode("latin-1")

    run_full_pipeline(content_str, file_ext, f"Uploaded: {filename}")
    return build_analytics_payload()


@app.get("/api/enrich-ip/{ip_address}")
def enrich_single_ip(ip_address: str):
    """On-demand threat intelligence query for any arbitrary IP address."""
    profile = enricher.enrich_ip(ip_address)
    return profile


@app.post("/api/alerts/{alert_id}/triage")
def update_alert_triage(alert_id: str, update: TriageUpdate):
    """Updates triage status and analyst notes for a specific alert."""
    for a in APP_STATE.get("alerts", []):
        if a.get("alert_id") == alert_id:
            a["triage_status"] = update.status
            if update.notes:
                a["analyst_notes"] = update.notes
            return {"success": True, "alert_id": alert_id, "status": update.status, "notes": a.get("analyst_notes")}
    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")


@app.post("/api/config/api-keys")
def configure_api_keys(config: ApiKeyConfig):
    """Updates API keys for live threat intelligence lookups."""
    if config.abuseipdb_key:
        enricher.abuseipdb_key = config.abuseipdb_key
    if config.virustotal_key:
        enricher.virustotal_key = config.virustotal_key
    return {"success": True, "message": "API keys updated successfully."}


@app.get("/api/export/csv")
def download_csv_report():
    """Generates and downloads a CSV report of all enriched alerts."""
    alerts = APP_STATE.get("alerts", [])
    csv_str = reporter.export_csv(alerts)
    response = StreamingResponse(io.StringIO(csv_str), media_type="text/csv")
    filename = f"threat_intel_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


@app.get("/api/export/pdf")
def download_pdf_report():
    """Generates and downloads an Executive Threat Intelligence PDF Report."""
    alerts = APP_STATE.get("alerts", [])
    stats = APP_STATE.get("stats", {})
    pdf_out = os.path.join(DATA_DIR, "threat_intelligence_executive_report.pdf")
    
    reporter.export_pdf(alerts, stats, pdf_out)
    return FileResponse(
        pdf_out,
        media_type="application/pdf",
        filename=f"Threat_Intelligence_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    )


@app.get("/api/export/json")
def download_json_export():
    """Exports entire incident triage package as a JSON file."""
    data = build_analytics_payload()
    json_str = json.dumps(data, indent=2)
    response = StreamingResponse(io.StringIO(json_str), media_type="application/json")
    filename = f"incident_triage_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8055, reload=True)
