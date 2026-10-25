"""
Pipeline Stage 6: Explainable Risk Scoring Engine
Combines detection evidence, threat-intelligence reputation,
attack frequency, and asset criticality into an explainable 0-100 risk score.
"""

from typing import List, Dict, Any


class RiskScorer:
    """Calculates prioritized, explainable risk scores for security alerts."""

    def __init__(self):
        self.severity_weights = {
            "CRITICAL": 35,
            "HIGH": 25,
            "MEDIUM": 15,
            "LOW": 8,
            "INFO": 3
        }

    def score_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates risk score and attaches an explainable breakdown to the alert."""
        reasons = []
        breakdown = {
            "base_detection": 0,
            "threat_intelligence": 0,
            "attack_velocity": 0,
            "asset_criticality": 0
        }

        # 1. Base Detection Severity
        sev = alert.get("severity", "MEDIUM").upper()
        base_points = self.severity_weights.get(sev, 15)
        breakdown["base_detection"] = base_points
        reasons.append({
            "category": "Detection Rule",
            "points": base_points,
            "explanation": f"Rule severity '{sev}' ({alert.get('title', 'Detection')})"
        })

        # 2. Threat Intelligence Reputation (Evaluate source and destination)
        src_ti = alert.get("threat_intel", {})
        dst_ti = alert.get("dest_intel", {})

        # Pick the most threatening entity (for C2/exfil, dest is the threat)
        ti = dst_ti if dst_ti.get("abuse_confidence_score", 0) > src_ti.get("abuse_confidence_score", 0) else src_ti
        ip_context = "Destination C2/Drop IP" if ti == dst_ti and ti else "Source IP"

        abuse_score = ti.get("abuse_confidence_score", 0)
        ti_points = 0
        if abuse_score > 0:
            ti_points = int((abuse_score / 100.0) * 28)
            reasons.append({
                "category": "Threat Intelligence",
                "points": ti_points,
                "explanation": f"{ip_context} ({ti.get('ip')}) reputation abuse score is {abuse_score}% ({ti.get('threat_classification', 'Suspicious')})"
            })

        # Attribution / Blacklist bonus
        if ti.get("threat_actor"):
            ti_points += 5
            reasons.append({
                "category": "Threat Actor",
                "points": 5,
                "explanation": f"Correlated with known adversary: {ti.get('threat_actor')}"
            })
        
        blacklists = ti.get("blacklists", [])
        if len(blacklists) >= 2:
            ti_points += 4
            reasons.append({
                "category": "Blacklists",
                "points": 4,
                "explanation": f"Flagged on {len(blacklists)} threat feeds: {', '.join(blacklists[:2])}"
            })

        breakdown["threat_intelligence"] = min(35, ti_points)

        # 3. Attack Frequency & Velocity
        ev_count = alert.get("evidence_count", 1)
        velocity_points = 0
        if ev_count >= 15:
            velocity_points = 15
            reasons.append({
                "category": "Attack Velocity",
                "points": 15,
                "explanation": f"High burst volume with {ev_count} correlated security events"
            })
        elif ev_count >= 7:
            velocity_points = 10
            reasons.append({
                "category": "Attack Velocity",
                "points": 10,
                "explanation": f"Elevated frequency: {ev_count} correlated security events"
            })
        elif ev_count >= 3:
            velocity_points = 5
            reasons.append({
                "category": "Attack Velocity",
                "points": 5,
                "explanation": f"Multiple repeated attempts: {ev_count} events"
            })
        else:
            velocity_points = 2

        breakdown["attack_velocity"] = min(15, velocity_points)

        # 4. Asset / Target Criticality
        target_points = 0
        user = str(alert.get("target_user", "")).lower()
        if any(admin in user for admin in ["root", "admin", "administrator", "sysadmin", "accounts"]):
            target_points += 8
            reasons.append({
                "category": "Target Criticality",
                "points": 8,
                "explanation": f"High-privilege identity targeted ({alert.get('target_user')})"
            })

        indicators = alert.get("indicators", {})
        sensitive_ports = indicators.get("sensitive_ports_hit", [])
        if sensitive_ports:
            target_points += 7
            reasons.append({
                "category": "Sensitive Services",
                "points": 7,
                "explanation": f"High-value service ports probed: {sensitive_ports}"
            })

        # Exfiltration or C2 specific impact
        if alert.get("rule_id") in ["RULE_C2_BEACONING", "RULE_DATA_EXFILTRATION"]:
            target_points += 7
            reasons.append({
                "category": "Critical Objective",
                "points": 7,
                "explanation": "Active exfiltration / command and control session established"
            })

        breakdown["asset_criticality"] = min(15, target_points)

        # Calculate final composite score
        total_raw = sum(breakdown.values())
        final_score = max(5, min(100, total_raw))

        # Determine finalized risk priority level
        if final_score >= 85:
            level = "CRITICAL"
            action = "Immediate Containment & Incident Response"
        elif final_score >= 65:
            level = "HIGH"
            action = "Priority Analyst Triage & IP Block"
        elif final_score >= 40:
            level = "MEDIUM"
            action = "Elevated Monitoring & Endpoint Audit"
        elif final_score >= 15:
            level = "LOW"
            action = "Informational Review"
        else:
            level = "INFO"
            action = "Audited Activity"

        alert["risk_score"] = final_score
        alert["risk_level"] = level
        alert["recommended_action"] = action
        alert["score_breakdown"] = breakdown
        alert["risk_factors"] = reasons
        alert["triage_status"] = alert.get("triage_status", "OPEN")
        alert["analyst_notes"] = alert.get("analyst_notes", "")

        return alert

    def score_all_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scores all alerts and sorts them by risk score descending (highest priority first)."""
        scored = [self.score_alert(a) for a in alerts]
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored
