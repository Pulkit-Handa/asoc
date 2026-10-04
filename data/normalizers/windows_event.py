"""
Windows Event Log Normalizer
=============================
Parses Windows Security Event Logs (XML or JSON format).
Key event IDs mapped to MITRE ATT&CK techniques.
"""
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict

# Windows Event ID → MITRE ATT&CK technique
_EVENT_TO_MITRE: Dict[int, str] = {
    4624:  "T1078",   # Successful logon
    4625:  "T1110",   # Failed logon (brute force)
    4648:  "T1078",   # Logon with explicit credentials
    4688:  "T1059",   # Process creation
    4698:  "T1053",   # Scheduled task created
    4702:  "T1053",   # Scheduled task modified
    4720:  "T1136",   # User account created
    4728:  "T1078",   # Member added to security-enabled global group
    4732:  "T1078",   # Member added to security-enabled local group
    4768:  "T1558",   # Kerberos TGT requested
    4769:  "T1558",   # Kerberos service ticket requested
    4776:  "T1003",   # Credential validation (NTLM)
    5140:  "T1021",   # Network share access
    7045:  "T1543",   # New service installed
    7036:  "T1543",   # Service state changed
}

# High-severity event IDs that warrant elevated scoring
_HIGH_SEVERITY_EVENTS = {4625, 4648, 4698, 4702, 4720, 4728, 4732, 4776, 7045}

_WS_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def normalize_windows_event(log_data: str) -> Dict[str, Any]:
    """
    Parse a Windows Event Log entry.
    Accepts either XML (raw WinEvt) or JSON (Winlogbeat/Elastic format).
    """
    if log_data.strip().startswith("{"):
        return _parse_json_event(log_data)
    elif log_data.strip().startswith("<"):
        return _parse_xml_event(log_data)
    else:
        return _parse_text_event(log_data)


def _parse_json_event(log_data: str) -> Dict[str, Any]:
    """Parse Winlogbeat/Elastic Agent JSON format."""
    try:
        data    = json.loads(log_data)
        winlog  = data.get("winlog", data)
        event_data = winlog.get("event_data", {})
        event_id   = int(winlog.get("event_id", 0))

        result = {
            "host_id":       data.get("host", {}).get("name", ""),
            "event_id":      event_id,
            "src_ip":        event_data.get("IpAddress", "").replace("-", ""),
            "user":          (
                event_data.get("TargetUserName") or
                event_data.get("SubjectUserName", "")
            ),
            "process_hash":  event_data.get("Hashes", "").split("=")[-1],
            "application":   event_data.get("ProcessName", ""),
            "mitre_id":      _EVENT_TO_MITRE.get(event_id, ""),
            "severity_score": 0.7 if event_id in _HIGH_SEVERITY_EVENTS else 0.3,
        }
        return {k: v for k, v in result.items() if v}

    except (json.JSONDecodeError, KeyError, ValueError):
        return {}


def _parse_xml_event(log_data: str) -> Dict[str, Any]:
    """Parse raw Windows XML Event Log format."""
    try:
        root = ET.fromstring(log_data)
        ns   = _WS_NS

        system    = root.find(f"{ns}System")
        event_data = root.find(f"{ns}EventData")

        if system is None:
            return {}

        event_id_el = system.find(f"{ns}EventID")
        event_id    = int(event_id_el.text) if event_id_el is not None else 0

        comp_el  = system.find(f"{ns}Computer")
        host_id  = comp_el.text if comp_el is not None else ""

        result = {
            "host_id":       host_id,
            "event_id":      event_id,
            "mitre_id":      _EVENT_TO_MITRE.get(event_id, ""),
            "severity_score": 0.7 if event_id in _HIGH_SEVERITY_EVENTS else 0.3,
        }

        # Extract named data fields
        if event_data is not None:
            for data_el in event_data.findall(f"{ns}Data"):
                name  = data_el.get("Name", "")
                value = (data_el.text or "").strip()
                if name == "IpAddress":
                    result["src_ip"] = value
                elif name in ("TargetUserName", "SubjectUserName"):
                    result.setdefault("user", value)
                elif name == "ProcessName":
                    result["application"] = value
                elif name == "Hashes":
                    result["process_hash"] = value.split("=")[-1]

        return {k: v for k, v in result.items() if v}

    except ET.ParseError:
        return {}


def _parse_text_event(log_data: str) -> Dict[str, Any]:
    """Fallback: extract what we can from plain text Windows log."""
    result: Dict[str, Any] = {}

    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", log_data)
    if ip_match:
        result["src_ip"] = ip_match.group(1)

    user_match = re.search(r"Account Name:\s+(\S+)", log_data)
    if user_match:
        result["user"] = user_match.group(1)

    eid_match = re.search(r"Event ID[:\s]+(\d+)", log_data, re.IGNORECASE)
    if eid_match:
        event_id = int(eid_match.group(1))
        result["event_id"]  = event_id
        result["mitre_id"]  = _EVENT_TO_MITRE.get(event_id, "")
        result["severity_score"] = 0.7 if event_id in _HIGH_SEVERITY_EVENTS else 0.3

    return result
