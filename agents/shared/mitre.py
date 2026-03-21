"""
MITRE ATT&CK Technique Lookup
==============================
Maps tactic categories to the specific technique IDs in scope for v1.0.
"""
from typing import List

TACTIC_TO_TECHNIQUES: dict[str, List[str]] = {
    "Initial Access":          ["T1566", "T1190", "T1133"],
    "Execution":               ["T1059", "T1204"],
    "Persistence":             ["T1053", "T1547"],
    "Privilege Escalation":    ["T1068", "T1055"],
    "Defense Evasion":         ["T1070", "T1036"],
    "Credential Access":       ["T1003", "T1110"],
    "Discovery":               ["T1082", "T1083"],
    "Lateral Movement":        ["T1021", "T1534"],
    "Collection":              ["T1005", "T1039"],
    "Command and Control":     ["T1071", "T1095"],
    "Exfiltration":            ["T1041", "T1048"],
    "Impact":                  ["T1486", "T1498"],
    "Reconnaissance":          ["T1595", "T1596"],
    "Resource Development":    ["T1583", "T1588"],
}

TECHNIQUE_NAMES: dict[str, str] = {
    "T1566": "Phishing",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1059": "Command and Scripting Interpreter",
    "T1204": "User Execution",
    "T1053": "Scheduled Task/Job",
    "T1547": "Boot or Logon Autostart Execution",
    "T1068": "Exploitation for Privilege Escalation",
    "T1055": "Process Injection",
    "T1070": "Indicator Removal",
    "T1036": "Masquerading",
    "T1003": "OS Credential Dumping",
    "T1110": "Brute Force",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1021": "Remote Services",
    "T1534": "Internal Spearphishing",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1071": "Application Layer Protocol",
    "T1095": "Non-Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1486": "Data Encrypted for Impact",
    "T1498": "Network Denial of Service",
    "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
    "T1583": "Acquire Infrastructure",
    "T1588": "Obtain Capabilities",
}


def get_techniques_for_category(category: str) -> List[str]:
    return TACTIC_TO_TECHNIQUES.get(category, [])


def get_technique_name(technique_id: str) -> str:
    return TECHNIQUE_NAMES.get(technique_id, technique_id)
