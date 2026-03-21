"""
Syslog Normalizer
=================
Parses RFC 3164 and RFC 5424 syslog messages from Linux hosts,
network devices (Cisco, Palo Alto), and Unix daemons.
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict

# RFC 5424 structured syslog
_RFC5424 = re.compile(
    r"<(?P<pri>\d+)>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>\S+)\s+"
    r"(?P<message>.+)",
)

# RFC 3164 legacy syslog
_RFC3164 = re.compile(
    r"<(?P<pri>\d+)>"
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)",
)

# Common IP patterns in log messages
_IP_PATTERN    = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_USER_PATTERN  = re.compile(r"(?:user|for)\s+(\S+)", re.IGNORECASE)
_HASH_PATTERN  = re.compile(r"\b([0-9a-fA-F]{32,64})\b")


def normalize_syslog(log_line: str) -> Dict[str, Any]:
    """Parse a syslog line into a normalized dict."""
    result: Dict[str, Any] = {}

    m = _RFC5424.match(log_line) or _RFC3164.match(log_line)
    if m:
        d = m.groupdict()
        result["host_id"] = d.get("hostname", "")
        result["message"] = d.get("message", log_line)
        result["application"] = d.get("appname") or d.get("process", "")

        # Syslog priority → severity
        pri = int(d.get("pri", 0))
        severity_level = pri % 8   # 0=Emergency, 7=Debug
        result["severity_score"] = max(0.0, (7 - severity_level) / 7.0)
    else:
        result["message"] = log_line

    msg = result.get("message", log_line)

    # Extract IPs from message body
    ips = _IP_PATTERN.findall(msg)
    if ips:
        result["src_ip"] = ips[0]
        if len(ips) > 1:
            result["dst_ip"] = ips[1]

    # Extract username
    user_match = _USER_PATTERN.search(msg)
    if user_match:
        result["user"] = user_match.group(1)

    # Extract potential process hash
    hash_match = _HASH_PATTERN.search(msg)
    if hash_match:
        result["process_hash"] = hash_match.group(1)

    return result
