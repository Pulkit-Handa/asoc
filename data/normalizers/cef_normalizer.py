"""
CEF Log Normalizer
==================
Parses Common Event Format (CEF) logs produced by:
  - Fortinet FortiGate
  - ArcSight
  - Check Point
  - Many SIEM appliances

CEF format:
  CEF:Version|Device Vendor|Device Product|Device Version|
  Signature ID|Name|Severity|Extension
"""
import re
from typing import Any, Dict


# CEF extension field name → our normalized field name
_CEF_FIELD_MAP = {
    "src":          "src_ip",
    "spt":          "src_port",
    "dst":          "dst_ip",
    "dpt":          "dst_port",
    "suser":        "user",
    "duser":        "dst_user",
    "cs1":          "process_hash",
    "fname":        "filename",
    "fsize":        "file_size",
    "dhost":        "dst_host",
    "shost":        "host_id",
    "act":          "action",
    "outcome":      "outcome",
    "app":          "application",
    "proto":        "protocol",
    "requestUrl":   "url",
    "msg":          "message",
    "cat":          "category",
    "deviceAction": "action",
}


def normalize_cef(log_line: str) -> Dict[str, Any]:
    """
    Parse a CEF log line into a normalized dict.
    Returns empty dict if the line is not valid CEF.
    """
    if not log_line.startswith("CEF:"):
        return {}

    try:
        # Split header and extension
        parts = re.split(r"(?<!\\)\|", log_line)
        if len(parts) < 8:
            return {}

        header = {
            "cef_version":     parts[0].replace("CEF:", ""),
            "device_vendor":   parts[1],
            "device_product":  parts[2],
            "device_version":  parts[3],
            "signature_id":    parts[4],
            "name":            parts[5],
            "severity":        parts[6],
        }

        # Parse extension key=value pairs
        extension_str = parts[7]
        extension = _parse_extension(extension_str)

        # Build normalized output
        result: Dict[str, Any] = {**header}
        for cef_key, our_key in _CEF_FIELD_MAP.items():
            if cef_key in extension:
                result[our_key] = extension[cef_key]

        # Normalize severity to [0, 1] float
        raw_severity = header.get("severity", "5")
        try:
            result["severity_score"] = min(1.0, int(raw_severity) / 10.0)
        except ValueError:
            result["severity_score"] = 0.5

        return result

    except Exception:
        return {}


def _parse_extension(ext: str) -> Dict[str, str]:
    """Parse CEF extension string: 'key=value key2=value2 ...'"""
    result = {}
    # Regex: match key=value where value ends at next ' key=' or end of string
    pattern = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s\w+=|$)")
    for match in pattern.finditer(ext):
        key   = match.group(1).strip()
        value = match.group(2).strip()
        # Unescape CEF escaped characters
        value = value.replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\")
        result[key] = value
    return result
