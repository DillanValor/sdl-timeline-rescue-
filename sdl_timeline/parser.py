"""
SDL CSV parser.

Loads a SentinelOne SDL telemetry export and normalizes column names to a
canonical schema. Handles both dot-notation (event.time, src.process.name) and
DVQL-style PascalCase (EventTime, ProcessName) column variants.

Adds two computed columns to the returned DataFrame:
  _timestamp : tz-aware datetime
  _row_id    : stable integer id
"""
from __future__ import annotations

import pandas as pd
from pathlib import Path
from typing import Dict, List


# Canonical name -> ordered list of possible source column names.
# Order matters: first match wins. DVQL-style names checked alongside SDL schema.
COLUMN_ALIASES: Dict[str, List[str]] = {
    # Time / event meta
    "event_time":      ["event.time", "EventTime", "eventTime", "@timestamp", "timestamp", "event.timestamp"],
    "event_type":      ["event.type", "EventType", "eventType", "event.category"],
    "event_category":  ["event.category", "EventCategory"],

    # Endpoint / agent
    "endpoint":        ["endpoint.name", "EndpointName", "agent.name", "AgentName", "computerName", "ComputerName"],
    "endpoint_os":     ["endpoint.os.name", "endpoint.os", "AgentOSName", "OSName", "agent.osName"],
    "site":            ["site.name", "SiteName"],

    # Source process (the actor)
    "proc_name":       ["src.process.name", "ProcessName", "srcProcName", "process.name"],
    "proc_pid":        ["src.process.pid", "Pid", "ProcessId", "srcProcPid", "process.pid"],
    "proc_cmdline":    ["src.process.cmdline", "src.process.cmd.line", "CmdLine", "ProcessCmd",
                        "srcProcCmdLine", "process.cmdline", "process.command_line"],
    "proc_path":       ["src.process.image.path", "src.process.path", "ProcessImagePath",
                        "srcProcImagePath", "process.executable"],
    "proc_sha1":       ["src.process.image.sha1", "src.process.sha1", "SHA1", "ProcessImageSha1",
                        "srcProcImageSha1"],
    "proc_sha256":     ["src.process.image.sha256", "src.process.sha256", "SHA256",
                        "ProcessImageSha256", "srcProcImageSha256"],
    "proc_md5":        ["src.process.image.md5", "MD5", "ProcessImageMd5"],
    "proc_user":       ["src.process.user", "UserName", "User", "srcProcUser", "user.name"],
    "proc_publisher":  ["src.process.publisher", "src.process.signer", "Publisher", "Signer",
                        "srcProcPublisher", "ProcessPublisher"],
    "proc_verified":   ["src.process.verifiedStatus", "src.process.verified.status",
                        "VerifiedStatus", "ProcessVerifiedStatus", "srcProcVerifiedStatus"],
    "proc_uid":        ["src.process.uid", "src.process.unique.id", "ProcessUniqueKey",
                        "srcProcUid"],
    "proc_storyline":  ["src.process.storyline.id", "storyline.id", "StorylineID",
                        "StorylineId", "srcProcStorylineId"],
    "proc_integrity":  ["src.process.integrityLevel", "IntegrityLevel"],

    # Parent process
    "parent_name":     ["src.process.parent.name", "ParentProcessName", "parentName",
                        "process.parent.name"],
    "parent_pid":      ["src.process.parent.pid", "ParentPid", "ParentProcessId", "parentPid"],
    "parent_cmdline":  ["src.process.parent.cmdline", "src.process.parent.cmd.line",
                        "ParentCmdLine", "parentCmdLine"],
    "parent_path":     ["src.process.parent.image.path", "ParentProcessImagePath", "parentPath"],
    "parent_uid":      ["src.process.parent.uid", "ParentProcessUniqueKey", "parentUid"],
    "parent_storyline": ["src.process.parent.storyline.id", "ParentStorylineID"],

    # Target file (file events)
    "tgt_file_path":   ["tgt.file.path", "TgtFilePath", "FilePath", "tgtFilePath", "file.path"],
    "tgt_file_sha1":   ["tgt.file.sha1", "TgtFileSha1", "FileSha1", "tgtFileSha1"],
    "tgt_file_sha256": ["tgt.file.sha256", "TgtFileSha256", "FileSha256", "tgtFileSha256"],
    "tgt_file_size":   ["tgt.file.size", "TgtFileSize", "FileSize"],

    # Target process (cross-process events: injection, handle dup, etc.)
    "tgt_proc_name":   ["tgt.process.name", "TgtProcessName", "tgtProcName"],
    "tgt_proc_pid":    ["tgt.process.pid", "TgtProcessPid", "tgtProcPid"],
    "tgt_proc_cmdline": ["tgt.process.cmdline", "TgtProcessCmdLine"],
    "tgt_proc_uid":    ["tgt.process.uid", "TgtProcessUniqueKey"],

    # Network
    "src_ip":          ["src.ip.address", "SrcIP", "SrcIp", "srcIp", "source.ip"],
    "src_port":        ["src.port.number", "SrcPort", "srcPort", "source.port"],
    "dst_ip":          ["dst.ip.address", "DstIP", "DstIp", "dstIp", "destination.ip"],
    "dst_port":        ["dst.port.number", "DstPort", "dstPort", "destination.port"],
    "net_protocol":    ["event.network.protocolName", "NetworkProtocol", "Protocol", "netProtocol"],
    "net_direction":   ["event.network.direction", "NetworkDirection", "Direction"],

    # URL / DNS
    "url":             ["url.address", "URL", "Url", "http.url"],
    "dns_request":     ["event.dns.request", "dns.request", "DnsRequest", "dnsRequest", "dns.question.name"],
    "dns_response":    ["event.dns.response", "dns.response", "DnsResponse", "dnsResponse"],

    # Registry
    "reg_key":         ["registry.keyPath", "RegistryKeyPath", "registry.path", "regKey"],
    "reg_value":       ["registry.value", "RegistryValue", "regValue"],
    "reg_data":        ["registry.value.data", "RegistryData", "regData"],
    "reg_old_data":    ["registry.value.oldData", "RegistryOldValue"],

    # Module / image load
    "module_path":     ["module.path", "ModulePath", "modulePath"],
    "module_sha1":     ["module.sha1", "ModuleSha1", "moduleSha1"],

    # S1 alerts / behavioral indicators / MITRE — high-signal metadata
    "alert_name":          ["alert.name", "AlertName"],
    "alert_description":   ["alert.description", "AlertDescription"],
    "alert_rule_id":       ["alert.ruleId", "AlertRuleId"],
    "indicator_name":         ["indicator.name", "IndicatorName"],
    "indicator_description":  ["indicator.description", "IndicatorDescription"],
    "indicator_category":     ["indicator.category", "IndicatorCategory"],
    "indicator_metadata":     ["indicator.metadata", "IndicatorMetadata"],
    "mitre_tactic":           ["event.mitreTactic", "MitreTactic"],
    "mitre_technique_id":     ["event.mitreTechnique.id", "MitreTechniqueId"],
    "mitre_technique_name":   ["event.mitreTechnique.name", "MitreTechniqueName"],
    "event_certainty":        ["event.certainty", "EventCertainty"],

    # Login / logon
    "logon_type":      ["login.type", "LoginType", "logonType"],
    "logon_user":      ["login.userName", "LoginUserName", "logonUserName"],
}


def _build_column_map(df_columns: List[str]) -> Dict[str, str]:
    """Return {canonical_name: actual_column_name} for columns present in df."""
    cols_lower = {c.lower(): c for c in df_columns}
    mapping: Dict[str, str] = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias.lower() in cols_lower:
                mapping[canonical] = cols_lower[alias.lower()]
                break
    return mapping


def _parse_timestamps(s: pd.Series) -> pd.Series:
    """
    Auto-detect timestamp format and parse.

    SDL CSV exports may use:
      - ISO 8601 strings: "2026-04-15T14:02:11.123Z"
      - Epoch milliseconds: "1778266023811"  (13 digits)
      - Epoch seconds:      "1778266023"     (10 digits)

    Returns a tz-aware UTC datetime Series with NaT where parsing failed.
    """
    sample = s.dropna().astype(str).head(20)
    if len(sample) == 0:
        return pd.to_datetime(s, errors="coerce", utc=True)

    # All-numeric, 13 digits → epoch milliseconds
    if sample.str.match(r"^\d{13}$").all():
        numeric = pd.to_numeric(s, errors="coerce")
        return pd.to_datetime(numeric, unit="ms", errors="coerce", utc=True)

    # All-numeric, 10 digits → epoch seconds
    if sample.str.match(r"^\d{10}$").all():
        numeric = pd.to_numeric(s, errors="coerce")
        return pd.to_datetime(numeric, unit="s", errors="coerce", utc=True)

    # Otherwise: ISO/dateutil string parse
    return pd.to_datetime(s, errors="coerce", utc=True)


def load_sdl_csv(path: str | Path) -> pd.DataFrame:
    """
    Load and normalize a SentinelOne SDL CSV export.

    Returns a DataFrame with canonical column names. Missing source columns are
    simply absent (not NaN-filled), so downstream code must check for column
    existence with `if 'col' in df.columns`.

    Raises FileNotFoundError if path doesn't exist.
    Raises ValueError if no recognizable timestamp column is found.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")

    # Read everything as string to skip pandas dtype inference; we'll convert as needed.
    df = pd.read_csv(
        path, dtype=str, low_memory=False,
        keep_default_na=False, na_values=["", "NULL", "null", "None", "N/A", "-"],
    )

    col_map = _build_column_map(df.columns.tolist())
    if not col_map:
        raise ValueError(
            "No recognizable SDL columns found. "
            f"Source columns: {df.columns.tolist()[:10]}..."
        )

    # Rename matched columns to canonical names; drop everything else.
    rename_dict = {actual: canonical for canonical, actual in col_map.items()}
    df = df.rename(columns=rename_dict)
    canonical_cols = [c for c in COLUMN_ALIASES if c in df.columns]
    df = df[canonical_cols].copy()

    # NaN -> empty string for all string-typed columns. Downstream code uses
    # `(row.get(col) or "").strip()` which breaks on NaN (NaN is truthy as a float).
    str_cols = [c for c in canonical_cols if c != "event_time"]
    if str_cols:
        df[str_cols] = df[str_cols].fillna("")

    # Stable row id (preserved across filters)
    df["_row_id"] = range(len(df))

    # Timestamp parsing — handle ISO strings, epoch ms, and epoch seconds.
    if "event_time" not in df.columns:
        raise ValueError("No event time column found. Expected one of: event.time, EventTime, @timestamp, timestamp")

    df["_timestamp"] = _parse_timestamps(df["event_time"])
    bad = int(df["_timestamp"].isna().sum())
    if bad > 0:
        # Don't drop silently — surface this so the user knows
        print(f"[WARN] {bad} rows had unparseable timestamps and were dropped")
        df = df.dropna(subset=["_timestamp"]).copy()

    df = df.sort_values("_timestamp").reset_index(drop=True)
    return df


def get_summary(df: pd.DataFrame) -> dict:
    """High-level dataset stats for the report header."""
    summary: dict = {
        "total_events": len(df),
        "time_start":   df["_timestamp"].min() if "_timestamp" in df.columns and len(df) else None,
        "time_end":     df["_timestamp"].max() if "_timestamp" in df.columns and len(df) else None,
        "endpoints":    sorted(df["endpoint"].dropna().unique().tolist()) if "endpoint" in df.columns else [],
        "event_types":  df["event_type"].value_counts().to_dict() if "event_type" in df.columns else {},
        "storylines":   int(df["proc_storyline"].nunique()) if "proc_storyline" in df.columns else 0,
    }
    return summary
