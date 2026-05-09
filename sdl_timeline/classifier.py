"""
Event classification.

Buckets each row into a high-level category so the renderer knows which fields
to show. SDL has dozens of event.type values; we collapse them to ~10 useful
buckets.
"""
from __future__ import annotations

import pandas as pd
from typing import Optional


# event.type substring -> category. First substring match wins.
EVENT_TYPE_RULES: list[tuple[str, str]] = [
    # Order matters: more specific patterns first.

    # S1's own detection events — gold-tier signal
    ("behavioral indicators",   "detection"),
    ("pre execution detection", "detection"),
    ("threat detection",        "detection"),
    ("threat killed",           "detection"),
    ("threat mitigated",        "detection"),
    ("indicator",               "detection"),

    ("remote thread",        "injection"),
    ("process injection",    "injection"),
    ("duplicate process",    "injection"),
    ("duplicate token",      "injection"),
    ("open process",         "injection"),

    ("process creation",     "process"),
    ("process exit",         "process"),
    ("process termination",  "process"),

    ("dns",                  "dns"),

    ("tcp",                  "network"),
    ("udp",                  "network"),
    ("ip connect",           "network"),
    ("ip listen",            "network"),
    ("http request",         "network"),

    ("file creation",        "file"),
    ("file modification",    "file"),
    ("file deletion",        "file"),
    ("file rename",          "file"),
    ("file scan",            "file"),

    ("registry",             "registry"),

    ("module load",          "module"),
    ("image load",           "module"),

    ("login",                "logon"),
    ("logout",               "logon"),
    ("logon",                "logon"),

    ("task ",                "task"),
    ("scheduled task",       "task"),
]


def _classify_one(et: Optional[str]) -> str:
    if not et or pd.isna(et):
        return "unknown"
    et_lower = str(et).lower().strip()
    # Bare HTTP verbs come through SDL as just "GET" / "POST" — bucket as network
    if et_lower in ("get", "post", "put", "delete", "head", "patch", "options"):
        return "network"
    for needle, cat in EVENT_TYPE_RULES:
        if needle in et_lower:
            return cat
    return "other"


def classify(df: pd.DataFrame) -> pd.DataFrame:
    """Add a `_category` column to the DataFrame."""
    df = df.copy()
    if "event_type" not in df.columns:
        df["_category"] = "unknown"
        return df
    df["_category"] = df["event_type"].apply(_classify_one)
    return df
