"""
Case management for sdl-timeline.

A "case" is a folder containing:
  - source.csv       The original SDL export (immutable after `new`)
  - report.html      Generated kill-chain timeline
  - case.json        Metadata + extracted IOCs for cross-case correlation
  - notes.md         Free-form analyst notes (created empty, edit by hand)

Lifecycle:
  new   → creates folder under _Active/<Customer>/<date>_<case_id>/
  close → moves the folder to _Completed/<Customer>/<date>_<case_id>/
  list  → enumerates open or closed cases
  info  → shows metadata for a single case

The folder layout makes performance-review reporting and cross-tenant IOC
correlation tractable: every case is structured the same way, so a separate
tool (`correlate`) can walk the tree and aggregate.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd


def _slugify(s: str) -> str:
    """Make a filesystem-safe slug. Keeps alnum, dash, underscore. Lowercases."""
    out = []
    for ch in s.strip().lower():
        if ch.isalnum() or ch in "-_":
            out.append(ch)
        elif ch in " ":
            out.append("-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-_") or "case"


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _extract_iocs(df: pd.DataFrame) -> dict:
    """
    Pull out durable indicators from the analyzed DataFrame.
    Used both for the case.json file and for cross-tenant correlation.
    """
    iocs: dict = {
        "hashes_sha256": [],
        "hashes_sha1":   [],
        "ips":           [],
        "domains":       [],
        "urls":          [],
        "file_paths":    [],
        "publishers":    [],
    }

    def _add(key: str, value):
        if value is None:
            return
        v = str(value).strip()
        if not v or v.lower() in ("nan", "none", "null"):
            return
        if v not in iocs[key]:
            iocs[key].append(v)

    if "proc_sha256" in df.columns:
        for v in df["proc_sha256"].dropna().unique():
            _add("hashes_sha256", v)
    if "tgt_file_sha256" in df.columns:
        for v in df["tgt_file_sha256"].dropna().unique():
            _add("hashes_sha256", v)
    if "proc_sha1" in df.columns:
        for v in df["proc_sha1"].dropna().unique():
            _add("hashes_sha1", v)
    if "tgt_file_sha1" in df.columns:
        for v in df["tgt_file_sha1"].dropna().unique():
            _add("hashes_sha1", v)

    # Network IOCs — only collect from non-noise events that actually went out
    if "_severity" in df.columns:
        sig = df[df["_severity"].isin(["medium", "high"])]
    else:
        sig = df

    if "dst_ip" in sig.columns:
        for v in sig["dst_ip"].dropna().unique():
            # Skip RFC1918 — internal IPs aren't useful as cross-tenant IOCs
            v_str = str(v).strip()
            if not v_str or v_str.startswith(("10.", "192.168.", "127.")):
                continue
            if v_str.startswith("172."):
                try:
                    second = int(v_str.split(".")[1])
                    if 16 <= second <= 31:
                        continue
                except (ValueError, IndexError):
                    pass
            _add("ips", v_str)

    if "dns_request" in sig.columns:
        for v in sig["dns_request"].dropna().unique():
            _add("domains", v)
    if "url" in sig.columns:
        for v in sig["url"].dropna().unique():
            _add("urls", v)

    # Suspicious-path file writes (interesting for cross-tenant correlation —
    # same dropper writes same-named payloads at multiple customers)
    if "tgt_file_path" in sig.columns:
        for v in sig["tgt_file_path"].dropna().unique():
            v_str = str(v).strip()
            if v_str:
                _add("file_paths", v_str)

    # Publishers — tracking abuse-cert reuse across tenants is high-value
    if "proc_publisher" in df.columns and "_flags" in df.columns:
        for _, row in df.iterrows():
            flags = row.get("_flags") or []
            if "pub:unfamiliar" in flags:
                pub = row.get("proc_publisher")
                if pub:
                    _add("publishers", pub)

    return iocs


def _build_case_metadata(df: pd.DataFrame, customer: str, case_id: str,
                        case_dir: Path, source_csv: Path) -> dict:
    """Assemble the case.json contents."""
    sev_counts = {"high": 0, "medium": 0, "low": 0, "noise": 0}
    if "_severity" in df.columns:
        for s in df["_severity"]:
            sev_counts[s] = sev_counts.get(s, 0) + 1

    endpoints = sorted(df["endpoint"].dropna().unique().tolist()) if "endpoint" in df.columns else []
    users = sorted(df["proc_user"].dropna().unique().tolist()) if "proc_user" in df.columns else []
    storylines = sorted(df["proc_storyline"].dropna().unique().tolist()) if "proc_storyline" in df.columns else []

    high_severity_procs = []
    if "_severity" in df.columns and "proc_name" in df.columns:
        high_df = df[df["_severity"] == "high"]
        if "proc_name" in high_df.columns:
            high_severity_procs = sorted(high_df["proc_name"].dropna().unique().tolist())

    time_start = df["_timestamp"].min() if "_timestamp" in df.columns and len(df) else None
    time_end   = df["_timestamp"].max() if "_timestamp" in df.columns and len(df) else None

    meta = {
        "schema_version":  1,
        "customer":        customer,
        "case_id":         case_id,
        "date_opened":     _today(),
        "date_closed":     None,
        "status":          "active",
        "source_csv":      source_csv.name,
        "event_count":     len(df),
        "severity_counts": sev_counts,
        "time_range": {
            "start": time_start.isoformat() if time_start is not None else None,
            "end":   time_end.isoformat()   if time_end   is not None else None,
        },
        "endpoints":            endpoints,
        "users":                users,
        "storylines":           storylines,
        "high_severity_procs":  high_severity_procs,
        "iocs":                 _extract_iocs(df),
    }
    return meta


# ============================================================
# Case lifecycle commands
# ============================================================

def new_case(customer: str, case_name: str, csv_path: Path,
             root: Path, open_report: bool = False) -> Path:
    """
    Create a new active case. Runs the analysis pipeline and writes:
      _Active/<Customer>/<YYYY-MM-DD>_<slug>/source.csv
      _Active/<Customer>/<YYYY-MM-DD>_<slug>/report.html
      _Active/<Customer>/<YYYY-MM-DD>_<slug>/case.json
      _Active/<Customer>/<YYYY-MM-DD>_<slug>/notes.md (empty stub)

    Returns the case directory path.
    """
    # Local imports — avoid pulling pandas at module-import time during help()
    from .parser import load_sdl_csv, get_summary
    from .classifier import classify
    from .heuristics import analyze
    from .tree import build_storylines
    from .render import render

    csv_path = Path(csv_path).expanduser().resolve()
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    customer_slug = _slugify(customer)
    case_slug = _slugify(case_name)
    case_id = f"{_today()}_{case_slug}"

    case_dir = root / "_Active" / customer_slug / case_id
    if case_dir.exists():
        raise FileExistsError(
            f"Case folder already exists: {case_dir}\n"
            f"Pick a different name or delete the existing folder first."
        )
    case_dir.mkdir(parents=True, exist_ok=False)

    # Copy CSV in (rather than move; user may want to keep a working copy)
    dest_csv = case_dir / "source.csv"
    shutil.copy2(csv_path, dest_csv)

    # Run pipeline
    df = load_sdl_csv(dest_csv)
    df = classify(df)
    df = analyze(df)
    # Drop noise from the rendered report but keep them in the metadata counts
    df_for_render = df[~df["_is_noise"]].copy() if "_is_noise" in df.columns else df
    storylines = build_storylines(df_for_render)
    summary = get_summary(df_for_render)
    report_path = case_dir / "report.html"
    render(df_for_render, storylines, summary, report_path,
           source_name=f"{customer} — {case_name}")

    # Write metadata (against the FULL df so noise counts are honest)
    meta = _build_case_metadata(df, customer, case_id, case_dir, csv_path)
    (case_dir / "case.json").write_text(
        json.dumps(meta, indent=2, default=str), encoding="utf-8"
    )

    # Notes stub
    notes = (
        f"# Case Notes — {customer} / {case_id}\n\n"
        f"**Source CSV:** `{csv_path.name}`  \n"
        f"**Opened:** {_today()}  \n"
        f"**Events:** {meta['event_count']}  "
        f"({meta['severity_counts'].get('high', 0)} high, "
        f"{meta['severity_counts'].get('medium', 0)} medium)\n\n"
        f"## Hypothesis\n\n_what do you think happened?_\n\n"
        f"## Findings\n\n_what did the timeline show?_\n\n"
        f"## Actions Taken\n\n_- [ ] _\n\n"
        f"## Outcome\n\n_resolved how?_\n"
    )
    (case_dir / "notes.md").write_text(notes, encoding="utf-8")

    if open_report:
        import webbrowser
        webbrowser.open(report_path.as_uri())

    return case_dir


def close_case(case_dir: Path, root: Path) -> Path:
    """
    Move an active case to _Completed/. Updates case.json status.
    Returns the new case dir path.
    """
    case_dir = Path(case_dir).expanduser().resolve()
    if not case_dir.exists():
        raise FileNotFoundError(f"Case folder not found: {case_dir}")
    if not (case_dir / "case.json").exists():
        raise ValueError(f"Not a valid case folder (no case.json): {case_dir}")

    # Update metadata
    meta_path = case_dir / "case.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["status"] = "closed"
    meta["date_closed"] = _today()
    meta_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")

    # Compute destination — preserve relative structure from _Active
    root = root.resolve()
    try:
        rel = case_dir.relative_to(root / "_Active")
    except ValueError:
        # Case folder isn't under _Active — fall back to flat customer/case
        customer = meta.get("customer", "_unknown")
        rel = Path(_slugify(customer)) / case_dir.name

    dest = root / "_Completed" / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise FileExistsError(f"Destination already exists: {dest}")
    shutil.move(str(case_dir), str(dest))
    return dest


def list_cases(root: Path, customer: Optional[str] = None,
               status: str = "active") -> list[dict]:
    """
    Return list of case metadata dicts. status='active'|'closed'|'all'.
    """
    if status == "active":
        bases = [root / "_Active"]
    elif status == "closed":
        bases = [root / "_Completed"]
    else:
        bases = [root / "_Active", root / "_Completed"]

    out: list[dict] = []
    for base in bases:
        if not base.exists():
            continue
        for case_json in base.rglob("case.json"):
            try:
                meta = json.loads(case_json.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if customer and _slugify(meta.get("customer", "")) != _slugify(customer):
                continue
            meta["_path"] = str(case_json.parent)
            out.append(meta)

    # Sort newest first
    out.sort(key=lambda m: m.get("date_opened", ""), reverse=True)
    return out
