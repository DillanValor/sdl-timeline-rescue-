"""
HTML report renderer.

Generates a single self-contained HTML file. No external CDNs, no remote fonts.
All filtering and tree expand/collapse runs in vanilla JS in the browser, so the
file works fully offline.
"""
from __future__ import annotations

import json
import html as _html
import re
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .tree import ProcessNode


def _safe(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and pd.isna(v):
        return ""
    return str(v)


# S1 stuffs literal HTML markup into indicator.description / alert.description
# (MITRE tactic/technique blocks). Strip tags so we get clean readable text in
# the report; keep paragraph/list breaks as line breaks.
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE  = re.compile(r"[ \t]+")
_NL_RE  = re.compile(r"\n{3,}")

def _strip_html(s) -> str:
    if not s:
        return ""
    s = str(s)
    if "<" not in s:
        return s
    # Replace block-level closers with newlines so MITRE sections stay legible
    s = re.sub(r"</(p|li|ul|h\d|div|br)\s*>", "\n", s, flags=re.IGNORECASE)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.IGNORECASE)
    s = _TAG_RE.sub("", s)
    # Decode common entities
    s = s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")
    # Collapse whitespace
    s = _WS_RE.sub(" ", s)
    s = _NL_RE.sub("\n\n", s)
    return s.strip()


def _format_event(row: pd.Series) -> dict:
    """Pick fields relevant to the event's category for compact display."""
    cat = row.get("_category", "unknown")
    base = {
        "ts":          row["_timestamp"].isoformat() if pd.notna(row.get("_timestamp")) else "",
        "event_type":  _safe(row.get("event_type")),
        "category":    cat,
        "endpoint":    _safe(row.get("endpoint")),
        "severity":    row.get("_severity", "low"),
        "flags":       list(row.get("_flags") or []),
        "proc_name":   _safe(row.get("proc_name")),
        "proc_pid":    _safe(row.get("proc_pid")),
        "proc_user":   _safe(row.get("proc_user")),
        "parent_name": _safe(row.get("parent_name")),
        "parent_pid":  _safe(row.get("parent_pid")),
        "storyline":   _safe(row.get("proc_storyline")),
        "detail":      {},
    }

    # Category-specific detail blocks. Always include cmdline for context if present.
    cmdline = _safe(row.get("proc_cmdline"))

    if cat == "process":
        base["detail"] = {
            "cmdline":         cmdline,
            "path":            _safe(row.get("proc_path")),
            "publisher":       _safe(row.get("proc_publisher")),
            "verified":        _safe(row.get("proc_verified")),
            "sha256":          _safe(row.get("proc_sha256")),
            "parent_cmdline":  _safe(row.get("parent_cmdline")),
            "parent_path":     _safe(row.get("parent_path")),
        }
    elif cat == "network":
        base["detail"] = {
            "src":      f"{_safe(row.get('src_ip'))}:{_safe(row.get('src_port'))}".strip(":"),
            "dst":      f"{_safe(row.get('dst_ip'))}:{_safe(row.get('dst_port'))}".strip(":"),
            "protocol": _safe(row.get("net_protocol")),
            "direction": _safe(row.get("net_direction")),
            "cmdline":  cmdline,
        }
    elif cat == "dns":
        base["detail"] = {
            "request":  _safe(row.get("dns_request")),
            "response": _safe(row.get("dns_response")),
            "cmdline":  cmdline,
        }
    elif cat == "file":
        base["detail"] = {
            "path":    _safe(row.get("tgt_file_path")),
            "sha256":  _safe(row.get("tgt_file_sha256")),
            "sha1":    _safe(row.get("tgt_file_sha1")),
            "size":    _safe(row.get("tgt_file_size")),
            "cmdline": cmdline,
        }
    elif cat == "registry":
        base["detail"] = {
            "key":      _safe(row.get("reg_key")),
            "value":    _safe(row.get("reg_value")),
            "data":     _safe(row.get("reg_data")),
            "old_data": _safe(row.get("reg_old_data")),
            "cmdline":  cmdline,
        }
    elif cat == "module":
        base["detail"] = {
            "module":  _safe(row.get("module_path")),
            "sha1":    _safe(row.get("module_sha1")),
            "cmdline": cmdline,
        }
    elif cat == "injection":
        base["detail"] = {
            "tgt_proc": _safe(row.get("tgt_proc_name")),
            "tgt_pid":  _safe(row.get("tgt_proc_pid")),
            "tgt_cmdline": _safe(row.get("tgt_proc_cmdline")),
            "cmdline":  cmdline,
        }
    elif cat == "logon":
        base["detail"] = {
            "logon_type": _safe(row.get("logon_type")),
            "logon_user": _safe(row.get("logon_user")),
        }
    elif cat == "detection":
        base["detail"] = {
            "indicator":         _safe(row.get("indicator_name")),
            "indicator_desc":    _strip_html(row.get("indicator_description")),
            "indicator_cat":     _safe(row.get("indicator_category")),
            "alert":             _safe(row.get("alert_name")),
            "alert_desc":        _strip_html(row.get("alert_description")),
            "mitre_tactic":      _safe(row.get("mitre_tactic")),
            "mitre_technique":   _safe(row.get("mitre_technique_name")),
            "mitre_id":          _safe(row.get("mitre_technique_id")),
            "cmdline":           cmdline,
            "path":              _safe(row.get("proc_path")),
        }
    else:
        base["detail"] = {
            "cmdline": cmdline,
            "path":    _safe(row.get("proc_path")),
        }

    # Universal: surface alert / MITRE / indicator metadata on ANY event that has them
    extras = {
        "alert":           _safe(row.get("alert_name")),
        "mitre_tactic":    _safe(row.get("mitre_tactic")),
        "mitre_technique": _safe(row.get("mitre_technique_name")),
        "indicator":       _safe(row.get("indicator_name")),
    }
    for k, v in extras.items():
        if v and k not in base["detail"]:
            base["detail"][k] = v

    base["detail"] = {k: v for k, v in base["detail"].items() if v}
    return base


# ============================================================
# CSS — tactical/utilitarian dark console aesthetic.
# ============================================================
_CSS = r"""
:root {
  --bg:           #0a0e14;
  --surface:      #11161d;
  --surface-2:    #161c24;
  --surface-hi:   #1d242e;
  --border:       #2a323d;
  --border-hi:    #3a4452;
  --text:         #d8dee9;
  --text-strong:  #eceff4;
  --muted:        #6b7785;
  --accent:       #ffaa44;          /* tactical amber */
  --accent-soft:  rgba(255,170,68,0.12);
  --link:         #88c0d0;

  --sev-noise:    #4c5562;
  --sev-low:      #6cbf6c;
  --sev-medium:   #e0b341;
  --sev-high:     #e75857;

  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display",
               "Segoe UI", system-ui, "Helvetica Neue", sans-serif;
  --font-mono: "JetBrains Mono", "Cascadia Mono", "Cascadia Code",
               ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-sans);
  font-size: 13px;
  line-height: 1.45;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

/* ---------- Header ---------- */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 14px 24px;
  position: sticky; top: 0; z-index: 50;
  display: flex; justify-content: space-between; align-items: center;
}
header .brand {
  display: flex; align-items: baseline; gap: 12px;
}
header h1 {
  margin: 0; font-size: 14px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 1.5px;
  color: var(--text-strong);
}
header .brand .accent {
  width: 6px; height: 14px; background: var(--accent); display: inline-block;
}
header .meta {
  display: flex; gap: 18px; color: var(--muted); font-size: 11px;
  font-family: var(--font-mono);
}
header .meta .source { color: var(--text); }

/* ---------- Main layout ---------- */
main { max-width: 1500px; margin: 0 auto; padding: 24px; }
section { margin-bottom: 28px; }
h2 {
  font-size: 11px; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1.5px;
  margin: 0 0 12px; padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: baseline;
}
h2 .count { color: var(--text); font-weight: 500; letter-spacing: 0; text-transform: none; font-size: 12px; }

/* ---------- Summary cards ---------- */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 14px 16px;
}
.card .label {
  font-size: 10px; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1px;
  margin-bottom: 8px;
}
.card .value {
  font-family: var(--font-mono); font-size: 22px; font-weight: 500;
  color: var(--text-strong);
}
.card .sub {
  font-size: 11px; color: var(--muted); margin-top: 6px;
  font-family: var(--font-mono); word-break: break-all;
}
.card.sev-high .value   { color: var(--sev-high); }
.card.sev-medium .value { color: var(--sev-medium); }
.card.sev-low .value    { color: var(--sev-low); }

/* ---------- Filter bar ---------- */
#filters {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 14px 16px;
  display: flex; flex-wrap: wrap; gap: 18px; align-items: center;
  position: sticky; top: 50px; z-index: 40;
}
.filter-group {
  display: flex; gap: 8px; align-items: center;
}
.filter-group .label {
  font-size: 10px; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1px;
}
.toggle {
  padding: 4px 10px;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  cursor: pointer;
  font-size: 11px;
  font-family: var(--font-mono);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  user-select: none;
  transition: background 80ms, border-color 80ms, color 80ms;
}
.toggle:hover { border-color: var(--border-hi); }
.toggle.active { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }
.toggle.sev-noise.active   { background: rgba(76,85,98,0.18);  border-color: var(--sev-noise);  color: var(--sev-noise); }
.toggle.sev-low.active     { background: rgba(108,191,108,0.12); border-color: var(--sev-low);    color: var(--sev-low); }
.toggle.sev-medium.active  { background: rgba(224,179,65,0.12);  border-color: var(--sev-medium); color: var(--sev-medium); }
.toggle.sev-high.active    { background: rgba(231,88,87,0.12);   border-color: var(--sev-high);   color: var(--sev-high); }

input[type="search"] {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px 10px;
  flex: 1; min-width: 220px;
  font-family: var(--font-mono);
  font-size: 12px;
}
input[type="search"]:focus { outline: 1px solid var(--accent); border-color: var(--accent); }

/* ---------- Process trees ---------- */
.storyline {
  background: var(--surface);
  border: 1px solid var(--border);
  margin-bottom: 10px;
}
.storyline > summary {
  list-style: none;
  cursor: pointer;
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text);
  user-select: none;
  display: flex; align-items: center; gap: 12px;
  border-bottom: 1px solid transparent;
}
.storyline[open] > summary { border-bottom-color: var(--border); }
.storyline > summary::-webkit-details-marker { display: none; }
.storyline > summary::before {
  content: "▸"; color: var(--muted); width: 10px; display: inline-block;
  transition: transform 100ms;
}
.storyline[open] > summary::before { content: "▾"; }
.storyline > summary .sid { color: var(--accent); }
.storyline > summary .roll {
  margin-left: auto; display: flex; gap: 6px;
}
.tree { padding: 12px 14px; }
.tree-node {
  padding: 4px 0 4px 14px;
  border-left: 2px solid var(--border);
  position: relative;
  margin-left: 4px;
}
.tree-node.sev-high   { border-left-color: var(--sev-high); }
.tree-node.sev-medium { border-left-color: var(--sev-medium); }
.tree-node.sev-low    { border-left-color: var(--sev-low); }
.tree-node.sev-noise  { border-left-color: var(--sev-noise); opacity: 0.65; }
.tree-children { padding-left: 14px; }
.tree-row {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  font-family: var(--font-mono); font-size: 12px;
  padding: 2px 0;
}
.tree-row .pname { color: var(--text-strong); font-weight: 500; }
.tree-row .pid { color: var(--muted); }
.tree-row .ec { color: var(--muted); font-size: 10px; }
.tree-cmdline {
  color: var(--muted);
  font-family: var(--font-mono);
  font-size: 11px;
  padding-left: 0;
  margin-top: 1px;
  word-break: break-all;
  white-space: pre-wrap;
}

/* ---------- Timeline ---------- */
.event {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left-width: 3px;
  margin-bottom: 3px;
  cursor: pointer;
  transition: background 60ms;
}
.event:hover { background: var(--surface-2); }
.event.sev-high   { border-left-color: var(--sev-high); }
.event.sev-medium { border-left-color: var(--sev-medium); }
.event.sev-low    { border-left-color: var(--sev-low); }
.event.sev-noise  { border-left-color: var(--sev-noise); opacity: 0.55; }
.event-line {
  display: flex; align-items: center; gap: 10px;
  padding: 6px 12px;
  font-size: 12px;
  flex-wrap: wrap;
}
.event-line .ts { font-family: var(--font-mono); font-size: 11px; color: var(--muted); min-width: 165px; }
.event-line .ep { color: var(--link); font-family: var(--font-mono); font-size: 11px; }
.event-line .pname { font-family: var(--font-mono); color: var(--text-strong); }
.event-line .pname .pid { color: var(--muted); font-weight: normal; }
.event-line .et { color: var(--muted); font-size: 11px; }
.event-detail {
  display: none;
  padding: 8px 12px 12px 12px;
  border-top: 1px solid var(--border);
  background: var(--bg);
}
.event.expanded .event-detail { display: block; }
.detail-grid {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 4px 12px;
  font-family: var(--font-mono); font-size: 11px;
}
.detail-grid .k {
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-size: 10px;
  padding-top: 2px;
}
.detail-grid .v { color: var(--text); word-break: break-all; white-space: pre-wrap; }

/* ---------- Badges & pills ---------- */
.pill {
  display: inline-block;
  padding: 1px 6px;
  font-size: 10px;
  font-family: var(--font-mono);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border: 1px solid currentColor;
  background: transparent;
}
.pill.sev-noise  { color: var(--sev-noise); }
.pill.sev-low    { color: var(--sev-low); }
.pill.sev-medium { color: var(--sev-medium); }
.pill.sev-high   { color: var(--sev-high); }
.pill.cat {
  color: var(--link);
  border-color: rgba(136,192,208,0.4);
}
.flag {
  display: inline-block;
  padding: 1px 5px;
  font-size: 9px;
  font-family: var(--font-mono);
  background: rgba(231,88,87,0.08);
  color: var(--sev-high);
  border: 1px solid rgba(231,88,87,0.3);
  text-transform: lowercase;
  letter-spacing: 0.3px;
}

/* ---------- Empty state ---------- */
.empty {
  padding: 40px;
  text-align: center;
  color: var(--muted);
  font-style: italic;
  border: 1px dashed var(--border);
}

/* ---------- Footer ---------- */
footer {
  border-top: 1px solid var(--border);
  padding: 16px 24px;
  color: var(--muted);
  font-size: 11px;
  font-family: var(--font-mono);
  text-align: center;
}

/* ---------- Scrollbar ---------- */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); }
::-webkit-scrollbar-thumb:hover { background: var(--border-hi); }
"""


# ============================================================
# JS — runs after DATA constants are defined
# ============================================================
_JS = r"""
(function() {
  const STATE = {
    severities: new Set(['low', 'medium', 'high']),  // 'noise' off by default
    categories: new Set(),                            // empty = all
    search: '',
  };

  const SEV_COLOR = { noise: 'sev-noise', low: 'sev-low', medium: 'sev-medium', high: 'sev-high' };

  function escapeHTML(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtTime(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      const pad = (n, w=2) => String(n).padStart(w, '0');
      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ` +
             `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(),3)}`;
    } catch (_) { return iso; }
  }

  // ----- Summary -----
  function renderSummary() {
    const el = document.getElementById('summary-grid');
    const sevCounts = { noise: 0, low: 0, medium: 0, high: 0 };
    EVENTS.forEach(e => { sevCounts[e.severity] = (sevCounts[e.severity] || 0) + 1; });

    const tStart = SUMMARY.time_start ? fmtTime(SUMMARY.time_start) : '—';
    const tEnd   = SUMMARY.time_end   ? fmtTime(SUMMARY.time_end)   : '—';

    const epList = (SUMMARY.endpoints || []).slice(0, 3).join(', ');
    const epSub = SUMMARY.endpoints.length > 3 ? `${epList}, +${SUMMARY.endpoints.length - 3} more` : epList;

    el.innerHTML = `
      <div class="card"><div class="label">Total Events</div><div class="value">${SUMMARY.total.toLocaleString()}</div><div class="sub">in dataset</div></div>
      <div class="card sev-high"><div class="label">High</div><div class="value">${sevCounts.high}</div><div class="sub">${pct(sevCounts.high, SUMMARY.total)}</div></div>
      <div class="card sev-medium"><div class="label">Medium</div><div class="value">${sevCounts.medium}</div><div class="sub">${pct(sevCounts.medium, SUMMARY.total)}</div></div>
      <div class="card sev-low"><div class="label">Low</div><div class="value">${sevCounts.low}</div><div class="sub">${pct(sevCounts.low, SUMMARY.total)}</div></div>
      <div class="card"><div class="label">Storylines</div><div class="value">${SUMMARY.storylines}</div><div class="sub">distinct chains</div></div>
      <div class="card"><div class="label">Endpoints</div><div class="value">${SUMMARY.endpoints.length}</div><div class="sub">${escapeHTML(epSub)}</div></div>
      <div class="card"><div class="label">Window Start</div><div class="value" style="font-size:13px">${escapeHTML(tStart)}</div></div>
      <div class="card"><div class="label">Window End</div><div class="value" style="font-size:13px">${escapeHTML(tEnd)}</div></div>
    `;
  }

  function pct(n, total) {
    if (!total) return '0%';
    return ((n / total) * 100).toFixed(1) + '%';
  }

  // ----- Filters -----
  function renderFilters() {
    // Severity toggles
    const sevWrap = document.getElementById('filter-sev');
    ['noise', 'low', 'medium', 'high'].forEach(s => {
      const btn = document.createElement('button');
      btn.className = 'toggle ' + SEV_COLOR[s];
      btn.dataset.sev = s;
      btn.textContent = s;
      if (STATE.severities.has(s)) btn.classList.add('active');
      btn.addEventListener('click', () => {
        if (STATE.severities.has(s)) STATE.severities.delete(s);
        else STATE.severities.add(s);
        btn.classList.toggle('active');
        renderTimeline();
      });
      sevWrap.appendChild(btn);
    });

    // Category toggles
    const catWrap = document.getElementById('filter-cat');
    const cats = [...new Set(EVENTS.map(e => e.category))].sort();
    cats.forEach(c => {
      const btn = document.createElement('button');
      btn.className = 'toggle';
      btn.dataset.cat = c;
      btn.textContent = c;
      btn.addEventListener('click', () => {
        if (STATE.categories.has(c)) STATE.categories.delete(c);
        else STATE.categories.add(c);
        btn.classList.toggle('active');
        renderTimeline();
      });
      catWrap.appendChild(btn);
    });

    document.getElementById('filter-search').addEventListener('input', (ev) => {
      STATE.search = ev.target.value.toLowerCase();
      renderTimeline();
    });
  }

  // ----- Timeline -----
  function passesFilters(e) {
    if (!STATE.severities.has(e.severity)) return false;
    if (STATE.categories.size > 0 && !STATE.categories.has(e.category)) return false;
    if (STATE.search) {
      // Build a search blob lazily once per event
      if (!e._searchBlob) {
        e._searchBlob = (
          e.proc_name + ' ' + e.parent_name + ' ' + e.event_type + ' ' +
          e.endpoint + ' ' + (e.flags || []).join(' ') + ' ' +
          Object.values(e.detail || {}).join(' ')
        ).toLowerCase();
      }
      if (!e._searchBlob.includes(STATE.search)) return false;
    }
    return true;
  }

  function renderTimeline() {
    const events = EVENTS.filter(passesFilters);
    const container = document.getElementById('timeline-list');
    document.getElementById('timeline-count').textContent =
      `${events.length.toLocaleString()} of ${EVENTS.length.toLocaleString()} events shown`;

    if (events.length === 0) {
      container.innerHTML = '<div class="empty">No events match current filters.</div>';
      return;
    }

    // Render in chunks for large datasets
    const HARD_CAP = 5000;
    const slice = events.slice(0, HARD_CAP);
    const html = slice.map(renderEvent).join('');
    container.innerHTML = html;
    if (events.length > HARD_CAP) {
      container.insertAdjacentHTML('beforeend',
        `<div class="empty">Display capped at ${HARD_CAP.toLocaleString()}. Refine filters to see more.</div>`);
    }

    // Wire up click-to-expand
    container.querySelectorAll('.event').forEach(row => {
      row.addEventListener('click', () => row.classList.toggle('expanded'));
    });
  }

  function renderEvent(e) {
    const flags = (e.flags || []).map(f => `<span class="flag">${escapeHTML(f)}</span>`).join(' ');
    const detail = Object.entries(e.detail || {}).map(([k, v]) =>
      `<div class="k">${escapeHTML(k)}</div><div class="v">${escapeHTML(v)}</div>`
    ).join('');
    const parentLine = e.parent_name
      ? `<div class="k">parent</div><div class="v">${escapeHTML(e.parent_name)} <span style="color:var(--muted)">(pid ${escapeHTML(e.parent_pid)})</span></div>`
      : '';
    const userLine = e.proc_user
      ? `<div class="k">user</div><div class="v">${escapeHTML(e.proc_user)}</div>`
      : '';
    const slLine = e.storyline
      ? `<div class="k">storyline</div><div class="v" style="color:var(--accent)">${escapeHTML(e.storyline)}</div>`
      : '';

    return `
      <div class="event ${SEV_COLOR[e.severity]}">
        <div class="event-line">
          <span class="ts">${escapeHTML(fmtTime(e.ts))}</span>
          <span class="pill ${SEV_COLOR[e.severity]}">${escapeHTML(e.severity)}</span>
          <span class="pill cat">${escapeHTML(e.category)}</span>
          <span class="ep">${escapeHTML(e.endpoint)}</span>
          <span class="pname">${escapeHTML(e.proc_name)} <span class="pid">(${escapeHTML(e.proc_pid)})</span></span>
          <span class="et">${escapeHTML(e.event_type)}</span>
          ${flags}
        </div>
        <div class="event-detail">
          <div class="detail-grid">
            ${parentLine}
            ${userLine}
            ${slLine}
            ${detail}
          </div>
        </div>
      </div>
    `;
  }

  // ----- Process trees -----
  function renderTrees() {
    const container = document.getElementById('tree-container');
    const sids = Object.keys(STORYLINES);
    if (sids.length === 0) {
      container.innerHTML = '<div class="empty">No storylines in dataset.</div>';
      return;
    }

    // Sort storylines by max severity (high first), then earliest event
    const sorted = sids.map(sid => {
      const roots = STORYLINES[sid];
      const maxSev = computeMaxSev(roots);
      const earliest = computeEarliest(roots);
      return { sid, roots, maxSev, earliest };
    }).sort((a, b) => {
      const sevOrder = { high: 3, medium: 2, low: 1, noise: 0 };
      const d = (sevOrder[b.maxSev] || 0) - (sevOrder[a.maxSev] || 0);
      if (d !== 0) return d;
      return (a.earliest || '').localeCompare(b.earliest || '');
    });

    container.innerHTML = sorted.map(({ sid, roots, maxSev }) => {
      const sidShort = sid.length > 32 ? sid.substring(0, 32) + '…' : sid;
      const isOpen = maxSev === 'high' || maxSev === 'medium' ? 'open' : '';
      return `
        <details class="storyline" ${isOpen}>
          <summary>
            <span>storyline:</span><span class="sid">${escapeHTML(sidShort)}</span>
            <span class="roll">
              <span class="pill ${SEV_COLOR[maxSev]}">${escapeHTML(maxSev)}</span>
              <span class="pill cat">${roots.length} root${roots.length === 1 ? '' : 's'}</span>
            </span>
          </summary>
          <div class="tree">${roots.map(r => renderNode(r, 0)).join('')}</div>
        </details>
      `;
    }).join('');
  }

  function computeMaxSev(roots) {
    const sevOrder = { noise: 0, low: 1, medium: 2, high: 3 };
    let max = 'noise';
    function walk(n) {
      if ((sevOrder[n.severity] || 0) > (sevOrder[max] || 0)) max = n.severity;
      (n.children || []).forEach(walk);
    }
    roots.forEach(walk);
    return max;
  }
  function computeEarliest(roots) {
    let earliest = null;
    function walk(n) {
      if (n.first_seen && (!earliest || n.first_seen < earliest)) earliest = n.first_seen;
      (n.children || []).forEach(walk);
    }
    roots.forEach(walk);
    return earliest;
  }

  function renderNode(n, depth) {
    const flags = (n.flags || []).slice(0, 6).map(f =>
      `<span class="flag">${escapeHTML(f)}</span>`).join(' ');
    const verifiedBadge = n.verified
      ? `<span class="pill cat" style="font-size:9px">${escapeHTML(n.verified)}</span>`
      : '';
    const cmdline = (n.cmdline || n.path || '').trim();
    const cmdlineHTML = cmdline ? `<div class="tree-cmdline">${escapeHTML(cmdline)}</div>` : '';
    const childrenHTML = (n.children || []).length
      ? `<div class="tree-children">${n.children.map(c => renderNode(c, depth + 1)).join('')}</div>`
      : '';
    return `
      <div class="tree-node ${SEV_COLOR[n.severity]}">
        <div class="tree-row">
          <span class="pill ${SEV_COLOR[n.severity]}">${escapeHTML(n.severity)}</span>
          <span class="pname">${escapeHTML(n.name || '(unknown)')}</span>
          <span class="pid">pid ${escapeHTML(n.pid)}</span>
          <span class="ec">${n.event_count} event${n.event_count === 1 ? '' : 's'}</span>
          ${verifiedBadge}
          ${flags}
        </div>
        ${cmdlineHTML}
        ${childrenHTML}
      </div>
    `;
  }

  // ----- Boot -----
  renderSummary();
  renderFilters();
  renderTrees();
  renderTimeline();
})();
"""


def render(df: pd.DataFrame, storylines: Dict[str, List[ProcessNode]],
           summary: dict, output_path: str | Path,
           source_name: str = "SDL Export") -> Path:
    """Build the HTML report and write it to disk. Returns the output Path."""
    output_path = Path(output_path)

    events = [_format_event(row) for _, row in df.iterrows()]
    storyline_data = {sid: [n.to_dict() for n in nodes] for sid, nodes in storylines.items()}

    summary_data = {
        "total":      summary.get("total_events", 0),
        "time_start": summary["time_start"].isoformat() if summary.get("time_start") is not None else "",
        "time_end":   summary["time_end"].isoformat() if summary.get("time_end") is not None else "",
        "endpoints":  summary.get("endpoints", []),
        "event_types": summary.get("event_types", {}),
        "storylines": summary.get("storylines", 0),
    }

    # Embed data as JSON literals
    events_json     = json.dumps(events,         default=str, separators=(",", ":"))
    storylines_json = json.dumps(storyline_data, default=str, separators=(",", ":"))
    summary_json    = json.dumps(summary_data,   default=str, separators=(",", ":"))

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SDL Timeline — {_html.escape(source_name)}</title>
<style>{_CSS}</style>
</head>
<body>

<header>
  <div class="brand"><span class="accent"></span><h1>SDL Timeline</h1></div>
  <div class="meta">
    <span class="source">{_html.escape(source_name)}</span>
    <span>generated {_html.escape(generated)}</span>
  </div>
</header>

<main>

  <section>
    <h2>Summary</h2>
    <div id="summary-grid" class="summary-grid"></div>
  </section>

  <section id="filters">
    <div class="filter-group"><span class="label">Severity</span><div id="filter-sev" style="display:flex;gap:6px"></div></div>
    <div class="filter-group"><span class="label">Category</span><div id="filter-cat" style="display:flex;gap:6px;flex-wrap:wrap"></div></div>
    <div class="filter-group" style="flex:1;min-width:240px"><span class="label">Search</span>
      <input type="search" id="filter-search" placeholder="process, hash, ip, domain, flag..." />
    </div>
  </section>

  <section>
    <h2>Process Trees by Storyline <span class="count">click any storyline to expand</span></h2>
    <div id="tree-container"></div>
  </section>

  <section>
    <h2>Event Timeline <span class="count" id="timeline-count">—</span></h2>
    <div id="timeline-list"></div>
  </section>

</main>

<footer>
  sdl-timeline · self-contained report · all filtering runs locally in your browser · no data left this machine
</footer>

<script>
const EVENTS     = {events_json};
const STORYLINES = {storylines_json};
const SUMMARY    = {summary_json};
{_JS}
</script>
</body>
</html>
"""
    output_path.write_text(page, encoding="utf-8")
    return output_path
