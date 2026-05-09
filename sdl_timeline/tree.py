"""
Process tree reconstruction.

S1 provides StorylineID which groups causally-related events. Within a
storyline, parent/child PID (or process UID) relationships build the tree.
Roots = nodes that aren't anyone's child within the dataset.
"""
from __future__ import annotations

import pandas as pd
from typing import Dict, List, Optional


SEVERITY_ORDER = {"noise": 0, "low": 1, "medium": 2, "high": 3}


class ProcessNode:
    __slots__ = (
        "name", "pid", "uid", "cmdline", "path", "publisher", "verified",
        "user", "children", "event_count", "flags", "severity",
        "first_seen", "last_seen",
    )

    def __init__(self, name: str = "", pid: str = "", uid: str = "",
                 cmdline: str = "", path: str = "", publisher: str = "",
                 verified: str = "", user: str = ""):
        self.name = name
        self.pid = pid
        self.uid = uid
        self.cmdline = cmdline
        self.path = path
        self.publisher = publisher
        self.verified = verified
        self.user = user
        self.children: List[ProcessNode] = []
        self.event_count = 0
        self.flags: List[str] = []
        self.severity = "low"
        self.first_seen: Optional[pd.Timestamp] = None
        self.last_seen: Optional[pd.Timestamp] = None

    def to_dict(self) -> dict:
        # Roll severity up: a parent is at least as severe as its children
        child_dicts = [c.to_dict() for c in self.children]
        max_child_sev = "noise"
        for c in child_dicts:
            if SEVERITY_ORDER.get(c["severity"], 1) > SEVERITY_ORDER.get(max_child_sev, 0):
                max_child_sev = c["severity"]
        rolled = self.severity
        if SEVERITY_ORDER.get(max_child_sev, 0) > SEVERITY_ORDER.get(rolled, 1):
            rolled = max_child_sev
        return {
            "name": self.name,
            "pid": self.pid,
            "uid": self.uid,
            "cmdline": self.cmdline,
            "path": self.path,
            "publisher": self.publisher,
            "verified": self.verified,
            "user": self.user,
            "event_count": self.event_count,
            "flags": sorted(set(self.flags)),
            "severity": rolled,
            "self_severity": self.severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen is not None else None,
            "last_seen":  self.last_seen.isoformat() if self.last_seen is not None else None,
            "children": child_dicts,
        }


def _node_key(uid: str, pid: str, name: str) -> str:
    """Stable identity for a process. Prefer uid (S1's process unique id)."""
    if uid:
        return f"uid:{uid}"
    return f"pid:{pid}:{name.lower()}"


def _build_tree_for_subset(df: pd.DataFrame) -> List[ProcessNode]:
    nodes: Dict[str, ProcessNode] = {}

    # First pass: create or update a node for the source process of every event
    for _, row in df.iterrows():
        proc_name = row.get("proc_name") or ""
        proc_pid  = str(row.get("proc_pid") or "")
        proc_uid  = str(row.get("proc_uid") or "")
        if not proc_name and not proc_pid:
            continue

        key = _node_key(proc_uid, proc_pid, proc_name)
        node = nodes.get(key)
        if node is None:
            node = ProcessNode(
                name=proc_name,
                pid=proc_pid,
                uid=proc_uid,
                cmdline=row.get("proc_cmdline") or "",
                path=row.get("proc_path") or "",
                publisher=row.get("proc_publisher") or "",
                verified=row.get("proc_verified") or "",
                user=row.get("proc_user") or "",
            )
            nodes[key] = node

        node.event_count += 1
        ts = row.get("_timestamp")
        if ts is not None and pd.notna(ts):
            if node.first_seen is None or ts < node.first_seen:
                node.first_seen = ts
            if node.last_seen is None or ts > node.last_seen:
                node.last_seen = ts

        flags = row.get("_flags") or []
        if flags:
            node.flags.extend(flags)

        sev = row.get("_severity", "low")
        if SEVERITY_ORDER.get(sev, 1) > SEVERITY_ORDER.get(node.severity, 1):
            node.severity = sev

    # Second pass: link children to parents
    children_keys: set[str] = set()
    for _, row in df.iterrows():
        proc_name   = row.get("proc_name") or ""
        proc_pid    = str(row.get("proc_pid") or "")
        proc_uid    = str(row.get("proc_uid") or "")
        parent_name = row.get("parent_name") or ""
        parent_pid  = str(row.get("parent_pid") or "")
        parent_uid  = str(row.get("parent_uid") or "")

        if not (proc_name or proc_pid):
            continue
        if not (parent_name or parent_pid):
            continue

        child_key  = _node_key(proc_uid, proc_pid, proc_name)
        parent_key = _node_key(parent_uid, parent_pid, parent_name)

        if parent_key == child_key:
            continue  # self-loop guard

        # Materialize parent if we haven't seen it as a source process
        if parent_key not in nodes:
            nodes[parent_key] = ProcessNode(
                name=parent_name,
                pid=parent_pid,
                uid=parent_uid,
                cmdline=row.get("parent_cmdline") or "",
                path=row.get("parent_path") or "",
            )

        parent_node = nodes[parent_key]
        child_node  = nodes[child_key]

        if child_node not in parent_node.children:
            parent_node.children.append(child_node)
        children_keys.add(child_key)

    # Roots are anything not claimed as a child
    roots = [n for k, n in nodes.items() if k not in children_keys]

    # Sort children chronologically within each node for readable trees
    def _sort_children(node: ProcessNode):
        node.children.sort(
            key=lambda n: (n.first_seen if n.first_seen is not None else pd.Timestamp.max)
        )
        for c in node.children:
            _sort_children(c)
    for r in roots:
        _sort_children(r)
    roots.sort(key=lambda n: (n.first_seen if n.first_seen is not None else pd.Timestamp.max))

    return roots


def build_storylines(df: pd.DataFrame) -> Dict[str, List[ProcessNode]]:
    """
    Return {storyline_id: [root_node, ...]}.
    If no storyline column exists, returns a single bucket keyed '_no_storyline'.
    """
    if "proc_storyline" not in df.columns:
        return {"_no_storyline": _build_tree_for_subset(df)}

    storylines: Dict[str, List[ProcessNode]] = {}
    for sid, group in df.groupby("proc_storyline", dropna=False):
        key = str(sid) if pd.notna(sid) else "_no_storyline"
        storylines[key] = _build_tree_for_subset(group)
    return storylines
