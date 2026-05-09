#!/usr/bin/env python3
"""
sdl-timeline: SentinelOne SDL CSV -> kill-chain HTML report + case management.

Runs entirely locally. No data leaves the machine.

Subcommands:
  analyze   One-shot mode: CSV in, HTML out (no case folder)
  new       Open a new case for a customer (creates folder + report + IOCs)
  close     Mark a case complete (move from _Active to _Completed)
  list      List active or closed cases
  info      Show metadata for a single case

Examples:
  sdl-timeline analyze investigation.csv
  sdl-timeline new "GarlandSales" "rachel-pup" _Inbox\\investigation.csv --open
  sdl-timeline list
  sdl-timeline list --closed GarlandSales
  sdl-timeline close _Active\\garlandsales\\2026-05-08_rachel-pup
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sdl_timeline.parser import load_sdl_csv, get_summary
from sdl_timeline.classifier import classify
from sdl_timeline.heuristics import analyze as analyze_df
from sdl_timeline.tree import build_storylines
from sdl_timeline.render import render
from sdl_timeline import case as case_mod


def _default_root() -> Path:
    """Toolkit root: $SDL_TOOLKIT_ROOT, else the directory containing cli.py."""
    import os
    if env := os.environ.get("SDL_TOOLKIT_ROOT"):
        return Path(env).expanduser().resolve()
    return Path(__file__).parent.resolve()


def cmd_analyze(args) -> int:
    csv_path = args.csv.expanduser().resolve()
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found", file=sys.stderr)
        return 1

    output = args.output or csv_path.with_suffix(".html")
    output = output.expanduser().resolve()

    def info(msg):
        if not args.quiet:
            print(msg)

    info(f"[*] Loading {csv_path.name}...")
    try:
        df = load_sdl_csv(csv_path)
    except Exception as e:
        print(f"ERROR: failed to parse CSV: {e}", file=sys.stderr)
        return 2
    info(f"[*] Loaded {len(df):,} events")

    info("[*] Classifying events...")
    df = classify(df)

    info("[*] Running heuristics...")
    df = analyze_df(df)

    if not args.include_noise:
        before = len(df)
        df = df[~df["_is_noise"]].copy()
        info(f"[*] Suppressed {before - len(df):,} noise events ({len(df):,} remaining)")

    info("[*] Building process trees...")
    storylines = build_storylines(df)

    info("[*] Rendering report...")
    summary = get_summary(df)
    out_path = render(df, storylines, summary, output, source_name=csv_path.name)

    print(f"[+] Report written: {out_path}")
    print(f"    Open with: file://{out_path}")
    return 0


def cmd_new(args) -> int:
    root = args.root or _default_root()
    try:
        case_dir = case_mod.new_case(
            customer=args.customer,
            case_name=args.name,
            csv_path=args.csv,
            root=root,
            open_report=args.open,
        )
    except (FileNotFoundError, FileExistsError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: failed to open case: {e}", file=sys.stderr)
        return 2

    print(f"[+] Case opened: {case_dir}")
    print(f"    report.html  -> {case_dir / 'report.html'}")
    print(f"    case.json    -> {case_dir / 'case.json'}")
    print(f"    notes.md     -> edit this with your findings")
    return 0


def cmd_close(args) -> int:
    root = args.root or _default_root()
    case_dir = args.case.expanduser().resolve()
    try:
        new_path = case_mod.close_case(case_dir, root=root)
    except (FileNotFoundError, FileExistsError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"[+] Case closed: {new_path}")
    return 0


def cmd_list(args) -> int:
    root = args.root or _default_root()
    if args.closed:
        status = "closed"
    elif args.all:
        status = "all"
    else:
        status = "active"

    cases = case_mod.list_cases(root, customer=args.customer, status=status)
    if not cases:
        scope = f"{status} cases"
        if args.customer:
            scope += f" for {args.customer}"
        print(f"No {scope} found under {root}")
        return 0

    header = f"{'CUSTOMER':<24} {'CASE':<35} {'OPENED':<11} {'STATUS':<8} {'EVT':>5} {'HI':>3} {'MED':>4}"
    print(header)
    print("-" * len(header))
    for c in cases:
        sev = c.get("severity_counts", {})
        row = (
            f"{c.get('customer', '?')[:23]:<24} "
            f"{c.get('case_id', '?')[:34]:<35} "
            f"{c.get('date_opened', '?'):<11} "
            f"{c.get('status', '?'):<8} "
            f"{c.get('event_count', 0):>5} "
            f"{sev.get('high', 0):>3} "
            f"{sev.get('medium', 0):>4}"
        )
        print(row)
    print()
    print(f"{len(cases)} case(s)")
    return 0


def cmd_info(args) -> int:
    case_dir = args.case.expanduser().resolve()
    meta_path = case_dir / "case.json"
    if not meta_path.exists():
        print(f"ERROR: no case.json in {case_dir}", file=sys.stderr)
        return 1
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    print(json.dumps(meta, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="sdl-timeline",
        description="SDL kill-chain timeline + case management. Runs locally - nothing leaves your machine.",
    )
    sub = p.add_subparsers(dest="cmd")

    p_an = sub.add_parser("analyze", help="One-shot: CSV -> HTML report (no case folder)")
    p_an.add_argument("csv", type=Path)
    p_an.add_argument("-o", "--output", type=Path, default=None)
    p_an.add_argument("--include-noise", action="store_true")
    p_an.add_argument("--quiet", action="store_true")
    p_an.set_defaults(func=cmd_analyze)

    p_new = sub.add_parser("new", help="Open a new case for a customer")
    p_new.add_argument("customer", type=str, help="Customer name")
    p_new.add_argument("name", type=str, help="Short case identifier (e.g. 'rachel-pup')")
    p_new.add_argument("csv", type=Path, help="Path to the SDL CSV export")
    p_new.add_argument("--root", type=Path, default=None,
                       help="Toolkit root (default: cli.py's directory or $SDL_TOOLKIT_ROOT)")
    p_new.add_argument("--open", action="store_true", help="Open report in browser when done")
    p_new.set_defaults(func=cmd_new)

    p_cl = sub.add_parser("close", help="Move an active case to _Completed/")
    p_cl.add_argument("case", type=Path, help="Path to the case folder under _Active/")
    p_cl.add_argument("--root", type=Path, default=None)
    p_cl.set_defaults(func=cmd_close)

    p_ls = sub.add_parser("list", help="List cases")
    p_ls.add_argument("customer", type=str, nargs="?", default=None,
                      help="Filter by customer name (optional)")
    p_ls.add_argument("--closed", action="store_true", help="Show closed cases instead of active")
    p_ls.add_argument("--all", action="store_true", help="Show both active and closed")
    p_ls.add_argument("--root", type=Path, default=None)
    p_ls.set_defaults(func=cmd_list)

    p_in = sub.add_parser("info", help="Show metadata for a single case")
    p_in.add_argument("case", type=Path, help="Path to the case folder")
    p_in.set_defaults(func=cmd_info)

    # Backwards compat: bare CSV path -> analyze
    if (len(sys.argv) >= 2
        and sys.argv[1] not in {"analyze", "new", "close", "list", "info", "-h", "--help"}
        and Path(sys.argv[1]).suffix.lower() == ".csv"):
        sys.argv.insert(1, "analyze")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
