# sdl-timeline

MIT Licenses

Convert SentinelOne SDL CSV exports into interactive kill-chain HTML reports.
Runs **entirely locally** — nothing ever leaves your machine.

Built for triaging hunting exports too noisy to read line-by-line in Excel.

---

## What it does

Parses an SDL CSV export, then for each event:

- Classifies it (process, network, dns, file, registry, module, injection, logon, task)
- Picks only the columns relevant to that event type (no more 100-column horizontal scrolling)
- Reconstructs process trees per S1 storyline using parent/child PID/UID
- Flags interesting indicators: LOLBins, suspicious paths/cmdlines, ransomware
  precursors, credential access patterns, defense evasion
- Marks well-known signed Microsoft binaries and MSP RMM/EDR vendor processes
  (SentinelOne, NinjaOne, ScreenConnect, Blackpoint, Huntress, Halcyon, etc.)
  as noise so they're suppressed by default

Outputs a single self-contained HTML file: dark tactical theme, severity
color-coded, click any event to expand full detail, click any storyline to
expand its process tree, filter by severity / category / freetext search — all
runs in the browser, no server, no CDN.

## Install

See `WORKFLOW.md` for the full toolkit-style deployment (portable Python,
case management, daily workflow). For a minimal install:

```bash
cd sdl-timeline
pip install -r requirements.txt
```

Only dep is pandas. Python 3.10+.

## Usage

One-shot mode:
```bash
python cli.py analyze path/to/sdl_export.csv
```

Case-managed mode (recommended for real investigations):
```bash
python cli.py new "CustomerName" "case-id" path/to/sdl_export.csv --open
python cli.py list
python cli.py close _Active/customername/2026-05-09_case-id
```

## What it expects in the CSV

The parser handles two SDL column naming conventions:

- **Dot-notation** (raw SDL schema): `event.time`, `src.process.name`,
  `src.process.cmdline`, `src.process.parent.name`, `tgt.file.path`,
  `dst.ip.address`, `src.process.storyline.id`, etc.
- **DVQL-style PascalCase**: `EventTime`, `ProcessName`, `CmdLine`,
  `ParentProcessName`, `FilePath`, `DstIP`, `StorylineID`, etc.

If your export uses different names, add an alias to
`sdl_timeline/parser.py:COLUMN_ALIASES` — first match wins per canonical field.

A timestamp column is required. Everything else is optional but more columns =
better triage.

## Severity rubric

| Level    | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| `noise`  | Known-good vendor or signed Microsoft system process, no other flags.   |
| `low`    | Routine event, no flags raised.                                         |
| `medium` | 2+ heuristic flags, single moderately-suspicious indicator, or any event from a process that fired a high-severity Behavioral Indicator |
| `high`   | High-signal indicator (encoded PowerShell, shadow copy delete, mimikatz, certutil download, LOLBin from suspicious path, S1 Behavioral Indicator) |

Noise is dropped from the data by default.

<img width="1879" height="710" alt="image" src="https://github.com/user-attachments/assets/786f56ea-e42a-403d-b202-bc4af7e680a0" />



## Privacy

The HTML output embeds your event data as JSON inside the file. **Treat the
output file with the same sensitivity as the source CSV** — keep it on
encrypted storage, share via the same channels you'd use for the raw export.

The tool itself makes zero network calls and has no telemetry.

## Project layout

```
sdl-timeline/
├── cli.py                          # CLI entry point
├── sdl-timeline.bat                # Windows launcher
├── requirements.txt
├── README.md
├── WORKFLOW.md                     # Full deployment + case workflow doc
└── sdl_timeline/                   # Importable as a package
    ├── __init__.py
    ├── parser.py                   # CSV → normalized DataFrame
    ├── classifier.py               # event_type → category
    ├── heuristics.py               # LOLBin / cmdline / path / publisher / vendor flags
    ├── tree.py                     # Process tree reconstruction
    ├── render.py                   # Self-contained HTML output
    └── case.py                     # Case lifecycle (new/close/list)
```
