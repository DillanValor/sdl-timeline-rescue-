# Toolkit Setup & Workflow

The deploy target is a self-contained folder on your work machine — no installers, no PATH changes, no admin rights, no PyInstaller. You move the folder, the toolkit moves with it.

## One-time setup

### 1. Pick a location
Anywhere your user has write access. Recommended: `C:\Tools\SDL-Toolkit\`.

### 2. Drop the code in
Clone or copy this repository so the layout looks like:

```
C:\Tools\SDL-Toolkit\
├── cli.py
├── sdl-timeline.bat
├── requirements.txt
├── sdl_timeline\           (the package)
└── examples\               (the synthetic test CSV)
```

### 3. Provide Python (two options)

**Option A — bundled portable Python (preferred):**
1. Download the [Python 3.12 or 3.13 embeddable distribution](https://www.python.org/downloads/windows/) for Windows x64. It's a ZIP file labelled "Windows embeddable package".
2. Extract it into a `python\` subfolder so you have `C:\Tools\SDL-Toolkit\python\python.exe`.
3. The embeddable distribution doesn't ship pip by default. Bootstrap it:
   ```cmd
   cd C:\Tools\SDL-Toolkit
   curl -o python\get-pip.py https://bootstrap.pypa.io/get-pip.py
   python\python.exe python\get-pip.py
   ```
4. Edit `python\python3XX._pth` (where XX matches your Python version, e.g. `python313._pth`) so it contains:
   ```
   python3XX.zip
   .
   ..

   import site
   ```
   The `..` line is critical — it adds the toolkit root to sys.path so the `sdl_timeline` package can be imported. The `import site` line lets pip-installed packages be found.
5. Install pandas:
   ```cmd
   python\python.exe -m pip install pandas
   ```

You now have a fully self-contained Python that lives inside the toolkit folder and won't conflict with anything else on the machine.

**Option B — system Python:**
If you already have Python 3.10+ on your PATH:
```cmd
cd C:\Tools\SDL-Toolkit
pip install -r requirements.txt
```
The launcher will fall back to `python` from PATH if no bundled `python\` folder is present.

### 4. Create your inbox
```cmd
mkdir _Inbox
```
The `_Active\` and `_Completed\` folders are created automatically as soon as you open your first case.

### 5. Smoke test
```cmd
sdl-timeline.bat analyze examples\synthetic_sdl.csv
```
This generates `examples\synthetic_sdl.html`. Open it to confirm everything works.

---

## Daily workflow

### Open a case
S1 alert fires, you pull a DVQL export, save the CSV to `_Inbox\`. Then:

```cmd
sdl-timeline.bat new "GarlandSales" "rachel-pup-investigation" _Inbox\search-results.csv --open
```

This:
1. Creates `_Active\garlandsales\<today>_rachel-pup-investigation\`
2. Copies the CSV in as `source.csv`
3. Runs the full pipeline → writes `report.html`
4. Extracts IOCs (hashes, IPs, domains, URLs, file paths, suspicious publishers) → writes `case.json`
5. Drops a `notes.md` template for your written analysis
6. Opens the report in your browser (because of `--open`)

### Track work in progress
```cmd
sdl-timeline.bat list
```

```
CUSTOMER                 CASE                                OPENED      STATUS     EVT  HI  MED
------------------------------------------------------------------------------------------------
GarlandSales             2026-05-08_rachel-pup-invest…       2026-05-08  active      66  16   50
ClientB                  2026-05-08_suspicious-rdp           2026-05-08  active     412   3   18
```

Filter by customer:
```cmd
sdl-timeline.bat list GarlandSales
```

### Inspect a case
```cmd
sdl-timeline.bat info _Active\garlandsales\2026-05-08_rachel-pup-investigation
```
Dumps the case.json — useful when you need a quick stats summary for an email or ticket update.

### Close a case
After investigation is done, notes.md is filled in:

```cmd
sdl-timeline.bat close _Active\garlandsales\2026-05-08_rachel-pup-investigation
```

The whole folder moves to `_Completed\garlandsales\...`. Status flips to `closed`, `date_closed` is stamped.

### Performance review prep
```cmd
sdl-timeline.bat list --closed
sdl-timeline.bat list --closed GarlandSales
```

Pipe to a file for review docs:
```cmd
sdl-timeline.bat list --all > investigations-2026.txt
```

---

## What `case.json` enables

Each closed case carries a structured fingerprint:

```json
{
  "customer": "GarlandSales",
  "case_id": "2026-05-08_rachel-pup-investigation",
  "date_opened": "2026-05-08",
  "date_closed": "2026-05-09",
  "status": "closed",
  "event_count": 66,
  "severity_counts": {"high": 16, "medium": 50, "low": 0, "noise": 0},
  "endpoints": ["RachelEaton-PC"],
  "users": ["RACHELEATON-PC\\Rachel Eaton"],
  "storylines": ["9AE78B9B1C7386DA"],
  "high_severity_procs": ["SetupMyPDFConvert_838248.exe", "SetupMyPDFConvert_838248.tmp"],
  "iocs": {
    "hashes_sha256": ["4cc1b7c878...", "..."],
    "ips":           ["104.26.7.244", "..."],
    "domains":       ["softwarefirstrun.com", "..."],
    "urls":          ["..."],
    "file_paths":    ["C:\\Users\\...\\Temp\\is-RLN5N8OOEM.tmp", "..."],
    "publishers":    ["DISPLAY NETWORK REVOLUTIONS LLC"]
  }
}
```

Because every case has the same shape, a future `correlate` subcommand can walk `_Completed\` and surface things like:

- **Same hash at multiple customers** — a piece of malware spreading across your tenant base
- **Same abuse-cert publisher across customers** — campaign attribution
- **Repeat-offender users** — `Rachel Eaton` showing up in 3 PUP cases probably needs awareness training
- **Same C2 domain across investigations** — actor infrastructure reuse
- **Per-customer monthly stats** — "Customer X had N high-severity investigations this quarter"

That last one is the performance-review angle: a structured dataset of every investigation you've conducted, queryable by customer, time, severity, IOC type. Nothing manual to maintain — it's a side effect of using the tool the way it's designed.

---

## A note on AV/EDR and PyInstaller

The original ask was "can we wrap this into an .exe." The clean answer is yes, but PyInstaller binaries are heavily abused by malware authors (PrivateLoader, Rhadamanthys, common infostealer families) and your EDR — including SentinelOne — flags them aggressively on heuristic and reputation grounds. You'd be running unsigned PyInstaller binaries on managed endpoints, which is the exact thing you'd flag a user for doing.

The portable-Python + .bat-launcher approach in this doc gives you the same UX (double-click or single command, no install needed) without any of the AV friction. If your org ever wants a true signed .exe, code-sign it with their certificate — but for one analyst's tooling, the .bat is the right level of effort.

---

## Privacy

The output `report.html` embeds the source event data as JSON inside the file. Treat it with the same sensitivity as the source CSV. Same goes for `case.json` — it contains client hostnames, usernames, and IOCs. Keep `_Active\` and `_Completed\` on encrypted storage.

The toolkit makes zero network calls, has no telemetry, and reads/writes only inside its own folder.
