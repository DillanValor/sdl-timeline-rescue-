# _Inbox

Drop SentinelOne SDL CSV exports here, then run:

```cmd
sdl-timeline.bat new "Customer" "case-id" _Inbox\<filename>.csv --open
```

## What's committed to git

The `practice_*.csv` files in this folder are demo data committed to the
repo so new users can practice the workflow with realistic-looking events.
They contain only fictional scenarios (test-net IPs, .example domains,
made-up usernames).

Real client CSVs you drop here are blocked by `.gitignore` and will never
accidentally get committed.

## Try the practice case

```cmd
sdl-timeline.bat new "AcmeNorthwind" "phishing-demo" _Inbox\practice_phishing-infostealer.csv --open
```

This walks the full lifecycle: open -> review report -> fill notes -> close.

What you'll see in the report:

- A clear kill chain: `chrome.exe -> Invoice_Q4_2026.exe -> cmd -> powershell -> WindowsHelper.exe`
- An abuse-cert publisher (`BRIGHT MORNING SOLUTIONS LLC`) flagged as `pub:unfamiliar`
- An unsigned binary running from `AppData\Roaming` (suspicious-path flag)
- Encoded PowerShell with hidden window
- Two SentinelOne Behavioral Indicators with full MITRE mapping:
  - T1555.003 (Credentials from Web Browsers)
  - T1497.001 (Virtualization/Sandbox Evasion: System Checks)
- C2 callback to a TEST-NET IP and exfil to another
- Vendor noise (SentinelAgent, NinjaRMMAgent) auto-suppressed

After running, look at what was created under
`_Active\acmenorthwind\<today>_phishing-demo\` to see the four artifacts
(`source.csv`, `report.html`, `case.json`, `notes.md`).

When done practicing:

```cmd
sdl-timeline.bat close _Active\acmenorthwind\<today>_phishing-demo
```

The folder moves to `_Completed\` as your first archived case.
