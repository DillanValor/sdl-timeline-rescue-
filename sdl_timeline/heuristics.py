"""
Heuristic analysis.

Flags rows for "interesting" indicators (LOLBins, suspicious paths/cmdlines)
and marks rows as noise so they can be suppressed by default. The MSP-aware
vendor list comes from the sigma-threat-hunting skill.
"""
from __future__ import annotations

import re
import pandas as pd


# ---------- LOLBins (lolbas-project.github.io subset) ----------
LOLBINS = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "forfiles.exe", "pcalua.exe", "mavinject.exe",
    "odbcconf.exe", "cmstp.exe", "control.exe", "ieexec.exe", "esentutl.exe",
    "expand.exe", "extexport.exe", "extrac32.exe", "findstr.exe", "finger.exe",
    "hh.exe", "ie4uinit.exe", "infdefaultinstall.exe", "makecab.exe", "msiexec.exe",
    "netsh.exe", "print.exe", "replace.exe", "runonce.exe", "scriptrunner.exe",
    "syncappvpublishingserver.exe", "verclsid.exe", "xwizard.exe",
    "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "msdt.exe", "wsl.exe", "bash.exe", "atbroker.exe", "diskshadow.exe",
}


# ---------- Suspicious path patterns (process running from / file written to) ----------
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\\Users\\[^\\]+\\AppData\\Roaming\\", re.IGNORECASE),
    re.compile(r"\\Users\\[^\\]+\\AppData\\Local\\Temp\\", re.IGNORECASE),
    re.compile(r"\\Users\\Public\\", re.IGNORECASE),
    # ProgramData but exclude well-known vendor subdirs
    re.compile(r"\\ProgramData\\(?!Microsoft\\|Sentinel|NinjaRMM|ScreenConnect|BPSAgent|Huntress|Halcyon|Datto|connectwise|McAfee|Symantec|CrowdStrike|chocolatey)",
               re.IGNORECASE),
    re.compile(r"\\Windows\\Temp\\", re.IGNORECASE),
    re.compile(r"\\Users\\[^\\]+\\Downloads\\.*\.(exe|dll|ps1|bat|vbs|js|hta|lnk|scr|jar|iso|img|vhd)$", re.IGNORECASE),
    re.compile(r"\\\$Recycle\.Bin\\", re.IGNORECASE),
    re.compile(r"\\PerfLogs\\", re.IGNORECASE),
    re.compile(r"\\Intel\\Logs\\.*\.(exe|dll)$", re.IGNORECASE),  # known fileless persistence loc
]


# ---------- Suspicious cmdline patterns: (regex, label) ----------
SUSPICIOUS_CMDLINE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE), "ps:encoded-command"),
    (re.compile(r"\s-w(indowstyle)?\s+hidden\b", re.IGNORECASE),                "ps:hidden-window"),
    (re.compile(r"\s-nop(rofile)?\b", re.IGNORECASE),                           "ps:no-profile"),
    (re.compile(r"\s-nonI(nteractive)?\b", re.IGNORECASE),                      "ps:non-interactive"),
    (re.compile(r"\s-execu?t?i?o?n?p?o?l?i?c?y?\s+bypass", re.IGNORECASE),       "ps:exec-bypass"),
    (re.compile(r"IEX\s*\(", re.IGNORECASE),                                    "ps:invoke-expression"),
    (re.compile(r"Invoke-Expression", re.IGNORECASE),                           "ps:invoke-expression"),
    (re.compile(r"DownloadString", re.IGNORECASE),                              "ps:download-string"),
    (re.compile(r"DownloadFile", re.IGNORECASE),                                "ps:download-file"),
    (re.compile(r"FromBase64String", re.IGNORECASE),                            "base64-decode"),
    (re.compile(r"New-Object\s+Net\.WebClient", re.IGNORECASE),                 "ps:webclient"),
    (re.compile(r"Invoke-WebRequest|iwr\b", re.IGNORECASE),                     "ps:webrequest"),
    (re.compile(r"certutil\b.*-(decode|urlcache|encode)", re.IGNORECASE),       "lolbin:certutil"),
    (re.compile(r"bitsadmin\b.*\/transfer", re.IGNORECASE),                     "lolbin:bitsadmin-transfer"),
    (re.compile(r"wmic\b.*process.*call.*create", re.IGNORECASE),               "lolbin:wmic-create"),
    (re.compile(r"rundll32\b.*javascript:", re.IGNORECASE),                     "lolbin:rundll32-js"),
    (re.compile(r"mshta\b.*https?:", re.IGNORECASE),                            "lolbin:mshta-remote"),
    (re.compile(r"regsvr32\b.*scrobj\.dll", re.IGNORECASE),                     "lolbin:regsvr32-squiblydoo"),
    (re.compile(r"reg\s+add\b.*\\Run\\?", re.IGNORECASE),                       "persistence:run-key"),
    (re.compile(r"schtasks\b.*\/create", re.IGNORECASE),                        "persistence:schtask-create"),
    (re.compile(r"net\s+user\s+\S+\s+\S+\s+\/add", re.IGNORECASE),              "persistence:user-create"),
    (re.compile(r"net\s+localgroup\s+admin\S*\s+\S+\s+\/add", re.IGNORECASE),   "persistence:admin-add"),
    (re.compile(r"vssadmin(?:\.exe)?\b.*delete\s+shadows", re.IGNORECASE),     "ransom:shadow-delete"),
    (re.compile(r"wmic(?:\.exe)?\b.*shadowcopy\s+delete", re.IGNORECASE),       "ransom:shadow-delete"),
    (re.compile(r"wbadmin(?:\.exe)?\b.*delete", re.IGNORECASE),                 "ransom:backup-delete"),
    (re.compile(r"bcdedit(?:\.exe)?\b.*recoveryenabled\s+no", re.IGNORECASE),   "ransom:recovery-disable"),
    (re.compile(r"cipher(?:\.exe)?\s+\/w", re.IGNORECASE),                      "ransom:cipher-wipe"),
    (re.compile(r"fsutil(?:\.exe)?\b.*usn\s+deletejournal", re.IGNORECASE),     "evasion:usn-delete"),
    (re.compile(r"wevtutil(?:\.exe)?\s+(cl|sl)\b", re.IGNORECASE),              "evasion:eventlog-clear"),
    (re.compile(r"Clear-EventLog", re.IGNORECASE),                              "evasion:eventlog-clear"),
    (re.compile(r"netsh(?:\.exe)?\b.*advfirewall.*off", re.IGNORECASE),         "evasion:firewall-disable"),
    (re.compile(r"Set-MpPreference.*Disable", re.IGNORECASE),                   "evasion:defender-disable"),
    (re.compile(r"\\(adfind|advanced_ip_scanner|netscan|softperfect)", re.IGNORECASE), "discovery:net-recon"),
    (re.compile(r"\b(mimikatz|sekurlsa|kerberos::|crypto::|lsadump)", re.IGNORECASE), "credaccess:mimikatz"),
    (re.compile(r"ntdsutil.*ifm", re.IGNORECASE),                               "credaccess:ntds-dump"),
    # LOLBin loading DLL from user-writable path — common DLL-sideload / fileless pattern
    (re.compile(r"rundll32(?:\.exe)?\b.*\\(AppData\\(Local|Roaming)|Temp|Public|ProgramData)\\.*\.dll",
                re.IGNORECASE), "lolbin:rundll32-userpath-dll"),
    (re.compile(r"regsvr32(?:\.exe)?\b.*\\(AppData\\(Local|Roaming)|Temp|Public|ProgramData)\\",
                re.IGNORECASE), "lolbin:regsvr32-userpath"),
]


# ---------- Noise: well-known signed Microsoft binaries (suppress if no flags) ----------
KNOWN_GOOD_NOISE = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "wininit.exe", "smss.exe", "spoolsv.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe", "taskhostw.exe",
    "taskhost.exe", "dwm.exe", "sihost.exe", "fontdrvhost.exe",
    "wuauclt.exe", "trustedinstaller.exe", "msmpeng.exe", "mssense.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "compattelrunner.exe", "ctfmon.exe", "audiodg.exe", "conhost.exe",
    "dllhost.exe", "wmiprvse.exe", "runtimebroker.exe",
    # Office/Edge/Browser autoupdate noise
    "msedge.exe", "msedgewebview2.exe", "officeclicktorun.exe",
    "microsoftedgeupdate.exe", "googleupdate.exe",
}


# ---------- Vendor binaries (always noise; MSP environment context) ----------
KNOWN_VENDOR_NOISE = {
    # SentinelOne agent
    "sentinelagent.exe", "sentinelagentworker.exe", "sentinelhelperservice.exe",
    "sentinelmemoryscanner.exe", "sentinelstaticengine.exe", "sentinelui.exe",
    "sentinelone.exe", "sentinel.exe", "sentinelremoteshell.exe",
    # NinjaOne
    "ninjarmmagent.exe", "ninjarmmagentpatcher.exe", "ninjaone.exe",
    "ninjarmmupdater.exe",
    # ScreenConnect / ConnectWise
    "screenconnect.windowsclient.exe", "screenconnect.windowsbackstageshell.exe",
    "screenconnect.clientservice.exe",
    # ConnectWise Automate
    "connectwiseautomateagent.exe", "ltsvc.exe", "ltsvcmon.exe", "ltechagent.exe",
    # Blackpoint
    "bpsagent.exe", "snapagent.exe", "snap.exe",
    # Halcyon
    "halcyon.exe", "halcyonagent.exe",
    # Huntress
    "huntressagent.exe", "huntressrio.exe", "huntressupdater.exe",
    # Todyl
    "todylagent.exe", "sgnext.exe",
    # Datto
    "datto.exe", "dattormm.exe",
    # Veeam
    "veeam.backup.manager.exe", "veeamagent.exe", "veeamservice.exe",
    # FortiClient
    "forticlient.exe", "fortitray.exe", "fcappdb.exe",
    # DUO
    "duo.exe", "duoauthproxy.exe",
}


# Trusted publishers — signed binaries from these are treated as legit.
# Match is case-insensitive substring against the proc.publisher field.
# Anything signed but not in this list gets a `pub:unfamiliar` flag, which
# catches the abuse-cert / fake-utility-malware pattern (e.g. "DISPLAY NETWORK
# REVOLUTIONS LLC" type publishers).
TRUSTED_PUBLISHERS = {
    "microsoft", "google", "mozilla", "adobe", "apple", "intel", "nvidia", "amd",
    "dell", "hewlett-packard", "hp inc", "lenovo", "vmware", "citrix",
    "oracle", "sun microsystems", "ibm", "amazon", "facebook", "meta",
    "github", "gitlab", "atlassian", "slack", "zoom", "dropbox", "box",
    "logitech", "realtek", "synaptics", "elan", "broadcom", "qualcomm",
    "sentinelone", "sentinel labs", "ninjaone", "ninjarmm", "connectwise",
    "screenconnect", "blackpoint", "huntress", "halcyon", "todyl", "datto",
    "veeam", "fortinet", "fortinet inc", "duo security", "cisco",
    "crowdstrike", "carbonite", "malwarebytes", "kaspersky", "eset",
    "bitdefender", "trend micro", "sophos", "symantec", "norton", "mcafee",
    "comodo", "proofpoint", "barracuda", "mimecast",
    "intuit", "autodesk", "jetbrains", "docker", "hashicorp",
    "paypal", "stripe", "salesforce", "hubspot",
    "valve", "epic games", "blizzard", "ea games", "ubisoft",
    "spotify", "discord",
    "the document foundation",  # LibreOffice
    "python software foundation", "node.js", "npm",
    "open source developer",   # common for OSS projects
    "git for windows", "putty",
}


# Flags that always bump severity to high
HIGH_SIGNAL_FLAGS = {
    "s1:detection",
    "ps:encoded-command", "lolbin:certutil", "lolbin:bitsadmin-transfer",
    "lolbin:regsvr32-squiblydoo", "lolbin:mshta-remote", "lolbin:rundll32-js",
    "lolbin:wmic-create",
    "lolbin:rundll32-userpath-dll", "lolbin:regsvr32-userpath",
    "ransom:shadow-delete", "ransom:backup-delete", "ransom:recovery-disable",
    "ransom:cipher-wipe",
    "evasion:eventlog-clear", "evasion:usn-delete", "evasion:defender-disable",
    "credaccess:mimikatz", "credaccess:ntds-dump",
    "persistence:user-create", "persistence:admin-add",
}


def _scan_row(row: pd.Series) -> tuple[list[str], str, bool]:
    """Return (flags, severity, is_noise) for one event."""
    proc_name = (row.get("proc_name") or "").lower().strip()
    proc_path = (row.get("proc_path") or "").strip()
    cmdline   = (row.get("proc_cmdline") or "").strip()
    publisher = (row.get("proc_publisher") or "").strip()
    verified  = (row.get("proc_verified") or "").lower().strip()
    tgt_file  = (row.get("tgt_file_path") or "").strip()
    category  = (row.get("_category") or "").lower().strip()
    indicator_name = (row.get("indicator_name") or "").strip()
    alert_name     = (row.get("alert_name") or "").strip()

    flags: list[str] = []

    # S1's own detection events: behavioral indicators, pre-exec, threat events.
    # If S1 flagged it, it's high signal regardless of cmdline patterns.
    if category == "detection" or indicator_name or alert_name:
        flags.append("s1:detection")

    if proc_name in LOLBINS:
        flags.append("lolbin")

    if proc_path:
        for pat in SUSPICIOUS_PATH_PATTERNS:
            if pat.search(proc_path):
                flags.append("path:proc-suspicious")
                break

    if tgt_file:
        for pat in SUSPICIOUS_PATH_PATTERNS:
            if pat.search(tgt_file):
                flags.append("path:write-suspicious")
                break

    if cmdline:
        for pat, label in SUSPICIOUS_CMDLINE_PATTERNS:
            if pat.search(cmdline):
                flags.append(label)

    # Unsigned non-vendor binary (the verified field varies — be permissive)
    if verified and verified not in ("signed", "verified", "true", "valid", "ok"):
        if proc_name and proc_name not in KNOWN_VENDOR_NOISE and proc_name not in KNOWN_GOOD_NOISE:
            flags.append("unsigned")

    # Verified-but-unfamiliar publisher: catches abuse-cert / fake-utility malware
    # (e.g. "DISPLAY NETWORK REVOLUTIONS LLC" type publishers from PrivateLoader,
    # FakeBat, and similar info-stealer droppers).
    if publisher and verified in ("signed", "verified", "true", "valid", "ok"):
        pub_lower = publisher.lower()
        if not any(trusted in pub_lower for trusted in TRUSTED_PUBLISHERS):
            # Belt-and-suspenders: don't double-flag if it's a known vendor binary anyway
            if proc_name not in KNOWN_VENDOR_NOISE and proc_name not in KNOWN_GOOD_NOISE:
                flags.append("pub:unfamiliar")

    # Noise determination — only if there are NO interesting flags
    is_noise = False
    if not flags:
        if proc_name in KNOWN_VENDOR_NOISE:
            is_noise = True
        elif proc_name in KNOWN_GOOD_NOISE and verified in ("signed", "verified", "true", "valid", "ok", ""):
            # Empty verified is common for trusted Microsoft binaries in some exports — treat as OK
            is_noise = True

    # Severity
    if not flags:
        severity = "noise" if is_noise else "low"
    elif any(f in HIGH_SIGNAL_FLAGS for f in flags):
        severity = "high"
    elif "lolbin" in flags and any(f.startswith("path:") or f == "unsigned" for f in flags):
        severity = "high"
    elif len(flags) >= 2:
        severity = "medium"
    else:
        severity = "low"

    return flags, severity, is_noise


def analyze(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add `_flags` (list[str]), `_severity` (str), `_is_noise` (bool) columns.

    After per-row scoring, propagates severity up at the process level: if any
    event from a given process (proc_uid, or pid+name as fallback) is `high`,
    every other event from that same process gets bumped to at least `medium`.
    This catches the case where S1 fires Behavioral Indicators on a process but
    the process's network/file/dns events would otherwise look benign in isolation.
    """
    df = df.copy()
    flags_col: list[list[str]] = []
    sev_col:   list[str] = []
    noise_col: list[bool] = []
    for _, row in df.iterrows():
        f, s, n = _scan_row(row)
        flags_col.append(f)
        sev_col.append(s)
        noise_col.append(n)
    df["_flags"] = flags_col
    df["_severity"] = sev_col
    df["_is_noise"] = noise_col

    # ---- Severity propagation at the process level ----
    sev_order = {"noise": 0, "low": 1, "medium": 2, "high": 3}

    def _proc_key(row) -> str:
        uid = (row.get("proc_uid") or "").strip()
        if uid:
            return f"uid:{uid}"
        pid = str(row.get("proc_pid") or "")
        name = (row.get("proc_name") or "").lower()
        return f"pn:{pid}:{name}"

    if len(df):
        df["_proc_key"] = df.apply(_proc_key, axis=1)
        # Find max severity per proc
        df["_proc_max_sev"] = df.groupby("_proc_key")["_severity"].transform(
            lambda s: max(s, key=lambda x: sev_order.get(x, 0))
        )
        # Bump: if proc max is high, all that proc's events get >= medium.
        # Don't downgrade anything that's already higher than the floor.
        def _bump(row):
            cur = row["_severity"]
            if row["_proc_max_sev"] == "high" and sev_order.get(cur, 0) < sev_order["medium"]:
                # Mark as bumped so the UI/flags list shows it
                new_flags = list(row["_flags"]) + ["proc:tainted-by-detection"]
                return pd.Series({"_severity": "medium", "_flags": new_flags})
            return pd.Series({"_severity": cur, "_flags": row["_flags"]})
        bumped = df.apply(_bump, axis=1)
        df["_severity"] = bumped["_severity"]
        df["_flags"]    = bumped["_flags"]
        df = df.drop(columns=["_proc_key", "_proc_max_sev"])

    return df
