# NSSECU3 MP3: Updated Paper Sections (Code + Narrative)

## Technical Completeness

The implemented parser is technically complete for application execution forensics because it integrates three complementary artifact families: BAM, CAM, and DAM. BAM provides per-user background execution traces from SYSTEM hive BAM keys. CAM provides capability usage telemetry (microphone, webcam, location, and related permissions) from Capability Access Manager ConsentStore paths in both SOFTWARE and NTUSER hives. DAM provides service and driver execution context through ImagePath extraction under Services keys.

The tool supports offline forensic workflows through mounted image analysis and includes resilience features needed in real investigations: multi-path control set fallback, optional transaction-log replay through yarp, defensive error handling, and timestamp sanity checks. Output generation supports operational triage and reporting requirements through JSON, CSV, and Excel formats, with both summary and artifact-specific detail sheets.

## System Implementation

The parser is implemented as a modular pipeline:

1. Discovery layer identifies candidate Windows installations and relevant hive files.
2. Hive open layer applies safe-open behavior and optional LOG1/LOG2 replay.
3. Artifact layer parses BAM, CAM, and DAM with dedicated parser functions.
4. Aggregation layer unifies artifact structures and computes category totals.
5. Reporting layer prints a console summary and exports JSON/CSV/XLSX.

CAM implementation follows CapabilityAccessManager ConsentStore, including packaged and non-packaged applications. BAM and DAM logic uses control-set candidate lists to reduce false negatives caused by registry path variation across systems.

## Code Design

### Code Design: BAM/CAM/DAM Parsing Logic

The code design is function-centric and evidence-oriented. Each parser function has a clear scope:

1. `parse_bam` extracts executable paths, user SID context, and execution timestamps.
2. `parse_cam` extracts capability, app identity, consent state, package type, and last-used times.
3. `parse_dam` extracts service names and executable image paths.

A shared helper layer provides reusable operations for FILETIME decoding, key timestamp extraction, hex conversion, and safe hive handling. The design separates parsing from reporting, allowing consistent export behavior regardless of artifact source.

### Figure 15 Caption (Updated)

Figure 15: Parsing Logic of the BAM/CAM/DAM Forensic Parser.

The parser opens target hives safely, resolves candidate registry paths, extracts and decodes BAM/CAM/DAM artifacts, normalizes evidence fields, and exports structured outputs for forensic interpretation.

## Procedure Steps (Updated)

1. Acquire and mount a forensic image.
2. Detect Windows installations and gather SYSTEM, SOFTWARE, and NTUSER.DAT paths.
3. Open each hive with safe handling; replay transaction logs when available.
4. Parse BAM from SYSTEM BAM UserSettings paths.
5. Parse CAM from ConsentStore in SOFTWARE and NTUSER hives.
6. Parse DAM from Services keys in SYSTEM.
7. Normalize and aggregate artifacts.
8. Display console summary and export JSON/CSV/XLSX evidence files.

## Code Snippets and Explanations

### Snippet 1: Core Imports and Dependency Loading

```python
import argparse, struct, json, csv, os, sys, string, ctypes, tempfile, shutil
from datetime import datetime, timedelta
from pathlib import Path

try:
    from Registry import Registry
except ImportError:
    sys.exit("pip install python-registry")
```

This section establishes required modules for registry parsing, encoding, exports, filesystem operations, and CLI handling.

### Snippet 2: FILETIME Conversion and Sanity Validation

```python
def filetime_to_dt(ft):
    if ft == 0:                  return "Never (0x0)"
    if ft == 0x7FFFFFFFFFFFFFFF: return "Never Expires"
    if ft == 0xFFFFFFFFFFFFFFFF: return "Not Set"
    try:
        r = datetime(1601, 1, 1) + __import__("datetime").timedelta(microseconds=ft // 10)
        return f"Invalid (0x{ft:016X})" if not (1980 <= r.year <= 2100) else r.isoformat()
    except:
        return f"Invalid (0x{ft:016X})"
```

Timestamps are converted from Windows FILETIME to ISO strings, with guardrails for sentinel and invalid values.

### Snippet 3: Safe Hive Open with Optional Transaction-Log Replay

```python
def _open_hive(hive_path, verbose=False):
    if HAS_YARP:
        log1, log2 = hive_path + ".LOG1", hive_path + ".LOG2"
        if os.path.isfile(log1) or os.path.isfile(log2):
            # replay logs into temporary hive copy
            ...
    return Registry.Registry(hive_path), None
```

This improves artifact recovery from dirty hives and minimizes parse failures in practical acquisition conditions.

### Snippet 4: Candidate Key Resolution

```python
def _first_key(reg, candidates):
    for p in candidates:
        try:
            return reg.open(p), p
        except Registry.RegistryKeyNotFoundException:
            pass
    return None, None
```

A shared lookup helper enables robust fallback across control-set path variants.

### Snippet 5: BAM Parsing Logic

```python
def parse_bam(reg, verbose=False):
    key, path = _first_key(reg, BAM_PATHS)
    if key is None:
        return []
    arts = []
    for sid_key in key.subkeys():
        for v in sid_key.values():
            prog = _bam_path(v.name())
            if not prog:
                continue
            raw = v.value()
            arts.append({
                "artifact_type": "BAM",
                "user_sid": sid_key.name(),
                "program_path": prog,
                "last_execution": read_filetime(raw[:8]) if len(raw) >= 8 else "Invalid Data"
            })
    return arts
```

BAM entries are extracted per SID, preserving path and execution timestamp evidence.

### Snippet 6: CAM Root Definition (ConsentStore)

```python
CAM_ROOT = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"
```

CAM evidence source is ConsentStore, not UserAssist.

### Snippet 7: CAM QWORD Timestamp Reader

```python
def _cam_read_qword(key, value_name):
    try:
        v = key.value(value_name)
        raw = v.raw_data()
        if len(raw) >= 8:
            return filetime_to_dt(struct.unpack("<Q", raw[:8])[0])
    except Exception:
        pass
    return None
```

CAM uses QWORD timestamps (`LastUsedTimeStart`, `LastUsedTimeStop`), decoded with shared FILETIME logic.

### Snippet 8: CAM Parsing Logic (Packaged and NonPackaged)

```python
def parse_cam(reg, verbose=False, source_label="SOFTWARE"):
    consent_root = reg.open(CAM_ROOT)
    arts = []
    for cap_key in consent_root.subkeys():
        capability = cap_key.name()
        for app_key in cap_key.subkeys():
            if app_key.name() == "NonPackaged":
                for np_key in app_key.subkeys():
                    ...
            else:
                ...
    return arts
```

The parser supports both packaged (UWP) and non-packaged (Win32) applications, improving CAM coverage.

### Snippet 9: DAM Parsing Logic

```python
def parse_dam(reg, verbose=False):
    key, path = _first_key(reg, DAM_PATHS)
    if key is None:
        return []
    arts = []
    for svc in key.subkeys():
        try:
            ip = svc.value("ImagePath").value()
            arts.append({"artifact_type": "DAM", "service_name": svc.name(), "image_path": ip})
        except:
            pass
    return arts
```

DAM extraction provides startup/service execution context through service image paths.

### Snippet 10: Hive-Level CAM Routing

```python
def parse_software_hive(path, verbose=False):
    reg, tmp = _open_safe(path, verbose)
    if reg is None:
        return []
    try:
        return parse_cam(reg, verbose, source_label="SOFTWARE")
    finally:
        _close_hive(tmp)

def parse_ntuser_cam(path, username, verbose=False):
    reg, tmp = _open_safe(path, verbose)
    if reg is None:
        return []
    try:
        return parse_cam(reg, verbose, source_label=f"NTUSER({username})")
    finally:
        _close_hive(tmp)
```

CAM evidence is collected from both system-wide and per-user contexts.

### Snippet 11: CSV Export Row Normalization

```python
def _row(art, trunc=100):
    t = art["artifact_type"]
    base = [t, "", "", "", art.get("last_execution", art.get("last_used_start", "")),
            art.get("registry_path", ""), art.get("key_last_modified", ""), art.get("raw_hex", "")[:trunc]]
    if t == "BAM":
        base[1], base[2] = art["program_path"], art["user_sid"]
    elif t == "CAM":
        base[1], base[2], base[3], base[4] = art.get("capability", ""), art.get("app_id", ""), art.get("source", ""), art.get("last_used_start", "")
    else:
        base[1], base[2] = art["image_path"], art["service_name"]
    return base
```

This function standardizes mixed artifact fields for flat CSV output.

### Snippet 12: Analysis Pipeline

```python
def analyze(hives, label, args):
    if hives.get("system"):
        arts, b, d = parse_system_hive(hives["system"], args.verbose)
    if hives.get("software"):
        ca = parse_software_hive(hives["software"], args.verbose)
    for uh in hives.get("ntuser_files", []):
        ca = parse_ntuser_cam(uh["path"], uh["username"], args.verbose)
    # print summary + export
```

The orchestrator combines SYSTEM, SOFTWARE, and NTUSER evidence into one reportable dataset.

### Snippet 13: CLI Entry Point

```python
def main():
    ap = argparse.ArgumentParser(description="BAM/CAM/DAM Artifact Parser")
    ap.add_argument("registry", nargs="?", help="Path to a hive file")
    ap.add_argument("--scan-images", action="store_true")
    ap.add_argument("--disk", metavar="DRIVE")
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--out", metavar="STEM")
    ap.add_argument("--exports", metavar="FORMATS", default="all")
    ap.add_argument("--json")
    ap.add_argument("--csv")
    ap.add_argument("--xlsx")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--admin-check", action="store_true")
```

CLI design supports whole-image analysis, targeted drive workflows, and ad-hoc single-hive parsing.

## Final Correctness Note

This updated write-up is aligned with the current implementation where CAM refers to Capability Access Manager ConsentStore artifacts. It supersedes previous SAM-centric and UserAssist-centric descriptions.