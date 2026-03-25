# Application Execution Forensics Parser (BAM / CAM / DAM)

Windows registry artifact parser for application execution and usage traces from offline or mounted Windows systems.

This README reflects the current implementation in:

- `wfp_app_execution_cbd_forensics.py`

## Current Features

- BAM parsing from SYSTEM hive with ControlSet fallback coverage.
- CAM parsing from `CapabilityAccessManager\ConsentStore` in both SOFTWARE and NTUSER.DAT hives.
- DAM parsing from Services trees with ControlSet fallback coverage.
- FILETIME normalization with sanity range checks (`1980` to `2100`).
- Timestamp handling for known sentinel values (`Never`, `Never Expires`, `Not Set`).
- Full-drive scan mode (`--scan-images`) and targeted drive mode (`--disk DRIVE`).
- Single-hive mode via positional `registry` path argument.
- Interactive export menu (format choice, filename stem, optional folder override).
- Non-interactive export when `--out` and explicit `--exports` are supplied.
- Colored console summary and per-artifact preview sections.
- Excel export with one summary sheet plus BAM/CAM/DAM detail sheets.
- Administrative privilege check (`--admin-check`) and permission-denied guidance.

## Requirements

Required packages:

```bash
pip install python-registry openpyxl colorama
```

## CLI Usage

```bash
python wfp_app_execution_cbd_forensics.py [OPTIONS] [registry]
```

Positional argument:

- `registry`: path to one hive file (for example `System`, `Software`, or `NTUSER.DAT`).

Options:

- `--scan-images`: scan all mounted drives for Windows installations.
- `--disk DRIVE`: scan only one drive letter (example: `--disk F`).
- `--auto`: auto-select first detected system in scan mode.
- `--out STEM`: output base filename/stem.
- `--exports FORMATS`: `all` (default) or comma list such as `json,csv,xlsx`.
- `--json PATH`: override JSON output path.
- `--csv PATH`: override CSV output path.
- `--xlsx PATH`: override XLSX output path.
- `--verbose`: print debug diagnostics and parse counters.
- `--admin-check`: print administrator status and guidance.
- `--no-color`: disable colored output.

Note:

- `--include-ueme` is removed and no longer used.

## Export Behavior

After analysis, the script opens an export menu.

Prompt flow:

1. Select format(s): JSON, CSV, XLSX, all, or custom combination.
2. Enter output stem (or accept generated default).
3. Save to current directory or provide a custom folder.
4. Export selected files.

Prompt bypass:

- If both `--out` and explicit `--exports` (not `all`) are provided, export runs directly.

## Quick Examples

Scan all drives and choose system manually:

```bash
python wfp_app_execution_cbd_forensics.py --scan-images
```

Scan all drives and auto-select first detected system:

```bash
python wfp_app_execution_cbd_forensics.py --scan-images --auto
```

Analyze mounted drive F with verbose diagnostics:

```bash
python wfp_app_execution_cbd_forensics.py --disk F --verbose
```

Direct export (no prompt):

```bash
python wfp_app_execution_cbd_forensics.py --disk F --out case_001 --exports json,csv
```

Parse SOFTWARE hive only (CAM-focused):

```bash
python wfp_app_execution_cbd_forensics.py "F:\Windows\System32\config\Software" --verbose
```

Parse SYSTEM hive only (BAM/DAM-focused):

```bash
python wfp_app_execution_cbd_forensics.py "F:\Windows\System32\config\System" --verbose
```

## Parsing Details

### BAM (Background Activity Moderator)

Primary key family (with fallback candidates):

- `...\Services\bam\State\UserSettings`
- `...\Services\bam\UserSettings`

Accepted value-name path styles:

- `\??\C:\...`
- `\Device\...`
- direct `C:\...`

Extracted fields include program path, SID, last execution timestamp, registry path, key timestamp, and raw hex.

### CAM (Capability Access Manager)

Source root:

- `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore`

Parser behavior:

- Enumerates capability groups (for example `microphone`, `webcam`, `location`).
- Parses packaged entries and nested `NonPackaged` Win32 entries.
- Reads `Value` consent and QWORD FILETIME timestamps:
  - `LastUsedTimeStart`
  - `LastUsedTimeStop`
- Tags source as `SOFTWARE` or `NTUSER(<username>)`.

### DAM (Services)

Scans Services trees in ControlSet candidates and extracts service `ImagePath` values.

## Timestamp Rules

FILETIME values are converted to ISO strings and validated.

- Valid year range: `1980` to `2100`.
- Out-of-range values: `Invalid (0x...)`.

Special values:

- `0` -> `Never (0x0)`
- `0x7FFFFFFFFFFFFFFF` -> `Never Expires`
- `0xFFFFFFFFFFFFFFFF` -> `Not Set`

## Output Files

Formats:

- JSON
- CSV
- XLSX

Default stem:

- `forensics_<target>_<YYYYMMDD_HHMMSS>`

XLSX sheets:

- `All Artifacts`
- `BAM Details` (if BAM exists)
- `CAM Details` (if CAM exists)
- `DAM Details` (if DAM exists)

## Operational Notes

- Use mounted/offline images when possible for forensic safety.
- Include both SOFTWARE and NTUSER.DAT hives for better CAM coverage.
- Live hives may be locked; use an elevated shell when needed.
- Use `--admin-check` before live acquisition workflows.
- Use `--verbose` when validating key discovery and artifact counts.
