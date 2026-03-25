# Application Execution Forensics Parser

BAM/CAM/DAM extractor for mounted or offline Windows hives.

This version uses CAM as Capability Access Manager

## Current Features

- BAM parsing from SYSTEM hive across multiple control-set path variants
- CAM parsing from CapabilityAccessManager\ConsentStore in SOFTWARE and NTUSER.DAT
- DAM parsing from Services keys in SYSTEM across multiple control-set path variants
- FILETIME conversion with sanity checks (1980 to 2100)
- Drive scan mode (`--scan-images`) and single-drive mode (`--disk DRIVE`)
- Single-hive mode via positional `registry` argument
- Interactive export prompt with selectable formats and output location
- Export control through `--exports`, `--out`, and per-format path overrides
- Colorized console summary with BAM/CAM/DAM preview entries
- Excel output with artifact-specific detail sheets

## Requirements

Required:

```bash
pip install python-registry openpyxl colorama
```

## CLI Usage

```bash
python app_execution_forensics.py [OPTIONS] [registry]
```

Positional:

- `registry`: path to one hive file (example: `System`, `Software`, or `NTUSER.DAT`)

Options:

- `--scan-images`: scan all mounted drives for Windows systems
- `--disk DRIVE`: scan only one drive (example: `--disk F`)
- `--auto`: auto-select first detected system in scan mode
- `--out STEM`: output base filename
- `--exports FORMATS`: `all` (default) or comma list like `json,csv,xlsx`
- `--json PATH`: override JSON output path
- `--csv PATH`: override CSV output path
- `--xlsx PATH`: override XLSX output path
- `--verbose`: debug diagnostics
- `--admin-check`: print admin status guidance
- `--no-color`: disable colored output

Note: `--include-ueme` is removed in this build because CAM is no longer UserAssist-based.

## Export Behavior

After analysis, the script opens an interactive export menu.

Prompt flow:

1. Choose format(s): JSON, CSV, XLSX, all, or custom combination
2. Choose output stem (or accept generated default)
3. Choose current directory or custom folder
4. Export files

Prompt bypass:

- If both `--out` and explicit `--exports` are provided (and not `all`), export runs directly without prompt.

## Quick Examples

Scan all drives and select a system manually:

```bash
python app_execution_forensics.py --scan-images
```

Scan all drives and auto-select first system:

```bash
python app_execution_forensics.py --scan-images --auto
```

Analyze mounted drive F with diagnostics:

```bash
python app_execution_forensics.py --disk F --verbose
```

Direct export (no interactive prompt):

```bash
python app_execution_forensics.py --disk F --out case_001 --exports json,csv
```

Parse only a SOFTWARE hive (CAM-focused single-hive run):

```bash
python app_execution_forensics.py "F:\Windows\System32\config\Software" --verbose
```

Parse only a SYSTEM hive (BAM/DAM-focused single-hive run):

```bash
python app_execution_forensics.py "F:\Windows\System32\config\System" --verbose
```

## Parsing Details

### BAM (Background Activity Moderator)

Primary target key (with control-set fallbacks):

- `...\Services\bam\State\UserSettings`

Accepted value-name path patterns:

- `\??\C:\...`
- `\Device\...`
- direct `C:\...`

Extracted fields include program path, SID context, last execution, key metadata, and raw hex.

### CAM (Capability Access Manager)

Source key:

- `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore`

Parser behavior:

- Enumerates capabilities (for example microphone, webcam, location)
- Parses packaged app entries and nested `NonPackaged` Win32 entries
- Reads `Value` consent state and QWORD timestamps:
	- `LastUsedTimeStart`
	- `LastUsedTimeStop`
- Tags record source as `SOFTWARE` or `NTUSER(<username>)`

### DAM (Services)

Scans service keys across control-set candidates and extracts entries with `ImagePath`.

## Timestamp Rules

`FILETIME` values are converted to ISO strings and validated:

- valid year range: `1980` to `2100`
- outside range: `Invalid (0x...)`

Special values handled:

- `0` -> `Never (0x0)`
- `0x7FFFFFFFFFFFFFFF` -> `Never Expires`
- `0xFFFFFFFFFFFFFFFF` -> `Not Set`

## Output Files

Generated formats:

- JSON
- CSV
- XLSX

Default output stem:

- `forensics_<target>_<timestamp>`

XLSX sheets:

- `All Artifacts`
- `BAM Details` (if present)
- `CAM Details` (if present)
- `DAM Details` (if present)

## Operational Notes

- Mounted/offline images are preferred for forensic integrity.
- For CAM coverage, include both SOFTWARE and user NTUSER.DAT hives.
- Live hives may be locked; use elevated shell when needed.
- Use `--admin-check` before live acquisition workflows.
- Use `--verbose` to inspect key discovery and artifact counters.
