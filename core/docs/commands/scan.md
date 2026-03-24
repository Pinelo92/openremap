# `openremap scan`

Sort a folder of ECU binaries by classification result. Every file is read and
run through all registered extractors. The result is printed to the screen and,
when you are ready, files are moved into sub-folders automatically.

Running without any flags is always a safe preview — nothing is moved until you
explicitly pass `--move`.

---

## Usage

```bash
openremap scan [DIRECTORY] [OPTIONS]
```

---

## Arguments

| Argument | Default | Description |
|---|---|---|
| `DIRECTORY` | `.` (current folder) | Folder containing the `.bin` / `.ori` files to scan |

---

## Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--dry-run` / `--move` | | `--dry-run` | Preview mode is the default — nothing is moved. Pass `--move` to actually sort files into their destination folders. |
| `--create-dirs` | | off | Create the five flat destination folders inside the scan directory if they do not already exist. |
| `--organize` | `-O` | off | Sort identified files into `manufacturer/family` sub-folders (e.g. `scanned/Bosch/EDC17/`). Creates all required folders automatically — no need to pass `--create-dirs` separately. |
| `--help` | | | Show help and exit. |

---

## How files are classified

Every file is tested against every registered extractor and placed into exactly
one of five outcomes:

| Outcome | Folder | What it means |
|---|---|---|
| **SCANNED** | `scanned/` | One extractor matched and a full calibration identity (match key) was extracted. Fully identified and ready to use. |
| **SW MISSING** | `sw_missing/` | One extractor matched and identified the ECU family, but the calibration version could not be read from the binary (e.g. the binary was wiped or the pattern is missing). |
| **CONTESTED** | `contested/` | More than one extractor matched. Signals a detection overlap that needs investigation. |
| **UNKNOWN** | `unknown/` | No extractor matched. The ECU family is not yet supported, or the file is not a valid ECU binary. |
| **TRASH** | `trash/` | The file does not have a `.bin` or `.ori` extension. Moved aside without being read. |

Files are never overwritten. If a file with the same name already exists in the
destination folder, a counter is appended automatically (`file__1.bin`,
`file__2.bin`, …).

---

## Destination folder layouts

### Flat layout (default, or `--create-dirs`)

```
my_bins/
├── scanned/        ← fully identified
├── sw_missing/     ← family known, calibration unknown
├── contested/      ← matched by more than one extractor
├── unknown/        ← no extractor matched
└── trash/          ← wrong file extension
```

### Organised layout (`--organize`)

`SCANNED` and `SW MISSING` files are further sorted into
`manufacturer/family` sub-folders. `CONTESTED`, `UNKNOWN`, and `TRASH`
remain flat because no single extractor was confirmed for them.

```
my_bins/
├── scanned/
│   ├── Bosch/
│   │   ├── EDC17/          ← ecu1.bin, ecu2.bin …
│   │   ├── MEDC17/         ← ecu3.bin …
│   │   └── ME7.5/          ← ecu4.bin …
│   └── Siemens/
│       └── SIM2K/          ← ecu5.bin …
├── sw_missing/
│   └── Bosch/
│       └── unknown_family/ ← ecu6.bin …
├── contested/              ← flat
├── unknown/                ← flat
└── trash/                  ← flat
```

---

## Examples

```bash
# Preview results — nothing moves (this is the default, no flag needed)
openremap scan ./my_bins/

# Preview the current folder
openremap scan

# Preview what --organize would do, without moving anything
openremap scan ./my_bins/ --organize

# Sort files into flat folders — create them first if they do not exist
openremap scan ./my_bins/ --move --create-dirs

# Sort files into flat folders that already exist
openremap scan ./my_bins/ --move

# Sort into a manufacturer/family tree — creates all folders automatically
openremap scan ./my_bins/ --move --organize
```

---

## Example output

### Default (dry-run, flat preview)

```
  OpenRemap — Batch ECU Scanner  [dry run — pass --move to sort files]
  5 file(s)  •  13 extractor(s)  •  /home/user/my_bins

[1/5]  SCANNED     006410010A0.bin          63.8 ms
                └─ extractor: BoschME7Extractor  family: ME7.1.1  sw: 1037371702  hw: 0261208771  key: ME7.1.1::1037371702
[2/5]  SCANNED     0280-000-560.bin           4.4 ms
                └─ extractor: BoschLHExtractor  family: LH-Jetronic  cal_id: 1012621LH241RP (sw absent by architecture)  key: LH-JETRONIC::1012621LH241RP
[3/5]  SW MISSING  anonymous_dump.bin         12.1 ms
                └─ extractor: BoschMotronicLegacyExtractor  family: DME-3.2  sw: None
[4/5]  CONTESTED   edge_case.bin              48.3 ms
                └─ claimed by: BoschEDC15Extractor(Bosch), BoschEDC16Extractor(Bosch)
[5/5]  UNKNOWN     mystery.bin                 0.4 ms
                └─ no extractor matched

  ── Summary ──────────────────────────────────────────────────
  Scanned       2
  SW Missing    1
  Contested     1
  Unknown       1
  Trash         0

  Total: 5  •  0.13s  (dry run — nothing moved)

  Tip: run with --move to sort files into flat folders, or add --organize
  to sort by manufacturer/family (e.g. scanned/Bosch/EDC17/).
```

### With `--organize` (dry-run preview of organised layout)

```
  OpenRemap — Batch ECU Scanner  [dry run — pass --move to sort files]  [organized]
  5 file(s)  •  13 extractor(s)  •  /home/user/my_bins

[1/5]  SCANNED     006410010A0.bin          63.8 ms
                └─ extractor: BoschME7Extractor  family: ME7.1.1  sw: 1037371702  key: ME7.1.1::1037371702  → scanned/Bosch/ME7.1.1/
[2/5]  SCANNED     0280-000-560.bin           4.4 ms
                └─ extractor: BoschLHExtractor  family: LH-Jetronic  cal_id: 1012621LH241RP  key: LH-JETRONIC::1012621LH241RP  → scanned/Bosch/LH-Jetronic/
[3/5]  SW MISSING  anonymous_dump.bin         12.1 ms
                └─ extractor: BoschMotronicLegacyExtractor  family: DME-3.2  sw: None  → sw_missing/Bosch/DME-3.2/
[4/5]  CONTESTED   edge_case.bin              48.3 ms
                └─ claimed by: BoschEDC15Extractor(Bosch), BoschEDC16Extractor(Bosch)
[5/5]  UNKNOWN     mystery.bin                 0.4 ms
                └─ no extractor matched

  ── Summary ──────────────────────────────────────────────────
  Scanned       2
  SW Missing    1
  Contested     1
  Unknown       1
  Trash         0

  Total: 5  •  0.13s  (dry run — nothing moved)

  Tip: run with --move --organize to sort files into the
  manufacturer/family tree shown above.
```

---

## Recommended workflow

```bash
# 1. Preview — nothing moves
openremap scan ./my_bins/

# 2. If the results look right, sort into a manufacturer/family tree
openremap scan ./my_bins/ --move --organize

# 3. Investigate anything that did not scan cleanly
openremap identify my_bins/sw_missing/Bosch/unknown_family/some_file.bin
openremap identify my_bins/contested/some_file.bin
```

---

## Tips

- **Always preview first.** Dry-run is the default for exactly this reason — you
  can see what will happen before anything is moved.
- **`--organize` is the recommended mode for large collections.** Finding a
  specific ECU is much easier when files are already grouped by manufacturer and
  family.
- **`contested` files need manual attention.** Run `openremap identify` on them
  and check which result looks correct. If two extractors genuinely overlap,
  open an issue.
- **`sw_missing` files are not broken.** The ECU family was recognised. The
  binary may have had its calibration string wiped, or the extractor's pattern
  needs improvement. Run `openremap identify` for the full detail.

---

← [Back to CLI reference](../cli.md)