# `openremap identify`

Read an ECU binary and print everything that can be extracted from it:
manufacturer, ECU family, software version, hardware number, calibration ID,
match key, file size, and SHA-256 hash.

Use this to confirm what a binary is before doing anything else with it.

---

## Usage

```bash
openremap identify <FILE> [OPTIONS]
```

---

## Arguments

| Argument | Required | Description |
|---|---|---|
| `FILE` | Yes | ECU binary to read. Must end in `.bin` or `.ori`. |

---

## Options

| Option | Short | Description |
|---|---|---|
| `--json` | | Output as JSON instead of a human-readable table. |
| `--output PATH` | `-o` | Save the result to a file instead of printing to the screen. |
| `--help` | | Show help and exit. |

---

## Examples

```bash
# Print a human-readable table
openremap identify ecu.bin

# Print JSON to the screen
openremap identify ecu.bin --json

# Save the result as a JSON file
openremap identify ecu.bin --json --output result.json

# Save the table output to a text file
openremap identify ecu.bin --output result.txt
```

---

## Example output

### Table (default)

```
  ecu.bin
  Bosch · MEDC17

  Manufacturer      Bosch
  ECU Family        MEDC17
  ECU Variant       EDC17C66
  Software Version  1037541778126241V0
  Hardware Number   unknown
  Calibration ID    unknown
  Match Key         EDC17C66::1037541778126241V0
  File Size         4,194,304 bytes
  SHA-256           00f727e8abf62d384acc4420b08fe8e...
```

### JSON (`--json`)

```json
{
  "manufacturer": "Bosch",
  "ecu_family": "MEDC17",
  "ecu_variant": "EDC17C66",
  "software_version": "1037541778126241V0",
  "hardware_number": null,
  "calibration_id": null,
  "match_key": "EDC17C66::1037541778126241V0",
  "file_size": 4194304,
  "sha256": "00f727e8abf62d384acc4420b08fe8e..."
}
```

### Unrecognised ECU

If no extractor matches the binary, every field other than `file_size` and
`sha256` will show as `unknown`. This means the ECU family is not yet
supported — see [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to add one.

```
  mystery.bin
  Unknown ECU — no extractor matched this binary

  Manufacturer      unknown
  ECU Family        unknown
  ECU Variant       unknown
  Software Version  unknown
  Hardware Number   unknown
  Calibration ID    unknown
  Match Key         unknown
  File Size         524,288 bytes
  SHA-256           3f9a21c7d84b...
```

---

## What to look for

| Field | What it tells you |
|---|---|
| **Manufacturer** | Who made the ECU hardware (Bosch, Siemens, Delphi, …) |
| **ECU Family** | The ECU line (EDC17, ME7, SID206, …) |
| **ECU Variant** | The specific hardware variant within the family (EDC17C66, …) |
| **Software Version** | The calibration version string — the primary part of the match key |
| **Hardware Number** | The physical hardware part number, if readable from the binary |
| **Calibration ID** | A secondary calibration identifier, present on some families |
| **Match Key** | The compound identifier used to match recipes to ECUs — must match between the binary and any recipe you intend to apply |
| **File Size** | Total size in bytes — a quick sanity check |
| **SHA-256** | Cryptographic hash of the file — use this to confirm a file has not changed |

### Good result

All of the following should be filled in for a fully supported binary:

- `Manufacturer` is a known name (not `unknown`)
- `ECU Family` is populated
- `Match Key` is populated — if it is `unknown`, the recipe system cannot match this binary to a recipe

### Needs attention

- **`Software Version` is `unknown` but `Match Key` is populated** — the ECU architecture uses a different field (e.g. calibration ID) as the version component. This is by design for some families (e.g. LH-Jetronic). The binary is still usable.
- **`Match Key` is `unknown`** — the extractor matched the file but could not build a version identifier. You can still cook a recipe from this binary, but applying it to other ECUs will not be possible without a match key.
- **Everything is `unknown`** — the ECU family is not yet supported. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

---

## Notes

- `openremap identify` is completely read-only. It never modifies the file.
- Only `.bin` and `.ori` files are accepted. Passing any other extension exits with an error.
- The `--output` flag strips terminal colour codes automatically when writing to a file, so the saved text is clean and readable in any editor.

---

← [Back to CLI reference](../cli.md)