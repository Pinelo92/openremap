# `openremap tune`

Apply a tuning recipe to a target ECU binary. Every changed byte block from
the recipe is written to the target at the correct location. The original
file is never modified — the tuned result is always written to a separate
output file.

Before writing a single byte, `openremap tune` runs `validate strict`
internally. If the check fails, nothing is written and the command exits with
an error. You can inspect the target first with
[`openremap validate strict`](validate.md#strict) if you want to see the
validation result before committing to the tune.

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
>
> `openremap tune` does NOT calculate or correct ECU checksums.
>
> Before flashing any tuned binary to a vehicle you **must** run it through a
> dedicated checksum correction tool — ECM Titanium, WinOLS, Checksum Fix Pro,
> or equivalent. `openremap validate tuned` confirms the recipe was applied
> correctly. It does **not** replace a checksum tool. These are two different
> things.
>
> **Flashing a binary with an incorrect checksum will brick your ECU.**
> No exceptions. No recovery without a bench flash or JTAG setup.

---

## Usage

```bash
openremap tune <TARGET> <RECIPE> [OPTIONS]
```

---

## Arguments

| Argument | Required | Description |
|---|---|---|
| `TARGET` | Yes | The untuned ECU binary to apply the recipe to. Must end in `.bin` or `.ori`. |
| `RECIPE` | Yes | The recipe `.json` file produced by `openremap cook`. |

---

## Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--output PATH` | `-o` | `<target_stem>_tuned<ext>` | Path to write the tuned binary. If omitted, the output is placed in the same folder as the target and named `target_tuned.bin`. |
| `--report PATH` | `-r` | | Save the full tune report as a JSON file alongside the tuned binary. Useful for auditing and record-keeping. |
| `--skip-validation` | | off | Skip the internal `validate strict` pre-flight check and apply the recipe directly. Only use this if you have already run `validate strict` manually and are certain the target is correct. |
| `--json` | | | Print the full tune report as JSON to the screen instead of the human-readable summary. |
| `--help` | | | Show help and exit. |

---

## Examples

```bash
# Apply a tune — output defaults to target_tuned.bin in the same folder
openremap tune target.bin recipe.json

# Specify where to write the tuned binary
openremap tune target.bin recipe.json --output my_tuned.bin

# Save a JSON report alongside the tuned binary for your records
openremap tune target.bin recipe.json --report tune_report.json

# Save both the tuned binary and the report
openremap tune target.bin recipe.json --output my_tuned.bin --report my_report.json

# Skip the internal validation (only if you have already run validate strict)
openremap tune target.bin recipe.json --skip-validation

# Print the full report as JSON to the screen
openremap tune target.bin recipe.json --json
```

---

## Example output

### Successful tune

```
  Applying tune recipe.json to target.bin …

  ✅ Tune applied successfully

  Target                 target.bin
  Target MD5             abc2e7d4610bfda5619951e015566e8d
  Tuned MD5              f3c1a9b2d8e7041256ff34c2ab987d31
  Instructions           277
  Applied                275
  Applied (shifted)        2

  Tuned binary saved to target_tuned.bin

  ⚠  Always verify checksums with ECM Titanium, WinOLS, or a similar
     tool before flashing the tuned binary to a vehicle.
```

### Pre-flight validation failed — nothing written

```
  Applying tune recipe.json to target.bin …

  ❌ Tune rejected during pre-flight validation:

  16 instruction(s) failed — ob bytes not found at expected offsets.
  Run  openremap validate exists target.bin recipe.json  to diagnose.
```

### Tune applied with some shifted instructions

```
  Applying tune recipe.json to target.bin …

  ✅ Tune applied successfully

  Target                 target.bin
  Target MD5             cc9f3b1a...
  Tuned MD5              7d42f8e1...
  Instructions           180
  Applied                173
  Applied (shifted)        7

  Tuned binary saved to target_tuned.bin

  ⚠  Always verify checksums with ECM Titanium, WinOLS, or a similar
     tool before flashing the tuned binary to a vehicle.
```

Shifted instructions were found at a nearby offset using the `ctx + ob`
anchor search and applied successfully. The tuned binary is valid, but
verify it carefully with `openremap validate tuned` before flashing.

---

## What to look for

| Result | What to do |
|---|---|
| `Tune applied successfully` — all instructions applied | Run `openremap validate tuned` to confirm, then correct checksums before flashing. |
| `Applied (shifted)` count is non-zero | The tune was applied but some instructions landed at a slightly different offset. Run `openremap validate tuned` and inspect the result carefully. |
| `Failed` count is non-zero | Some instructions could not be written. Do not flash the output. Run `openremap validate exists target.bin recipe.json` to diagnose. |
| `Tune rejected during pre-flight validation` | The target binary failed the pre-flight check. Nothing was written. Run `openremap validate strict` for the full report, then `openremap validate exists` to understand why. |

---

## How it works

1. The target binary and recipe are loaded.
2. `validate strict` is run internally (unless `--skip-validation` is passed).
   If any instruction fails, the command exits here — nothing is written.
3. For each instruction, the tuner looks for the `ctx + ob` anchor at the
   expected offset. If found, the `ob` bytes are replaced with `mb` bytes.
4. If the anchor is not found at the expected offset, the tuner searches
   within ±2 KB. This recovers instructions whose offsets have shifted
   slightly due to a different software revision.
5. If the anchor cannot be found within the search window, the instruction
   is marked as failed.
6. If all instructions are applied (with or without shifting), the tuned
   binary is written to the output path. If any instruction failed, the
   output is not written.

---

## After tuning — required next steps

```bash
# 1. Verify every byte was written correctly
openremap validate tuned target_tuned.bin recipe.json

# 2. MANDATORY — correct checksums before flashing
#    Use ECM Titanium, WinOLS, Checksum Fix Pro, or equivalent.
#    Skipping this step will brick the ECU.
```

---

## Notes

- The original `TARGET` file is never modified. The tuned result is always
  written to a separate output file.
- If the output file path already exists, it will be overwritten. Choose a
  specific `--output` path if you want to preserve the previous file.
- The `--report` JSON file contains the full per-instruction result,
  including exact offsets, MD5 hashes of target and tuned binaries, and
  whether each instruction was applied at the exact offset or shifted.
  Useful for auditing and for sharing results with another tuner.
- `--skip-validation` is an escape hatch for scripted workflows where you
  have already validated separately. In interactive use, always let the
  internal validation run.

---

← [Back to CLI reference](../cli.md)