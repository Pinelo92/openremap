# `openremap validate`

Three sub-commands for checking a binary against a recipe — before and after
tuning. Run `validate strict` before you tune anything. Run `validate tuned`
after. Use `validate exists` only when `validate strict` fails and you need
to understand why.

---

## Sub-commands at a glance

| Sub-command | When to run | What it checks |
|---|---|---|
| [`strict`](#strict) | **Before** tuning | Are the original bytes at the exact expected offsets? |
| [`exists`](#exists) | When `strict` fails | Are the original bytes anywhere in the binary at all? |
| [`tuned`](#tuned) | **After** tuning | Are the new bytes now at the correct offsets? |

---

## `strict`

**Run this before applying a tune.**

Checks that the exact original bytes (`ob`) from every instruction in the
recipe are present at their expected offsets in the target binary. Every
instruction is checked before reporting — you see the full picture, not just
the first failure.

A result of `Safe to tune` means every instruction matched and it is safe to
call `openremap tune`.

### Usage

```bash
openremap validate strict <TARGET> <RECIPE> [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `TARGET` | Yes | The untuned ECU binary to check (`.bin` or `.ori`). |
| `RECIPE` | Yes | The recipe `.json` file. |

### Options

| Option | Short | Description |
|---|---|---|
| `--json` | | Output the full report as JSON instead of a table. |
| `--output PATH` | `-o` | Save the report to a file. |
| `--help` | | Show help and exit. |

### Examples

```bash
# Run the check and print the result
openremap validate strict target.bin recipe.json

# Save the full JSON report to a file
openremap validate strict target.bin recipe.json --json --output report.json
```

### Example output

**All instructions passed**

```
  Validating target.bin against recipe.json …

  ✅ Safe to tune

  Target               target.bin
  MD5                  abc2e7d4610bfda5619951e015566e8d
  Instructions         277
  Passed               277
```

**Some instructions failed**

```
  Validating target.bin against recipe.json …

  ⚠  match_key mismatch
     recipe : EDC17C66::1037541778126241V0
     target : EDC17C66::1037541778999999V0

  ❌ Not safe to tune

  Target               target.bin
  MD5                  ff3a91b2...
  Instructions         277
  Passed               261
  Failed                16

  Failed instructions:
     #  12  offset 0x0012A4F0  — ob not found at offset
     #  13  offset 0x0012A510  — ob not found at offset
     ...
```

### What to look for

| Result | What to do |
|---|---|
| `Safe to tune` — all passed | Proceed to `openremap tune`. |
| Any failures | Stop. Do NOT tune. Run `validate exists` to find out why. |
| `match_key mismatch` warning | The target binary is a different software version from the one the recipe was built on. Run `validate exists` before deciding whether to continue. |

---

## `exists`

**Run this when `validate strict` fails.**

Searches the entire binary for the original bytes (`ob`) of every instruction
— not just at the expected offset. This tells you whether the bytes exist
somewhere else in the file (meaning the maps have shifted, likely due to a
different software revision) or are absent entirely (meaning this is the
wrong ECU).

This command does not move or modify any file. It is purely a diagnostic
tool.

### Usage

```bash
openremap validate exists <TARGET> <RECIPE> [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `TARGET` | Yes | The ECU binary to search (`.bin` or `.ori`). |
| `RECIPE` | Yes | The recipe `.json` file. |

### Options

| Option | Short | Description |
|---|---|---|
| `--json` | | Output the full report as JSON. |
| `--output PATH` | `-o` | Save the report to a file. |
| `--help` | | Show help and exit. |

### Examples

```bash
# Run the existence check
openremap validate exists target.bin recipe.json

# Save the report
openremap validate exists target.bin recipe.json --json --output exists_report.json
```

### Verdicts

| Verdict | What it means | What to do |
|---|---|---|
| `SAFE EXACT` | All `ob` bytes found at their exact expected offsets. | Re-examine why `validate strict` failed — this is unusual. |
| `SHIFTED RECOVERABLE` | All `ob` bytes found, but at different offsets from those recorded in the recipe. | The target is a different software revision. The tuner's ±2 KB anchor search may still recover these automatically — proceed with caution and verify the result carefully. |
| `MISSING UNRECOVERABLE` | Some `ob` bytes are not found anywhere in the binary. | This is the wrong ECU. Do not tune. |

### Example output

```
  Checking existence of ob bytes in target.bin against recipe.json …

  Verdict: SHIFTED RECOVERABLE

  Instructions checked   277
  Found at exact offset  261
  Found shifted            16
  Not found                 0

  Shifted instructions (sample):
     # 12  expected 0x0012A4F0  found at 0x0012B4F0  (shifted +4096 bytes)
     # 13  expected 0x0012A510  found at 0x0012B510  (shifted +4096 bytes)
```

---

## `tuned`

**Run this after applying a tune.**

Confirms that every instruction's new bytes (`mb`) are now present at the
correct offset in the tuned binary. The mirror image of `validate strict`:
`strict` checks the original bytes (`ob`) before tuning; `tuned` checks the
modified bytes (`mb`) after.

A result of `Tune confirmed` means every instruction was written correctly.

### Usage

```bash
openremap validate tuned <TUNED> <RECIPE> [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `TUNED` | Yes | The tuned ECU binary to verify (`.bin` or `.ori`). |
| `RECIPE` | Yes | The recipe `.json` file used when tuning. |

### Options

| Option | Short | Description |
|---|---|---|
| `--json` | | Output the full report as JSON. |
| `--output PATH` | `-o` | Save the report to a file. |
| `--help` | | Show help and exit. |

### Examples

```bash
# Verify the tuned binary
openremap validate tuned target_tuned.bin recipe.json

# Save the verification report for your records
openremap validate tuned target_tuned.bin recipe.json --json --output verify.json
```

### Example output

**All instructions confirmed**

```
  Verifying tuned binary target_tuned.bin against recipe.json …

  ✅ Tune confirmed — all mb bytes verified

  Tuned File           target_tuned.bin
  MD5                  f3c1a9b2d8e7041256ff34c2ab987d31
  Instructions         277
  Confirmed            277
```

**Some instructions failed**

```
  Verifying tuned binary target_tuned.bin against recipe.json …

  ❌ Tune NOT confirmed — some instructions failed

  Tuned File           target_tuned.bin
  MD5                  ...
  Instructions         277
  Confirmed            274
  Failed                 3

  Failed instructions:
     #  45  offset 0x00FF1200  size 4 bytes  — mb not found at offset
```

### What to look for

| Result | What to do |
|---|---|
| `Tune confirmed` — all passed | The tune was written correctly. Proceed to checksum correction before flashing. |
| Any failures | Do not flash. Re-run `openremap tune` or investigate with `validate exists`. |

---

## The full validation sequence

```bash
# 1. Before tuning — must pass before you proceed
openremap validate strict target.bin recipe.json

# 2. If strict fails — diagnose first
openremap validate exists target.bin recipe.json

# 3. After tuning — confirm everything landed correctly
openremap validate tuned target_tuned.bin recipe.json
```

---

## Notes

- All three `validate` commands are read-only. They never modify any file.
- The `--json` flag outputs the raw validation report, which includes every
  instruction result individually. Useful for scripting or archiving.
- `validate strict` is also run automatically inside `openremap tune` before
  any bytes are written. Passing `--skip-validation` to `tune` bypasses this
  — only do so if you have already run `validate strict` manually and are
  certain the target is correct.

---

← [Back to CLI reference](../cli.md)