# CLI Reference

Full reference for the `openremap` command-line tool. No server, no database,
no internet connection required — install and run anywhere.

> **New to the terminal?** Run `openremap workflow` first. It prints a complete
> plain-English walkthrough with the exact commands to type and what to look for
> at each step. No reading required.

---

## Installation

See the full setup guide → [`docs/setup.md`](setup.md)

Quick start for most users — `openremap` is on [PyPI](https://pypi.org/project/openremap/):

```bash
uv tool install openremap
```

Prefer plain pip?

```bash
pip install openremap
```

`openremap` is then available from any folder, no activation required.
Shell completion, development setup, updating, and troubleshooting are all
covered in [`docs/setup.md`](setup.md).

---

## Commands

Every command supports `--help` for a quick reminder of its arguments and options.

| Command | What it does | Reference |
|---|---|---|
| `workflow` | Step-by-step guide — start here if you are new | [→ workflow.md](commands/workflow.md) |
| `scan` | Sort a folder of ECU files by manufacturer and family | [→ scan.md](commands/scan.md) |
| `identify` | Read an ECU binary and print everything extracted from it | [→ identify.md](commands/identify.md) |
| `cook` | Compare a stock and a tuned binary and save the difference as a recipe | [→ cook.md](commands/cook.md) |
| `validate strict` | Safety check — run this **before** tuning | [→ validate.md#strict](commands/validate.md#strict) |
| `validate exists` | Diagnosis — run this when `validate strict` fails | [→ validate.md#exists](commands/validate.md#exists) |
| `validate tuned` | Confirmation — run this **after** tuning | [→ validate.md#tuned](commands/validate.md#tuned) |
| `tune` | Apply a recipe to an ECU binary | [→ tune.md](commands/tune.md) |

---

## Quick-start example

```bash
# New here? Print the full step-by-step guide first
openremap workflow

# (Optional) Sort a folder of binaries into a tidy library
openremap scan ./my_bins/                    # preview — nothing moves
openremap scan ./my_bins/ --move --organize  # sort into Bosch/EDC17/ etc.

# 1. Read the stock binary — confirm it is a supported ECU
openremap identify stock.bin

# 2. Extract the tune — diff stock vs tuned and save as a recipe
openremap cook stock.bin stage1.bin --output recipe.json

# 3. Safety check — must pass before you tune anything
openremap validate strict target.bin recipe.json

# 4. Apply the tune
openremap tune target.bin recipe.json --output target_tuned.bin

# 5. Confirm every byte was written correctly
openremap validate tuned target_tuned.bin recipe.json

# 6. MANDATORY — correct checksums with ECM Titanium, WinOLS, or equivalent
#    before flashing the tuned binary to any vehicle
```

---

## Other documentation

| Document | Contents |
|---|---|
| [`docs/commands/`](commands/) | Per-command reference — arguments, options, examples, example output |
| [`docs/about.md`](about.md) | How it works in detail — the recipe format, the match key, use cases, FAQ |
| [`docs/recipe-format.md`](recipe-format.md) | The recipe JSON spec — fields, structure, versioning |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | How to add a new ECU extractor, code style, submitting a PR |
| [`DISCLAIMER.md`](../DISCLAIMER.md) | Liability, intended use, professional review requirements |