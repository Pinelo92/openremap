# Quick start

You just installed OpenRemap — here's how to do something useful in the next
five minutes. No theory, just commands and what to expect.

---

## Step 1: Check what you have

Point `identify` at any ECU binary to see what's inside:

```bash
openremap identify ecu.bin
```

The output prints the **manufacturer**, **ECU family**, **software version**,
**hardware number**, and a **confidence tier** (HIGH, MEDIUM, or LOW) that tells
you how reliably the file was identified. HIGH means all key identifiers were
found and consistent.

---

## Step 2: Scan a folder

Preview everything in a directory at once:

```bash
openremap scan ./my_bins/
```

This prints a table of every recognised binary — no files are moved. When you're
ready to organise, add the flags:

```bash
openremap scan ./my_bins/ --move --organize
```

Files are sorted into `manufacturer/family/` subfolders automatically.

---

## Step 3: Cook a recipe

Diff a stock binary against a tuned binary to capture the changes:

```bash
openremap cook stock.bin tuned.bin --output recipe.remap
```

The `.remap` file is a portable JSON recipe that records every byte-level
difference, plus the identity metadata of both files. You can share it, version
it, or apply it to other binaries in the same ECU family.

---

## Step 4: Apply a recipe

Apply a recipe to a target binary:

```bash
openremap tune target.bin recipe.remap
```

This runs a 3-phase process — **validate** the recipe against the target,
**apply** the patch, and **verify** the result. If anything looks wrong,
it stops before writing.

To run just the pre-flight check without applying anything:

```bash
openremap validate before target.bin recipe.remap
```

---

## What's next

| Topic | Where to go |
|---|---|
| Full command reference | [CLI reference](cli.md) |
| Interactive terminal UI | Run `openremap` with no arguments, or `openremap-tui` |
| Confidence scoring explained | [Confidence scoring](confidence.md) |
| Recipe file spec | [Recipe format](recipe-format.md) |
| Supported ECU families | Run `openremap families` to list all 30+ families |
| Guided walkthrough | Run `openremap workflow` for a step-by-step guide in your terminal |

---

← [Back to docs](README.md)