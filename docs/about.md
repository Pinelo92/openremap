# About OpenRemap

## The problem with how tuning works today

When you load a tune into WinOLS, ECM Titanium, or any professional calibration tool, those tools are doing something sophisticated: they interpret the binary. They know where the maps are, what the axes mean, what the values represent. That knowledge is valuable, and those tools have earned their place in professional workshops.

But there is a gap they do not fill.

When you take a modified binary and want to know *exactly* what changed — at the byte level — and move that change reliably to another ECU with the same software, there is no clean, open, scriptable way to do it. You are either eyeballing hex diffs, using proprietary scripts, or hoping the checksum tool and the flash tool agree on what happened.

OpenRemap fills that gap. It does not try to replace calibration software. It works alongside it.

---

## What OpenRemap actually does

At its core, OpenRemap is a **binary diff and patch pipeline** built specifically for ECU firmware files.

You give it two binaries — a stock file and a tuned file — and it finds every byte that changed, captures the surrounding context, and saves the result as a portable **recipe**. That recipe can then be validated against any target ECU and applied with confidence.

The full pipeline looks like this:

```
identify → cook → validate → patch → verify
```

Each step is independent. You can run them separately, inspect the output at every stage, and automate the whole chain.

---

## Step by step

### 1. Identify

Before anything else, OpenRemap reads the binary and figures out what it is.

```bash
openremap identify ecu.bin
```

It scans the file through a registry of manufacturer-specific extractors and pulls out everything it can find: ECU family, software version, hardware number, calibration ID. From those it builds a **match key** — a compact identity string that uniquely represents this binary.

```
Manufacturer       Bosch
ECU Family         EDC17
ECU Variant        EDC17C66
Software Version   1037541778126241V0
Match Key          EDC17C66::1037541778126241V0
```

The match key is the fingerprint. Everything downstream uses it to confirm you are working with the right binary.

---

### 2. Cook

This is where the diff happens.

```bash
openremap cook stock.bin stage1.bin --output recipe.json
```

OpenRemap compares the two files byte by byte, groups consecutive changed bytes into blocks, and for each block records:

- **`offset`** — where in the binary the change is
- **`ob`** — the original bytes (what was there before)
- **`mb`** — the modified bytes (what the tune wrote)
- **`ctx`** — context bytes immediately before the change (used as an anchor during patching)

The output is a JSON file — the recipe. It is human-readable, version-controllable, and completely self-contained. The ECU identity block is embedded so the recipe always knows which binary it was built from.

A recipe for a real-world stage 1 tune typically contains a few dozen to a few hundred instructions, depending on how many maps were touched.

---

### 3. Validate (before patching)

Before writing a single byte to the target, you validate.

```bash
openremap validate strict target.bin recipe.json
```

Strict validation reads the exact offset of every instruction in the recipe and checks that the original bytes (`ob`) are still there. If every instruction matches, the binary is clean and safe to patch. If anything fails, it will not proceed.

There is a second validator for when strict validation fails:

```bash
openremap validate exists target.bin recipe.json
```

This scans the entire binary for each instruction's original bytes, regardless of offset, and tells you:

- **EXACT** — found at the right place, same as a strict pass
- **SHIFTED** — found, but at a different offset (the map moved between SW versions)
- **MISSING** — not found anywhere (wrong ECU, wrong calibration, already modified)

The exists validator answers the question: *is this the right ECU, or just the wrong revision?*

---

### 4. Tune

```bash
openremap tune target.bin recipe.json --output target_tuned.bin
```

The tuner runs strict pre-flight validation internally before touching anything. If that passes, it applies every instruction using a **context + original bytes anchor search**: instead of blindly writing to the recorded offset, it searches within a ±2 KB window for the exact pattern of `ctx + ob`. This makes the tuner tolerant of minor software revision shifts — maps that moved slightly between calibrations are found and tuned correctly.

The tuner works on an in-memory copy of the binary. The original file is never modified. The tuned result is only written if every single instruction succeeded. A partial tune is never written.

---

### 5. Verify (after tuning)

```bash
openremap validate tuned target_tuned.bin recipe.json
```

The post-tune validator is the mirror image of strict validation: it checks that the modified bytes (`mb`) are now present at every recorded offset. This confirms the tune was written correctly, not just that it was attempted.

> 🔴 **After tuning, two things are mandatory before this binary goes anywhere near a vehicle.**
>
> **1. Checksum correction.** OpenRemap does not calculate or correct ECU checksums. Every ECU has internal checksums that must be recalculated after any binary modification. Use a dedicated checksum tool (WinOLS, ECM Titanium, or the appropriate standalone corrector for your ECU family). Flashing a binary with an incorrect checksum **will brick your ECU.**
>
> **2. Professional tuner review.** A recipe tells you what bytes changed — it does not tell you whether those changes are safe for your specific engine, fuel quality, hardware condition, or use case. Before flashing any modified binary to a vehicle, the tune must be reviewed and approved by a qualified, experienced tuner who can assess the calibration against the actual engine. Incorrect calibration can cause serious engine damage, turbo failure, or create unsafe driving conditions.
>
> OpenRemap is a tool for applying and auditing binary changes. The responsibility for what those changes do to an engine rests entirely with the person who created the tune and the professional who validated it.

---

## The recipe format

The recipe is a JSON file. Here is a simplified example of what a single instruction looks like:

```json
{
  "offset": 139264,
  "offset_hex": "22000",
  "size": 4,
  "ob": "3C0A0000",
  "mb": "500A0000",
  "ctx": "DEADBEEF12345678",
  "description": "4 bytes at 0x22000 modified"
}
```

Every field has a purpose:

| Field | What it is |
|---|---|
| `offset` | Absolute byte position in the binary |
| `ob` | Original bytes — what was there before tuning |
| `mb` | Modified bytes — what the tune wrote |
| `ctx` | Context anchor — bytes before the change, used to locate the instruction even if it shifted |
| `size` | Number of bytes changed |

The recipe also carries an `ecu` block with the match key, software version, and file hash of the original binary. When you apply a recipe to a target, the validator compares those values and warns you if anything does not line up.

Full format reference → [`recipe-format.md`](recipe-format.md)

---

## When would you actually use this

### You have two ECUs with the same software version

This is the most common scenario. You have already tuned one ECU — a stage 1, a remap, a flex fuel adjustment — and a second customer walks in with the same car, same ECU family, same software version. Instead of starting from scratch or manually replicating the changes, you cook a recipe from the first pair of binaries and apply it to the second ECU. The validator confirms the bytes match before anything is written. The whole process is auditable and repeatable.

### You want to know what a tune actually changes before flashing it

You have a modified binary from a third party — a tune you bought, a file from a forum, a calibration from another tuner. Before it goes near any ECU, you want to know exactly what it touches. Run `openremap cook` with the stock and the modified file. The recipe tells you every changed offset, every original byte, every modified byte. You decide if you trust it.

### You are developing a tune and want to track your changes between sessions

You are iterating on a calibration — adjusting, reflashing, data-logging, adjusting again. At the end of each session, cook a recipe between the previous version and the new one. You get an exact record of what changed in that session. Over time you build a complete history of every modification and when it was made, in a format you can read and diff in git.

### You are porting a tune across ECUs of the same family but different software revisions

You have a recipe built from software version A and a target ECU running software version B — the same family, a minor revision difference. Run `openremap validate exists` first. If it comes back with SHIFTED results rather than MISSING, the patcher's anchor search may recover the correct offsets automatically. If it comes back with MISSING instructions, the maps moved too far or the calibration is too different — stop there.

### You want to batch-identify a library of ECU binaries

```bash
# Preview results — dry-run is the default, nothing moves
openremap scan ./my_bins/

# Sort into a manufacturer/family tree once you're happy with the preview
openremap scan ./my_bins/ --move --organize
```

The `scan` command runs every binary in a folder through all registered extractors and prints the identification result for each one — manufacturer, family, software version, match key. Running without any flags is a safe preview: every file is classified and the result is printed but nothing is moved. When you are ready, pass `--move` to actually sort files into sub-folders (`scanned`, `sw_missing`, `contested`, `unknown`, `trash`). Add `--organize` to further sort identified files into a `manufacturer/family` tree (e.g. `scanned/Bosch/EDC17/`) — all required directories are created automatically. Useful for building a tidy library of collected files before processing them.

---

## The match key — why it matters

Every recipe embeds the match key of the binary it was built from. Every validator checks the match key of the target binary. If they do not match, you get a warning.

The match key is built from two things: the ECU family and the software version string extracted from the binary.

```
EDC17C66::1037541778126241V0
  ↑            ↑
  family        software version
```

The reason this matters: two ECUs from the same car model, even the same year, can have different software versions. The maps are at different offsets. The calibration values are different. A recipe built from version A applied to version B can write bytes to the wrong location entirely.

A match key mismatch is not a hard block — you can override it — but it is a serious warning. Unless you have confirmed through `validate exists` that the instructions land correctly on the target, a mismatch means stop.

For ECU families where no software version is readable from the binary, the match key falls back to another extracted field (calibration ID, hardware number). The patcher still works, but the identity guarantee is weaker.

---

## Frequently asked questions

**Do I need to know how to code to use OpenRemap?**
No. The CLI is designed to be usable by anyone comfortable with a terminal. You run commands, read the output, and pass files around. No programming required.

**Will running `identify` or `cook` modify my files?**
No. Both commands are completely read-only. `identify` reads the binary and prints results. `cook` reads two binaries and writes a recipe JSON — it never touches the input files. The only command that produces a modified binary is `tune`, and even then the original file is never overwritten — the tuned result is written to a separate output file.

**Can I break an ECU just by using OpenRemap?**
Not by identifying or cooking. Patching produces a modified binary, but that binary only matters when you flash it. OpenRemap does not flash anything — it hands you a file. What happens next is your responsibility and your flash tool's job.

**My strict validation failed. What do I do?**
Run `openremap validate exists` on the same target and recipe. Read the output. If all instructions come back EXACT or SHIFTED, the binary is the right ECU but possibly a different software revision — the patcher may still work. If any instructions come back MISSING, the binary is the wrong ECU or has already been modified at those locations. Do not proceed.

**Can I use this on encrypted or scrambled ECU binaries?**
No. OpenRemap works on plaintext binaries where the calibration data is readable. Some ECU variants store the calibration in an encrypted or scrambled region — the extractors will either fail to identify them or return incomplete results. A scrambled EDC16C8, for example, will be identified correctly (the boot sector is not scrambled) but the software version will come back as `null`.

**Does OpenRemap work on files larger than a full ECU flash?**
It works on whatever bytes you give it. If you pass a partial dump or a file with extra padding, the results depend on whether the extractor patterns fall within the data. For best results, use complete, unmodified flash dumps.

---

## Why open source

Professional calibration tools are closed systems. That is not a criticism — they carry years of reverse-engineered knowledge, proprietary map definitions, and hardware integration that justify the cost. For a workshop doing this at scale, they are the right choice.

But closed toolchains have a side effect: the knowledge stays inside them. How does the tool know where the maps are? How does it detect a Bosch EDC17 vs an EDC16? What exactly changed between the stock file and the tuned one? Those questions have answers, but the answers are locked away.

OpenRemap is built on the belief that this knowledge should be open, documented, and inspectable. Not to undercut commercial tools — but because open software can be studied, corrected, extended, and trusted in ways that closed software cannot.

Concretely, that means:

- **The extraction logic is readable.** You can open any extractor and see exactly how it identifies an EDC17, what byte patterns it looks for, and how it builds the match key. If it is wrong, you can fix it.
- **The recipe is inspectable.** Every change is recorded as plain JSON. There are no proprietary formats, no opaque blobs. You can read a recipe in a text editor and understand exactly what it will do before you run it.
- **The pipeline is scriptable.** Every step has a CLI interface with JSON output. You can integrate OpenRemap into your own tools, scripts, or workflows without asking anyone's permission.
- **The community can extend it.** Every ECU family that gets added benefits everyone. A tuner who figures out the SW version pattern for a Siemens SID can contribute an extractor and make the tool work for that entire family permanently.

---

## Project aims

OpenRemap is a **research and educational project.**

The goal is to build open, well-documented tooling for understanding ECU binary structure and the mechanics of binary-level calibration changes — not to enable unsafe or illegal modifications.

Concretely, the project aims to:

- Provide a transparent, auditable alternative for binary diff and patch workflows that is not locked to any commercial tool or vendor
- Build readable, documented extractors that identify ECU families from patterns observable through independent analysis of binaries — without relying on proprietary documentation, Damos files, or any information covered by NDA
- Give tuners and developers a shared vocabulary and toolchain for discussing and working with calibration changes
- Serve as a foundation for further research into ECU binary analysis, calibration portability, and safe patching practices

**What this project is not:**

OpenRemap is not a tool for bypassing emissions systems, deleting DPF or EGR, circumventing speed limiters, or making any modification that is illegal under the laws of your jurisdiction. Pull requests implementing such functionality will not be accepted. Users are solely responsible for ensuring their use of this software complies with applicable laws and regulations.

Any output produced by OpenRemap — recipes, patched binaries, identification results — is for research and analysis purposes. Flashing modified firmware to a vehicle must be done by a qualified professional who has reviewed and validated the calibration for the specific engine, vehicle, and use case.