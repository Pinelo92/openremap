# OpenRemap

[![CI](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml/badge.svg)](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openremap.svg)](https://pypi.org/project/openremap/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

Extract what changed between a stock and a tuned ECU binary. Replay that change — safely — on any matching ECU.

Drop any `.bin` at it — manufacturer, ECU family, software version, match key, all back in under a second. Point it at a folder of hundreds of binaries — sorted into `Bosch/EDC17/`, `Siemens/SIM2K/` automatically, nothing moved until you say so. Diff a stock and a tuned binary and the difference becomes a portable **recipe** — validated against any target before touching it, applied byte-by-byte with a full audit trail, verified after the fact. No guessing, no blind flashing.

Built for tuners who want to understand what they're writing to an ECU, and for developers who want an open, scriptable alternative to closed tuning toolchains. → [How it works in detail](docs/about.md)

---

## Install

Now on PyPI — no git URL required. Requires [Python 3.14+](https://www.python.org/downloads/) and [uv](https://github.com/astral-sh/uv).
Full setup guide → [`docs/setup.md`](docs/setup.md)

### Regular use

```bash
uv tool install openremap
```

Installs `openremap` permanently on your system PATH. Works from any folder,
no environment to activate, survives reboots. Verify with:

```bash
openremap --version
```

Prefer `pip`? That works too:

```bash
pip install openremap
```

### Contributing / development

```bash
git clone https://github.com/Pinelo92/openremap.git
cd openremap
uv sync
```

After `uv sync` the command lives inside the virtual environment. Either
prefix every call with `uv run`, or activate the environment first:

```bash
# Option A — prefix (no activation needed)
uv run openremap identify ecu.bin

# Option B — activate once per session, then use bare command
source .venv/bin/activate          # macOS / Linux
.venv\Scripts\activate             # Windows
openremap identify ecu.bin
```

---

## CLI Quickstart

> **New here?** Run `openremap workflow` first — it prints a complete plain-English
> guide with every step, the exact commands to type, and what to do when something
> goes wrong. No reading required.

Full CLI Guide → [`docs/cli.md`](docs/cli.md)

```bash
# New users: print the full step-by-step workflow guide
openremap workflow

# Identify an ECU binary
openremap identify ecu.bin

# Extract the tune — diff a stock and a modified binary into a recipe
openremap cook stock.bin stage1.bin --output recipe.json

# Validate the target before touching it
openremap validate strict target.bin recipe.json

# Apply the tune
openremap tune target.bin recipe.json --output target_tuned.bin

# Confirm every byte landed correctly
openremap validate tuned target_tuned.bin recipe.json

# Batch-scan a folder of binaries — dry-run is the default, nothing moves
openremap scan ./my_bins/

# Sort files into a manufacturer/family tree once you're happy with the preview
openremap scan ./my_bins/ --move --organize
```

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
> Before flashing any tuned binary to a vehicle, you **must** run it through a
> dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent).
> `openremap validate tuned` confirms the recipe was applied — it does **not**
> correct or validate ECU checksums. Flashing a binary with an incorrect checksum
> **will brick your ECU.** No exceptions.

---

## Supported ECU Families

All current extractors are Bosch. The registry is built to be extended to any manufacturer without touching existing code.

| Family | Era | Notes |
|---|---|---|
| EDC1 / EDC2 | 1990–1997 | Audi 80/A6 TDI, 32 KB / 64 KB |
| EDC 3.x | 1993–2000 | VAG TDI diesel bridge generation |
| EDC15 | 1997–2004 | Format A (TSW) and Format B (C3-fill) |
| EDC16 | 2003–2008 | `0xDECAFE` magic, 256 KB / 1 MB / 2 MB |
| EDC17 / MEDC17 / MED17 / ME17 | 2008+ | PSA, VAG, BMW diesel and petrol |
| ME7 | 1999–2006 | VAG 1.8T, Porsche, Ferrari |
| M1.x | 1987–1996 | BMW, early VAG, unique ROM header |
| M1.55 | 1994–2002 | Alfa Romeo 155/156/GT, 128 KB |
| M2.x | 1993–1999 | Porsche 964 (M2.3) and related |
| M3.x | 1989–1999 | BMW E30/E36 petrol |
| M5.x / M3.8x | 1997–2004 | VW/Audi 1.8T (AGU, AUM, APX) |
| LH-Jetronic | 1982–1995 | Volvo, early BMW/Mercedes |
| Motronic Legacy | various | Early 6802-era Bosch DME / KE / EZK |

---

> ⚠️ **Research and educational use only.** Any output produced by this software must be reviewed by a qualified professional before being flashed to a vehicle. The authors accept no liability for damage, loss, or legal consequences arising from its use. Read the full [DISCLAIMER](DISCLAIMER.md) before proceeding.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/setup.md`](docs/setup.md) | Full install guide — regular use, development, shell completion, updating, troubleshooting |
| [`docs/cli.md`](docs/cli.md) | Commands guide — what each command does, with links to full per-command pages |
| [`docs/recipe-format.md`](docs/recipe-format.md) | The recipe JSON spec — fields, structure, versioning |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add a new ECU extractor, code style, submitting a PR, contributor safety notice |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Liability, intended use, professional review requirements, legal notice |

---

## Contributing

Contributions are welcome — especially new ECU family extractors. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
