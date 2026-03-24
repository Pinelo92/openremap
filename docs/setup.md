# Setup Guide

Everything you need to get `openremap` installed and working, from a fresh
machine to your first command.

---

## Prerequisites

| Requirement | Minimum version | Check |
|---|---|---|
| Python | 3.14 | `python --version` |
| uv | latest | `uv --version` |
| git | any | `git --version` |

### Installing Python

Download from https://www.python.org/downloads/ and follow the installer for
your platform. 

On macOS you can also use Homebrew:

```bash
brew install python@3.14
```

On Linux, use your package manager:

```bash
# Debian / Ubuntu
sudo apt install python3.14

# Fedora
sudo dnf install python3.14
```

### Installing uv

uv is the package and environment manager used by this project. It is fast,
reliable, and handles everything in one tool.

```bash
# macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Restart your terminal after installing. Verify with:

```bash
uv --version
```

Full uv documentation: https://docs.astral.sh/uv/

---

## Option A — Regular use (recommended for most people)

If you just want to use `openremap` as a command-line tool and are not
planning to contribute to the code, this is the right option.

`openremap` is published on [PyPI](https://pypi.org/project/openremap/), so
installation is a single command:

```bash
uv tool install openremap
```

Prefer plain pip? That works too:

```bash
pip install openremap
```

That is the only command you need. uv installs `openremap` into an isolated
environment and places the command on your system PATH permanently.

**What this means in practice:**

- `openremap` works from any folder on your machine
- No environment to activate before using it
- No `uv run` prefix required
- Survives reboots and new terminal sessions
- Does not affect any other Python tools or projects on your system

Verify the install:

```bash
openremap --version
openremap --help
```

If the command is not found after installing, see
[Troubleshooting](#troubleshooting) below.

---

## Option B — Development setup (for contributors)

If you want to work on the code, run the tests, or add a new ECU extractor,
clone the repository and use `uv sync` instead.

```bash
git clone https://github.com/Pinelo92/openremap.git
cd openremap
uv sync
```

`uv sync` creates a virtual environment at `.venv/` inside the project folder
and installs all dependencies into it. The `openremap` command is registered
inside that environment only — it is not on your global PATH.

You have two ways to run commands after this:

### Option B1 — Prefix with `uv run` (simplest, no activation needed)

```bash
uv run openremap identify ecu.bin
uv run openremap scan ./my_bins/
uv run pytest
```

`uv run` automatically uses the project's virtual environment for that single
call. You can use this from anywhere inside the project folder without any
setup step.

### Option B2 — Activate the environment once per session

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

After activation, the bare `openremap` command works for the rest of that
terminal session:

```bash
openremap identify ecu.bin
openremap scan ./my_bins/
pytest
```

The environment stays active until you close the terminal or run `deactivate`.

---

## Shell completion (optional)

Shell completion lets you press Tab to complete command names and flag names.
Highly recommended — it eliminates typos and makes flags discoverable without
reading the docs.

```bash
openremap --install-completion
```

Restart your terminal after running this. Then Tab-complete works:

```bash
openremap i<Tab>          # completes to: openremap identify
openremap scan --<Tab>    # shows: --dry-run  --move  --create-dirs  --organize
```

Supported shells: bash, zsh, fish, PowerShell.

If you installed via Option A (`uv tool install`), run the completion install
once and it persists permanently. If you installed via Option B (`uv sync`),
run it inside the activated environment or with `uv run`:

```bash
uv run openremap --install-completion
```

---

## Updating

### Option A (uv tool install / pip)

```bash
# uv
uv tool upgrade openremap

# pip
pip install --upgrade openremap
```

### Option B (development clone)

```bash
git pull
uv sync
```

`uv sync` will install any new or updated dependencies automatically.

---

## Uninstalling

### Option A

```bash
# uv
uv tool uninstall openremap

# pip
pip uninstall openremap
```

The command is removed from your PATH. Nothing else on your system is
affected.

### Option B

Delete the project folder. The virtual environment is self-contained inside
`.venv/` — removing the folder removes everything.

---

## Verifying the install

Run these three commands in order. If all three succeed, the install is
complete and correct.

```bash
# 1. The command is found and reports its version
openremap --version
# expected output: openremap x.y.z

# 2. The workflow guide prints without errors
openremap workflow

# 3. Scanning the current folder runs without errors (dry-run, nothing moves)
openremap scan .
```

---

## Troubleshooting

### `openremap: command not found` after `uv tool install`

uv installs tools into `~/.local/bin` (Linux/macOS) or
`%APPDATA%\Local\uv\bin` (Windows). This directory must be on your PATH.

Check whether it is:

```bash
# macOS / Linux
echo $PATH | tr ':' '\n' | grep -i uv

# Windows (PowerShell)
$env:PATH -split ';' | Select-String 'uv'
```

If it is missing, add it to your shell profile:

```bash
# bash — add to ~/.bashrc or ~/.bash_profile
export PATH="$HOME/.local/bin:$PATH"

# zsh — add to ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"

# fish
fish_add_path ~/.local/bin
```

Restart your terminal after editing the profile.

On Windows, run the uv installer again — it sets the PATH automatically via
the system environment variables dialog.

---

### `openremap: command not found` after `uv sync`

This is expected. After `uv sync` the command only exists inside the virtual
environment, not on your global PATH. Use `uv run openremap` or activate the
environment first. See [Option B](#option-b--development-setup-for-contributors).

---

### `python: command not found` or wrong Python version

uv manages its own Python installations and does not depend on the system
Python. If you have a Python version mismatch, let uv handle it:

```bash
uv python install 3.14
uv sync
```

---

### `uv: command not found`

uv is not installed or not on your PATH. Follow the
[Installing uv](#installing-uv) section above.

---

### `Permission denied` on Linux / macOS

Do not use `sudo` with uv. If you see a permission error, the most likely
cause is that `~/.local/bin` is owned by root. Fix it:

```bash
sudo chown -R $USER ~/.local
```

Then retry the install without `sudo`.

---

### Windows: `execution of scripts is disabled`

PowerShell's default execution policy blocks unsigned scripts. Run once to
allow user-level scripts:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then retry activating the environment or running the uv installer.

---

### Tests failing after `uv sync`

Run the test suite to confirm the development install is healthy:

```bash
uv run pytest core/tests/ -q
```

If tests fail on a fresh clone, open an issue with the output. The test suite
must be fully green before any contribution is submitted.

---

## Summary

| Goal | Command |
|---|---|
| Install for regular use | `uv tool install openremap` (or `pip install openremap`) |
| Check installed version | `openremap --version` or `openremap -V` |
| Update (regular use) | `uv tool upgrade openremap` |
| Uninstall (regular use) | `uv tool uninstall openremap` |
| Clone for development | `git clone … && cd openremap && uv sync` |
| Run a command (dev, no activation) | `uv run openremap <command>` |
| Activate environment (dev) | `source .venv/bin/activate` (macOS/Linux) |
| Activate environment (dev, Windows) | `.venv\Scripts\activate.bat` |
| Install shell completion | `openremap --install-completion` |
| Run tests | `uv run pytest core/tests/ -q` |

---

← [Back to README](../README.md)
