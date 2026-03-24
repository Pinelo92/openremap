"""
OpenRemap CLI — root entry point.

Usage:
    openremap --help
    openremap --version
    openremap workflow
    openremap identify ecu.bin
    openremap cook stock.bin stage1.bin --output recipe.json
    openremap validate strict target.bin recipe.json
    openremap validate exists target.bin recipe.json
    openremap validate tuned target_tuned.bin recipe.json
    openremap tune target.bin recipe.json --output target_tuned.bin
    openremap scan ./my_bins/
    openremap scan ./my_bins/ --move --organize
"""

from importlib.metadata import version as _get_version
from typing import Optional

import typer

from openremap.cli.commands import validate
from openremap.cli.commands.cook import cook
from openremap.cli.commands.identify import identify
from openremap.cli.commands.scan import scan
from openremap.cli.commands.tune import tune
from openremap.cli.commands.workflow import workflow

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="openremap",
    help=(
        "OpenRemap — ECU binary analysis and patching toolkit.\n\n"
        "Diff, validate, and apply tuning recipes to automotive ECU binaries "
        "without a running API server.\n\n"
        "New here? Run  openremap workflow  for a plain-English step-by-step guide."
    ),
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# ---------------------------------------------------------------------------
# Version flag
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"openremap {_get_version('openremap')}")
        raise typer.Exit()


@app.callback()
def _callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

# workflow, identify, cook, tune, and scan are single-action commands —
# registered directly to avoid the Typer 0.12+ regression where
# @app.callback(invoke_without_command=True) with typer.Argument parameters
# fails when added via add_typer().

app.command(
    name="workflow",
    help=(
        "Print a complete step-by-step workflow guide — plain English, "
        "with commands, expected output, and what to do when something goes wrong. "
        "Start here if you are new to OpenRemap or the terminal."
    ),
)(workflow)

app.command(
    name="identify",
    help="Identify an ECU binary — manufacturer, family, software version, and more.",
    no_args_is_help=True,
)(identify)

app.command(
    name="cook",
    help="Cook a recipe by diffing an original and a modified ECU binary.",
    no_args_is_help=True,
)(cook)

# validate has real sub-commands (strict / exists / tuned) and uses
# @app.command() internally — add_typer works correctly for it.
app.add_typer(validate.app, name="validate")

app.command(
    name="tune",
    help=(
        "Apply a tuning recipe to a target ECU binary. "
        "Runs strict pre-flight validation before writing anything. "
        "The original file is never modified — the tuned result is written separately."
    ),
    no_args_is_help=True,
)(tune)

app.command(
    name="scan",
    help=(
        "Batch-scan a directory of ECU binaries through all registered extractors.\n\n"
        "Each file is classified and optionally moved into one of five sub-folders: "
        "scanned, sw_missing, contested, unknown, or trash."
    ),
)(scan)


if __name__ == "__main__":
    app()
