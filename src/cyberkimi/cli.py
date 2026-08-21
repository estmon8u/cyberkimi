from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .domain import DataClassification
from .manifest import load_manifest, provision_repository_manifest, write_manifest
from .orchestrator import CyberKimi


app = typer.Typer(
    name="cyberkimi",
    help="Evidence-first security analysis harness for authorized engagements.",
    no_args_is_help=False,
    invoke_without_command=True,
)
engagement_app = typer.Typer(help="Provision, validate, and register engagement manifests.")
app.add_typer(engagement_app, name="engagement")

StateOption = Annotated[
    Path,
    typer.Option("--state-directory", "-s", help="Trusted local CyberKimi state directory."),
]


@app.callback()
def root(
    context: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", help="Print the CyberKimi version and exit.", is_eager=True),
    ] = False,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if context.invoked_subcommand is None:
        typer.echo(context.get_help())
        raise typer.Exit()


@app.command("init")
def initialize(state_directory: StateOption = Path(".cyberkimi")) -> None:
    instance = CyberKimi(state_directory)
    typer.echo(f"Initialized CyberKimi state at {instance.paths.root}")


@engagement_app.command("provision")
def provision(
    target: Annotated[Path, typer.Option("--target", exists=True, file_okay=False)],
    owner: Annotated[str, typer.Option("--owner")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("engagement.yaml"),
    classification: Annotated[
        DataClassification,
        typer.Option("--data-classification", case_sensitive=False),
    ] = DataClassification.INTERNAL,
) -> None:
    manifest = provision_repository_manifest(
        target,
        owner=owner,
        classification=classification,
    )
    write_manifest(manifest, output)
    typer.echo(f"Wrote {manifest.engagement_id} to {output}")


@engagement_app.command("validate")
def validate_manifest(path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    manifest = load_manifest(path)
    typer.echo(
        json.dumps(
            {
                "valid": True,
                "engagement_id": manifest.engagement_id,
                "revision": manifest.revision,
                "assets": [asset.id for asset in manifest.assets],
            },
            indent=2,
        )
    )


@engagement_app.command("create")
def create_engagement(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    state_directory: StateOption = Path(".cyberkimi"),
) -> None:
    instance = CyberKimi(state_directory)
    assets = instance.register_manifest_file(path)
    typer.echo(
        json.dumps(
            {
                "registered": True,
                "manifest": str(path),
                "asset_revisions": assets,
            },
            indent=2,
        )
    )


@app.command("review")
def review(
    asset_id: Annotated[str, typer.Argument(help="Registered repository asset alias or revision.")],
    engagement_id: Annotated[str, typer.Option("--engagement", "-e")],
    goal: Annotated[str, typer.Option("--goal", "-g")],
    state_directory: StateOption = Path(".cyberkimi"),
) -> None:
    instance = CyberKimi(state_directory)
    result = instance.review_repository(
        engagement_id=engagement_id,
        asset_id=asset_id,
        goal=goal,
    )
    typer.echo(
        json.dumps(
            {
                "task_id": result.task_id,
                "asset_revision": result.asset_revision,
                "files": result.file_count,
                "dependencies": result.dependency_count,
                "secret_signals": result.secret_signal_count,
                "confirmed_findings": result.confirmed_finding_count,
                "unresolved_findings": result.unresolved_finding_count,
                "report": str(result.report_path),
            },
            indent=2,
        )
    )


@app.command("doctor")
def doctor(state_directory: StateOption = Path(".cyberkimi")) -> None:
    checks: dict[str, object] = {
        "python": platform.python_version(),
        "python_supported": sys.version_info >= (3, 12),
        "state_directory": str(state_directory.expanduser().resolve()),
        "moonshot_key_configured": bool(os.getenv("MOONSHOT_API_KEY")),
        "control_plane_secret_leak_candidates": sorted(
            key
            for key in os.environ
            if key.startswith("CYBERKIMI_TOOL_")
            and any(marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
        ),
    }
    try:
        instance = CyberKimi(state_directory)
        instance.database.fetch_one("SELECT 1 AS healthy")
        checks["state_initialized"] = True
        checks["database_healthy"] = True
    except Exception as exc:  # pragma: no cover - command reports diagnostics by design
        checks["state_initialized"] = False
        checks["database_healthy"] = False
        checks["error"] = str(exc)
    healthy = bool(checks["python_supported"]) and bool(checks.get("database_healthy")) and not checks[
        "control_plane_secret_leak_candidates"
    ]
    checks["healthy"] = healthy
    typer.echo(json.dumps(checks, indent=2, sort_keys=True))
    if not healthy:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
