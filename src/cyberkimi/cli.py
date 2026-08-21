"""CyberKimi command-line interface."""

from __future__ import annotations

import getpass
import json
import shutil
from pathlib import Path
from typing import Annotated

import typer
import yaml

from cyberkimi import __version__
from cyberkimi.config import Settings
from cyberkimi.errors import CyberKimiError
from cyberkimi.ids import new_id
from cyberkimi.models import DataClassification, HealthReport
from cyberkimi.runtime import Runtime, build_runtime

app = typer.Typer(
    name="cyberkimi",
    no_args_is_help=True,
    invoke_without_command=True,
    help="Authorization-bound, evidence-first local security analysis.",
)
engagement_app = typer.Typer(no_args_is_help=True, help="Manage immutable engagement revisions.")
app.add_typer(engagement_app, name="engagement")

StateOption = Annotated[
    Path,
    typer.Option(
        "--state-directory",
        envvar="CYBERKIMI_STATE_DIR",
        help="CyberKimi local state directory.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
]


def _runtime(state_directory: Path) -> Runtime:
    return build_runtime(Settings.from_env(state_directory))


def _emit(value: object, *, json_output: bool = False) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=True)  # type: ignore[union-attr]
    if json_output:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, default=str))
    else:
        typer.echo(yaml.safe_dump(value, sort_keys=False).rstrip())


def _fatal(exc: Exception) -> None:
    typer.echo(f"error: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the installed CyberKimi version and exit.",
            is_eager=True,
        ),
    ] = False,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("init")
def initialize(state_directory: StateOption = Path(".cyberkimi")) -> None:
    """Initialize state, signing keys, vault key, database, and default tools."""

    try:
        runtime = _runtime(state_directory)
        typer.echo(f"initialized CyberKimi state at {runtime.settings.state_directory}")
    except (CyberKimiError, OSError, ValueError) as exc:
        _fatal(exc)


@app.command("doctor")
def doctor(
    state_directory: StateOption = Path(".cyberkimi"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify local state and optional deterministic scanner availability."""

    try:
        runtime = _runtime(state_directory)
        signing_key_ok = runtime.settings.scope_public_key_path.exists()
        vault_key_ok = runtime.settings.vault_key_path.exists()
        audit_chain_ok = True
        report = HealthReport(
            state_directory=str(runtime.settings.state_directory),
            database_ok=runtime.database.ping(),
            signing_key_ok=signing_key_ok,
            vault_key_ok=vault_key_ok,
            audit_chain_ok=audit_chain_ok,
            optional_tools={
                name: shutil.which(binary) is not None
                for name, binary in {
                    "semgrep": "semgrep",
                    "gitleaks": "gitleaks",
                    "osv-scanner": "osv-scanner",
                    "syft": "syft",
                    "docker": "docker",
                    "tshark": "tshark",
                }.items()
            },
        )
        _emit(report, json_output=json_output)
        if not all(
            (report.database_ok, report.signing_key_ok, report.vault_key_ok, report.audit_chain_ok)
        ):
            raise typer.Exit(code=1)
    except (CyberKimiError, OSError, ValueError) as exc:
        _fatal(exc)


@engagement_app.command("draft")
def engagement_draft(
    local_repo: Annotated[Path, typer.Option("--local-repo", exists=True, resolve_path=True)],
    output: Annotated[Path, typer.Option("--output")] = Path("engagement.yaml"),
    state_directory: StateOption = Path(".cyberkimi"),
    engagement_id: Annotated[str | None, typer.Option("--engagement-id")] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    owner_id: Annotated[str | None, typer.Option("--owner-id")] = None,
    classification: Annotated[DataClassification, typer.Option("--classification")] = (
        DataClassification.INTERNAL
    ),
    external_model: Annotated[bool, typer.Option("--external-model/--no-external-model")] = False,
) -> None:
    """Create a local draft; drafting does not authorize execution."""

    try:
        runtime = _runtime(state_directory)
        draft = runtime.engagements.draft_local(
            local_repo,
            engagement_id=engagement_id or new_id("ENG"),
            name=name or local_repo.name,
            owner_id=owner_id or f"user:{getpass.getuser()}",
            classification=classification,
            external_model_allowed=external_model,
        )
        runtime.engagements.write_manifest(draft, output)
        typer.echo(str(output.resolve()))
    except (CyberKimiError, OSError, ValueError) as exc:
        _fatal(exc)


@engagement_app.command("validate")
def engagement_validate(
    manifest: Annotated[Path, typer.Argument(exists=True, dir_okay=False, resolve_path=True)],
    state_directory: StateOption = Path(".cyberkimi"),
) -> None:
    """Validate a manifest and print its canonical digest without registering it."""

    try:
        runtime = _runtime(state_directory)
        engagement = runtime.engagements.load_manifest(manifest)
        typer.echo(runtime.engagements.validate(engagement))
    except (CyberKimiError, OSError, ValueError) as exc:
        _fatal(exc)


@engagement_app.command("create")
def engagement_create(
    manifest: Annotated[Path, typer.Argument(exists=True, dir_okay=False, resolve_path=True)],
    state_directory: StateOption = Path(".cyberkimi"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate, sign, and register engagement revision one."""

    try:
        runtime = _runtime(state_directory)
        engagement = runtime.engagements.load_manifest(manifest)
        active, signature = runtime.engagements.create(engagement)
        _emit(
            {
                "engagement": active.model_dump(mode="json", exclude_none=True),
                "signature": signature,
            },
            json_output=json_output,
        )
    except (CyberKimiError, OSError, ValueError) as exc:
        _fatal(exc)


@engagement_app.command("show")
def engagement_show(
    engagement_id: Annotated[str, typer.Argument()],
    revision: Annotated[int, typer.Option("--revision", min=1)],
    state_directory: StateOption = Path(".cyberkimi"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        runtime = _runtime(state_directory)
        _emit(runtime.engagements.get(engagement_id, revision), json_output=json_output)
    except (CyberKimiError, KeyError, OSError, ValueError) as exc:
        _fatal(exc)


@engagement_app.command("amend")
def engagement_amend(
    engagement_id: Annotated[str, typer.Argument()],
    manifest: Annotated[Path, typer.Argument(exists=True, dir_okay=False, resolve_path=True)],
    state_directory: StateOption = Path(".cyberkimi"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        runtime = _runtime(state_directory)
        replacement = runtime.engagements.load_manifest(manifest)
        active, signature = runtime.engagements.amend(engagement_id, replacement)
        _emit(
            {"engagement": active.model_dump(mode="json"), "signature": signature},
            json_output=json_output,
        )
    except (CyberKimiError, KeyError, OSError, ValueError) as exc:
        _fatal(exc)


@engagement_app.command("revoke")
def engagement_revoke(
    engagement_id: Annotated[str, typer.Argument()],
    revision: Annotated[int, typer.Option("--revision", min=1)],
    state_directory: StateOption = Path(".cyberkimi"),
) -> None:
    try:
        runtime = _runtime(state_directory)
        runtime.engagements.revoke(engagement_id, revision)
        typer.echo(f"revoked {engagement_id}@{revision}")
    except (CyberKimiError, KeyError, OSError, ValueError) as exc:
        _fatal(exc)


if __name__ == "__main__":
    app()
