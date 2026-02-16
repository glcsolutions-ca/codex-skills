#!/usr/bin/env python3
"""
azure-rg-sandbox: workspace-scoped Azure sandbox lifecycle tool.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

SKILL_NAME = "azure-rg-sandbox"
STATE_VERSION = 1
SANDBOX_DIR_REL = Path(".codex/azure-rg-sandbox")
STATE_FILE_NAME = "state.json"
AZURE_CONFIG_DIR_NAME = "azure-config"
GITIGNORE_LINE = ".codex/azure-rg-sandbox/"

REQUIRED_STATE_FIELDS = {
    "version": int,
    "workspace_path": str,
    "workspace_id": str,
    "subscription_id": str,
    "tenant_id": str,
    "resource_group_name": str,
    "resource_group_scope": str,
    "location": str,
    "service_principal_app_id": str,
    "service_principal_object_id": str,
    "service_principal_display_name": str,
    "service_principal_client_secret": str,
    "created_at_utc": str,
    "updated_at_utc": str,
}


class CliError(Exception):
    """User-facing command error."""


class CommandError(Exception):
    """Subprocess command error."""

    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = stderr.strip() or stdout.strip() or f"Command failed with exit code {returncode}"
        super().__init__(message)


@dataclass
class WorkspacePaths:
    workspace: Path
    sandbox_dir: Path
    state_file: Path
    azure_config_dir: Path
    gitignore_file: Path


def now_utc_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_workspace_paths(workspace: Path | None = None) -> WorkspacePaths:
    workspace_path = (workspace or Path.cwd()).resolve()
    sandbox_dir = workspace_path / SANDBOX_DIR_REL
    return WorkspacePaths(
        workspace=workspace_path,
        sandbox_dir=sandbox_dir,
        state_file=sandbox_dir / STATE_FILE_NAME,
        azure_config_dir=sandbox_dir / AZURE_CONFIG_DIR_NAME,
        gitignore_file=workspace_path / ".gitignore",
    )


def run_cmd(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        cmd,
        env=env,
        text=True,
        capture_output=capture_output,
    )
    if check and process.returncode != 0:
        raise CommandError(cmd, process.returncode, process.stdout or "", process.stderr or "")
    return process


def run_az(
    args: list[str],
    *,
    azure_config_dir: Path | None = None,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if azure_config_dir is not None:
        env["AZURE_CONFIG_DIR"] = str(azure_config_dir)
    return run_cmd(["az", *args], env=env, check=check, capture_output=capture_output)


def az_json(args: list[str], *, azure_config_dir: Path | None = None) -> Any:
    process = run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
    payload = process.stdout.strip()
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CliError(f"Failed to parse JSON from Azure CLI output for: {' '.join(args)}") from exc


def az_tsv(args: list[str], *, azure_config_dir: Path | None = None) -> str:
    process = run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
    return process.stdout.strip()


def slugify(text: str) -> str:
    lower = text.strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "-", lower)
    normalized = normalized.strip("-")
    normalized = re.sub(r"-{2,}", "-", normalized)
    return normalized or "workspace"


def workspace_id_for(path: Path) -> tuple[str, str, str]:
    workspace_path = str(path.resolve())
    slug = slugify(path.name)
    digest = hashlib.sha256(workspace_path.encode("utf-8")).hexdigest()[:10]
    return slug, digest, f"{slug}-{digest}"


def default_resource_group_name(slug: str, digest: str) -> str:
    prefix = "codex-sbx"
    candidate = f"{prefix}-{slug}-{digest}"
    if len(candidate) <= 90:
        return candidate

    reserve = len(prefix) + len(digest) + 2
    allowed_slug_len = max(1, 90 - reserve)
    trimmed_slug = slug[:allowed_slug_len].strip("-") or "ws"
    return f"{prefix}-{trimmed_slug}-{digest}"[:90].rstrip("-")


def ensure_directory(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)


def ensure_gitignore_line(paths: WorkspacePaths) -> bool:
    line = GITIGNORE_LINE
    if paths.gitignore_file.exists():
        existing_text = paths.gitignore_file.read_text(encoding="utf-8")
        existing = existing_text.splitlines()
        if line in existing:
            return False
        needs_newline = existing_text != "" and not existing_text.endswith("\n")
        with paths.gitignore_file.open("a", encoding="utf-8") as handle:
            if needs_newline:
                handle.write("\n")
            handle.write(f"{line}\n")
        return True

    paths.gitignore_file.write_text(f"{line}\n", encoding="utf-8")
    return True


def gitignore_has_line(paths: WorkspacePaths) -> bool:
    if not paths.gitignore_file.exists():
        return False
    return GITIGNORE_LINE in paths.gitignore_file.read_text().splitlines()


def validate_state_data(state: dict[str, Any], workspace: Path) -> list[str]:
    errors: list[str] = []

    for field, expected in REQUIRED_STATE_FIELDS.items():
        if field not in state:
            errors.append(f"Missing state field: {field}")
            continue
        if not isinstance(state[field], expected):
            errors.append(
                f"Invalid type for '{field}': expected {expected.__name__}, got {type(state[field]).__name__}"
            )

    if state.get("version") != STATE_VERSION:
        errors.append(f"Unsupported state version: {state.get('version')} (expected {STATE_VERSION})")

    expected_workspace = str(workspace.resolve())
    if isinstance(state.get("workspace_path"), str) and state["workspace_path"] != expected_workspace:
        errors.append(
            "State file workspace_path does not match current workspace. "
            f"Expected '{expected_workspace}', found '{state['workspace_path']}'"
        )

    rg_name = state.get("resource_group_name")
    sub_id = state.get("subscription_id")
    scope = state.get("resource_group_scope")
    if isinstance(rg_name, str) and isinstance(sub_id, str) and isinstance(scope, str):
        expected_scope = f"/subscriptions/{sub_id}/resourceGroups/{rg_name}"
        if scope != expected_scope:
            errors.append(
                "State resource_group_scope does not match subscription/resource_group_name. "
                f"Expected '{expected_scope}', found '{scope}'"
            )

    return errors


def load_state(paths: WorkspacePaths) -> dict[str, Any]:
    if not paths.state_file.exists():
        raise CliError(
            f"Sandbox state not found at {paths.state_file}. Run 'sandbox init --location <location>' first."
        )

    try:
        raw = paths.state_file.read_text(encoding="utf-8")
        state = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError(f"State file is not valid JSON: {paths.state_file}") from exc

    if not isinstance(state, dict):
        raise CliError(f"State file root must be a JSON object: {paths.state_file}")

    validation_errors = validate_state_data(state, paths.workspace)
    if validation_errors:
        raise CliError("State validation failed:\n- " + "\n- ".join(validation_errors))

    return state


def write_state(paths: WorkspacePaths, state: dict[str, Any]) -> None:
    ensure_directory(paths.sandbox_dir, 0o700)
    temp_file = paths.state_file.with_suffix(".tmp")
    payload = json.dumps(state, indent=2, sort_keys=True) + "\n"
    temp_file.write_text(payload, encoding="utf-8")
    os.chmod(temp_file, 0o600)
    temp_file.replace(paths.state_file)
    os.chmod(paths.state_file, 0o600)


def looks_like_not_found(message: str) -> bool:
    lower = message.lower()
    return any(
        token in lower
        for token in (
            "could not be found",
            "was not found",
            "does not exist",
            "no matched role assignments",
            "not found",
        )
    )


def best_effort_az(args: list[str], *, azure_config_dir: Path | None = None) -> tuple[bool, str]:
    try:
        run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
        return True, "ok"
    except CommandError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        if looks_like_not_found(message):
            return True, f"already absent ({message})"
        return False, message


def ensure_sandbox_login(state: dict[str, Any], paths: WorkspacePaths) -> tuple[bool, str]:
    expected_sub = state["subscription_id"]

    try:
        account = az_json(["account", "show", "--output", "json"], azure_config_dir=paths.azure_config_dir)
        if str(account.get("id", "")).lower() == expected_sub.lower():
            return True, "already authenticated"
    except (CommandError, CliError):
        pass

    run_az(
        [
            "login",
            "--service-principal",
            "--username",
            state["service_principal_app_id"],
            "--password",
            state["service_principal_client_secret"],
            "--tenant",
            state["tenant_id"],
            "--output",
            "none",
        ],
        azure_config_dir=paths.azure_config_dir,
        check=True,
        capture_output=True,
    )
    run_az(
        ["account", "set", "--subscription", expected_sub],
        azure_config_dir=paths.azure_config_dir,
        check=True,
        capture_output=True,
    )

    account_after = az_json(
        ["account", "show", "--output", "json"],
        azure_config_dir=paths.azure_config_dir,
    )
    if str(account_after.get("id", "")).lower() != expected_sub.lower():
        raise CliError(
            "Service principal login succeeded, but Azure CLI is not on the expected subscription "
            f"'{expected_sub}'."
        )

    return True, "re-authenticated"


def resolve_subscription_and_tenant(subscription_arg: str | None) -> tuple[str, str]:
    args = ["account", "show", "--output", "json"]
    if subscription_arg:
        args.extend(["--subscription", subscription_arg])
    account = az_json(args)

    subscription_id = str(account.get("id", "")).strip()
    tenant_id = str(account.get("tenantId", "")).strip()

    if not subscription_id or not tenant_id:
        raise CliError("Unable to resolve subscription_id or tenant_id from az account context.")

    return subscription_id, tenant_id


def parse_option_values(args: list[str], long_name: str, short_name: str | None = None) -> list[str]:
    values: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith(f"{long_name}="):
            values.append(token.split("=", 1)[1])
        elif token == long_name:
            if i + 1 >= len(args):
                raise CliError(f"Missing value for option {long_name}")
            values.append(args[i + 1])
            i += 1
        elif short_name and token == short_name:
            if i + 1 >= len(args):
                raise CliError(f"Missing value for option {short_name}")
            values.append(args[i + 1])
            i += 1
        i += 1
    return values


def parse_ids_values(args: list[str]) -> list[str]:
    ids: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("--ids="):
            raw = token.split("=", 1)[1]
            ids.extend([piece for piece in raw.split(",") if piece])
        elif token == "--ids":
            i += 1
            while i < len(args) and not args[i].startswith("-"):
                ids.extend([piece for piece in args[i].split(",") if piece])
                i += 1
            continue
        i += 1
    return ids


def parse_scopes_values(args: list[str]) -> list[str]:
    values: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("--scopes="):
            raw = token.split("=", 1)[1]
            if raw:
                values.extend(raw.split())
        elif token == "--scopes":
            i += 1
            while i < len(args) and not args[i].startswith("-"):
                values.append(args[i])
                i += 1
            continue
        i += 1
    return values


def enforce_guardrails(az_args: list[str], state: dict[str, Any]) -> None:
    expected_sub = state["subscription_id"]
    expected_rg = state["resource_group_name"]
    expected_scope = state["resource_group_scope"].lower()

    for sub in parse_option_values(az_args, "--subscription", "-s"):
        if sub.lower() != expected_sub.lower():
            raise CliError(
                "Sandbox guardrail violation: --subscription must equal "
                f"'{expected_sub}', got '{sub}'."
            )

    for rg in parse_option_values(az_args, "--resource-group", "-g"):
        if rg.lower() != expected_rg.lower():
            raise CliError(
                "Sandbox guardrail violation: --resource-group must equal "
                f"'{expected_rg}', got '{rg}'."
            )

    for scope in parse_option_values(az_args, "--scope"):
        if not scope.lower().startswith(expected_scope):
            raise CliError(
                "Sandbox guardrail violation: --scope must be within "
                f"'{state['resource_group_scope']}', got '{scope}'."
            )

    for scope in parse_scopes_values(az_args):
        if not scope.lower().startswith(expected_scope):
            raise CliError(
                "Sandbox guardrail violation: --scopes must be within "
                f"'{state['resource_group_scope']}', got '{scope}'."
            )

    for resource_id in parse_ids_values(az_args):
        if not resource_id.lower().startswith(expected_scope):
            raise CliError(
                "Sandbox guardrail violation: --ids entry must be within "
                f"'{state['resource_group_scope']}', got '{resource_id}'."
            )


def check_health(
    paths: WorkspacePaths,
    state: dict[str, Any],
    *,
    allow_relogin: bool,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    remediations: list[str] = []

    def add_check(name: str, ok: bool, details: str, remediation: str | None = None) -> None:
        checks.append({"name": name, "ok": ok, "details": details})
        if not ok and remediation:
            remediations.append(remediation)

    add_check(
        "state-schema",
        True,
        f"State is present and version {state['version']} fields are valid.",
    )

    rg_exists = False
    try:
        exists = az_tsv(
            [
                "group",
                "exists",
                "--name",
                state["resource_group_name"],
                "--subscription",
                state["subscription_id"],
                "--output",
                "tsv",
            ]
        )
        rg_exists = exists.strip().lower() == "true"
        add_check(
            "resource-group-exists",
            rg_exists,
            f"Resource group '{state['resource_group_name']}' exists={rg_exists}.",
            "Run 'sandbox init --location <location> --recreate' to re-establish the boundary.",
        )
    except CommandError as exc:
        add_check(
            "resource-group-exists",
            False,
            exc.stderr.strip() or exc.stdout.strip() or str(exc),
            "Ensure your current user can read subscription resources and rerun status.",
        )

    sp_exists = False
    try:
        sp_id = az_tsv(
            [
                "ad",
                "sp",
                "show",
                "--id",
                state["service_principal_app_id"],
                "--query",
                "id",
                "--output",
                "tsv",
            ]
        )
        sp_exists = bool(sp_id)
        add_check(
            "service-principal-exists",
            sp_exists,
            f"Service principal appId '{state['service_principal_app_id']}' exists={sp_exists}.",
            "Run 'sandbox init --location <location> --recreate' to recreate the service principal.",
        )
    except CommandError as exc:
        add_check(
            "service-principal-exists",
            False,
            exc.stderr.strip() or exc.stdout.strip() or str(exc),
            "Ensure the current account can query Entra ID objects and rerun status.",
        )

    owner_assignment_ok = False
    if sp_exists and rg_exists:
        try:
            owner_assignments = az_json(
                [
                    "role",
                    "assignment",
                    "list",
                    "--assignee-object-id",
                    state["service_principal_object_id"],
                    "--scope",
                    state["resource_group_scope"],
                    "--role",
                    "Owner",
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--output",
                    "json",
                ]
            )
            owner_assignment_ok = isinstance(owner_assignments, list) and len(owner_assignments) > 0
            add_check(
                "owner-assignment",
                owner_assignment_ok,
                f"Owner assignment count at RG scope: {len(owner_assignments) if isinstance(owner_assignments, list) else 0}.",
                "Run 'sandbox init --location <location> --recreate' to rebind Owner at RG scope.",
            )
        except CommandError as exc:
            add_check(
                "owner-assignment",
                False,
                exc.stderr.strip() or exc.stdout.strip() or str(exc),
                "Check RBAC permissions for the current user and rerun status.",
            )
    else:
        add_check(
            "owner-assignment",
            False,
            "Skipped because resource group or service principal check failed.",
            "Repair missing resources first, then rerun status.",
        )

    if sp_exists:
        try:
            assignments = az_json(
                [
                    "role",
                    "assignment",
                    "list",
                    "--assignee-object-id",
                    state["service_principal_object_id"],
                    "--all",
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--output",
                    "json",
                ]
            )
            outside = []
            expected_scope = state["resource_group_scope"].lower()
            if isinstance(assignments, list):
                for assignment in assignments:
                    scope = str(assignment.get("scope", "")).lower()
                    if scope and not scope.startswith(expected_scope):
                        outside.append(scope)
            is_scoped = len(outside) == 0
            details = "All role assignments are within the sandbox scope." if is_scoped else (
                "Detected role assignments outside sandbox scope: " + ", ".join(outside[:5])
            )
            add_check(
                "assignment-boundary",
                is_scoped,
                details,
                "Remove external role assignments or recreate the sandbox boundary.",
            )
        except CommandError as exc:
            add_check(
                "assignment-boundary",
                False,
                exc.stderr.strip() or exc.stdout.strip() or str(exc),
                "Ensure role assignment listing permissions are available for the current user.",
            )
    else:
        add_check(
            "assignment-boundary",
            False,
            "Skipped because service principal check failed.",
            "Repair or recreate the service principal first.",
        )

    auth_ok = False
    auth_detail = ""
    try:
        account = az_json(["account", "show", "--output", "json"], azure_config_dir=paths.azure_config_dir)
        auth_ok = str(account.get("id", "")).lower() == state["subscription_id"].lower()
        auth_detail = f"Sandbox AZURE_CONFIG_DIR account id={account.get('id', '')}."
    except (CommandError, CliError) as exc:
        auth_detail = str(exc)

    if not auth_ok and allow_relogin:
        try:
            _, login_detail = ensure_sandbox_login(state, paths)
            auth_ok = True
            auth_detail = f"Recovered sandbox authentication ({login_detail})."
        except (CommandError, CliError) as exc:
            auth_detail = str(exc)

    add_check(
        "sandbox-auth",
        auth_ok,
        auth_detail,
        "Run 'sandbox init --location <location> --recreate' if credentials are expired or invalid.",
    )

    ignore_ok = gitignore_has_line(paths)
    add_check(
        "gitignore-protection",
        ignore_ok,
        f"{paths.gitignore_file} contains '{GITIGNORE_LINE}'={ignore_ok}.",
        "Add '.codex/azure-rg-sandbox/' to workspace .gitignore.",
    )

    healthy = all(check["ok"] for check in checks)
    return {"healthy": healthy, "checks": checks, "remediation": remediations}


def print_status_report(report: dict[str, Any]) -> None:
    print(f"healthy: {str(report['healthy']).lower()}")
    for check in report["checks"]:
        badge = "OK" if check["ok"] else "FAIL"
        print(f"[{badge}] {check['name']}: {check['details']}")
    if report["remediation"]:
        print("remediation:")
        for item in report["remediation"]:
            print(f"- {item}")


def destroy_boundary(
    state: dict[str, Any],
    paths: WorkspacePaths,
) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []

    rg_ok, rg_detail = best_effort_az(
        [
            "group",
            "delete",
            "--name",
            state["resource_group_name"],
            "--subscription",
            state["subscription_id"],
            "--yes",
        ]
    )
    operations.append({"step": "delete-resource-group", "ok": rg_ok, "details": rg_detail})

    assignment_ok, assignment_detail = best_effort_az(
        [
            "role",
            "assignment",
            "delete",
            "--assignee-object-id",
            state["service_principal_object_id"],
            "--role",
            "Owner",
            "--scope",
            state["resource_group_scope"],
            "--subscription",
            state["subscription_id"],
        ]
    )
    operations.append({"step": "delete-role-assignment", "ok": assignment_ok, "details": assignment_detail})

    sp_ok, sp_detail = best_effort_az(["ad", "sp", "delete", "--id", state["service_principal_app_id"]])
    operations.append({"step": "delete-service-principal", "ok": sp_ok, "details": sp_detail})

    app_ok, app_detail = best_effort_az(["ad", "app", "delete", "--id", state["service_principal_app_id"]])
    operations.append({"step": "delete-application", "ok": app_ok, "details": app_detail})

    if paths.sandbox_dir.exists():
        shutil.rmtree(paths.sandbox_dir)

    healthy = all(step["ok"] for step in operations)
    return {"healthy": healthy, "operations": operations}


def cmd_init(args: argparse.Namespace) -> int:
    if not args.location:
        raise CliError("init requires --location <azure-location>.")

    paths = resolve_workspace_paths()
    ensure_directory(paths.sandbox_dir, 0o700)

    if paths.state_file.exists():
        existing_state = load_state(paths)
        if args.recreate:
            destroy_result = destroy_boundary(existing_state, paths)
            if not destroy_result["healthy"]:
                details = "; ".join(
                    f"{step['step']}: {step['details']}" for step in destroy_result["operations"] if not step["ok"]
                )
                raise CliError(
                    "Failed to fully destroy existing sandbox during --recreate. "
                    f"Resolve errors and retry: {details}"
                )
            ensure_directory(paths.sandbox_dir, 0o700)
        else:
            report = check_health(paths, existing_state, allow_relogin=True)
            if report["healthy"]:
                payload = {
                    "status": "already-initialized",
                    "workspace": str(paths.workspace),
                    "resource_group_name": existing_state["resource_group_name"],
                    "subscription_id": existing_state["subscription_id"],
                }
                if args.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(
                        "Sandbox is already initialized and healthy "
                        f"for resource group '{existing_state['resource_group_name']}'."
                    )
                return 0

            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print("Existing sandbox state is unhealthy. Refusing to create duplicate boundary.")
                print_status_report(report)
                print("Re-run with --recreate to destroy and reinitialize the sandbox boundary.")
            return 1

    subscription_id, tenant_id = resolve_subscription_and_tenant(args.subscription)

    slug, digest, workspace_id = workspace_id_for(paths.workspace)
    resource_group = args.resource_group or default_resource_group_name(slug, digest)
    sp_name = resource_group
    scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"

    run_az(
        [
            "group",
            "create",
            "--name",
            resource_group,
            "--location",
            args.location,
            "--subscription",
            subscription_id,
            "--tags",
            "codex-sandbox=true",
            f"codex-workspace-id={workspace_id}",
            f"codex-skill={SKILL_NAME}",
            "--output",
            "none",
        ],
        check=True,
        capture_output=True,
    )

    create_payload = az_json(
        [
            "ad",
            "sp",
            "create-for-rbac",
            "--name",
            sp_name,
            "--role",
            "Owner",
            "--scopes",
            scope,
            "--years",
            "1",
            "--output",
            "json",
        ]
    )

    app_id = str(create_payload.get("appId", "")).strip()
    client_secret = str(create_payload.get("password", "")).strip()
    tenant_from_create = str(create_payload.get("tenant", "")).strip()

    if not app_id or not client_secret:
        raise CliError(
            "Unexpected output from 'az ad sp create-for-rbac': missing appId/password. "
            "No state file was written."
        )

    if tenant_from_create:
        tenant_id = tenant_from_create

    sp_object_id = az_tsv(
        [
            "ad",
            "sp",
            "show",
            "--id",
            app_id,
            "--query",
            "id",
            "--output",
            "tsv",
        ]
    )
    if not sp_object_id:
        raise CliError("Failed to resolve service principal object id after creation.")

    state_now = now_utc_iso()
    state = {
        "version": STATE_VERSION,
        "workspace_path": str(paths.workspace),
        "workspace_id": workspace_id,
        "subscription_id": subscription_id,
        "tenant_id": tenant_id,
        "resource_group_name": resource_group,
        "resource_group_scope": scope,
        "location": args.location,
        "service_principal_app_id": app_id,
        "service_principal_object_id": sp_object_id,
        "service_principal_display_name": sp_name,
        "service_principal_client_secret": client_secret,
        "created_at_utc": state_now,
        "updated_at_utc": state_now,
    }

    ensure_directory(paths.azure_config_dir, 0o700)
    ensure_sandbox_login(state, paths)
    write_state(paths, state)
    ensure_gitignore_line(paths)

    payload = {
        "status": "initialized",
        "workspace": str(paths.workspace),
        "resource_group_name": resource_group,
        "resource_group_scope": scope,
        "subscription_id": subscription_id,
        "tenant_id": tenant_id,
        "service_principal_app_id": app_id,
        "state_file": str(paths.state_file),
        "azure_config_dir": str(paths.azure_config_dir),
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Initialized Azure sandbox boundary for workspace: {paths.workspace}")
        print(f"- resource group: {resource_group}")
        print(f"- scope: {scope}")
        print(f"- service principal app id: {app_id}")
        print(f"- state file: {paths.state_file}")

    return 0


def cmd_az(args: argparse.Namespace) -> int:
    if not args.az_args:
        raise CliError("Usage: sandbox az <azure-cli-args...>")

    paths = resolve_workspace_paths()
    state = load_state(paths)

    enforce_guardrails(args.az_args, state)
    ensure_sandbox_login(state, paths)

    env = os.environ.copy()
    env["AZURE_CONFIG_DIR"] = str(paths.azure_config_dir)

    result = subprocess.run(["az", *args.az_args], env=env)
    return result.returncode


def cmd_status(args: argparse.Namespace) -> int:
    paths = resolve_workspace_paths()

    if not paths.state_file.exists():
        report = {
            "healthy": False,
            "checks": [
                {
                    "name": "state-schema",
                    "ok": False,
                    "details": f"State file not found: {paths.state_file}",
                }
            ],
            "remediation": [
                "Run 'sandbox init --location <location>' to create a new workspace sandbox boundary."
            ],
        }
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print_status_report(report)
        return 1

    try:
        state = load_state(paths)
    except CliError as exc:
        report = {
            "healthy": False,
            "checks": [
                {
                    "name": "state-schema",
                    "ok": False,
                    "details": str(exc),
                }
            ],
            "remediation": [
                "Repair or remove the invalid state file, then run 'sandbox init --location <location> --recreate'."
            ],
        }
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print_status_report(report)
        return 1

    report = check_health(paths, state, allow_relogin=True)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_status_report(report)

    return 0 if report["healthy"] else 1


def cmd_destroy(args: argparse.Namespace) -> int:
    if not args.yes:
        raise CliError("Refusing to destroy without --yes.")

    paths = resolve_workspace_paths()
    state = load_state(paths)

    result = destroy_boundary(state, paths)

    payload = {
        "status": "destroyed" if result["healthy"] else "destroyed-with-errors",
        "workspace": str(paths.workspace),
        "resource_group_name": state["resource_group_name"],
        "service_principal_app_id": state["service_principal_app_id"],
        "operations": result["operations"],
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Destroyed workspace sandbox boundary for {paths.workspace}")
        for op in result["operations"]:
            badge = "OK" if op["ok"] else "FAIL"
            print(f"[{badge}] {op['step']}: {op['details']}")

    return 0 if result["healthy"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sandbox",
        description="Workspace-scoped Azure resource-group sandbox lifecycle tool.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create or validate the workspace sandbox boundary.")
    init_parser.add_argument("--location", help="Azure location for the sandbox resource group.")
    init_parser.add_argument("--subscription", help="Subscription ID to bind this workspace sandbox.")
    init_parser.add_argument("--resource-group", help="Override default deterministic resource group name.")
    init_parser.add_argument("--recreate", action="store_true", help="Destroy existing boundary before re-initializing.")
    init_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    init_parser.set_defaults(func=cmd_init)

    az_parser = subparsers.add_parser("az", help="Run az commands through sandbox guardrails.")
    az_parser.add_argument("az_args", nargs=argparse.REMAINDER, help="Arguments passed directly to az.")
    az_parser.set_defaults(func=cmd_az)

    status_parser = subparsers.add_parser("status", help="Report sandbox health and drift checks.")
    status_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    status_parser.set_defaults(func=cmd_status)

    destroy_parser = subparsers.add_parser("destroy", help="Tear down sandbox resources and local state.")
    destroy_parser.add_argument("--yes", action="store_true", help="Confirm destructive teardown.")
    destroy_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    destroy_parser.set_defaults(func=cmd_destroy)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # argparse.REMAINDER keeps a leading '--' separator; drop it for passthrough.
    if getattr(args, "az_args", None) and args.az_args and args.az_args[0] == "--":
        args.az_args = args.az_args[1:]

    try:
        return args.func(args)
    except CliError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except CommandError as exc:
        cmd_text = " ".join(exc.cmd)
        details = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        print(f"ERROR: Command failed: {cmd_text}\n{details}", file=sys.stderr)
        return exc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
