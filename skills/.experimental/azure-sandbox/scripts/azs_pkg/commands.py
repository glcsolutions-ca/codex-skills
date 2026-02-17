#!/usr/bin/env python3
"""azure-sandbox: workspace-scoped Azure sandbox fleet lifecycle tool."""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, TextIO, TypeVar

SKILL_NAME = "azure-sandbox"
FLEET_VERSION = 1
STATE_VERSION = 2

SANDBOX_ROOT_REL = Path(".sandbox/azure")
SANDBOXES_DIR_NAME = "sandboxes"
FLEET_FILE_NAME = "fleet.json"
STATE_FILE_NAME = "state.json"
AZURE_CONFIG_DIR_NAME = "config"
AZURE_EXTENSION_DIR_NAME = "extensions"
AZURE_TMP_DIR_NAME = "tmp"
AZURE_CACHE_DIR_NAME = "cache"
AZURE_CONFIG_FILE_NAME = "config"
AZURE_COMMAND_LOG_DIR_NAME = "commands"

RUNTIME_SANDBOX_SCRIPT_NAME = "azs"
RUNTIME_AZ_SHIM_NAME = "az"
REMOVED_RUNTIME_SHIM_NAMES = ("sandbox", "azure-sandbox", "azs-cli.py")

GITIGNORE_LINE = ".sandbox/azure/"

DEFAULT_TTL_SECONDS = 3600
MIN_TTL_SECONDS = 900
MAX_TTL_SECONDS = 24 * 3600

LOGIN_RETRY_ATTEMPTS = 8
LOGIN_RETRY_INITIAL_DELAY_SECONDS = 5
LOGIN_RETRY_MAX_DELAY_SECONDS = 30

BUDGET_THRESHOLD_PERCENT = 100

AUTOMATION_EXTENSION_NAME = "automation"
AUTOMATION_ACCOUNT_API_VERSIONS = ["2023-11-01", "2022-08-08", "2020-01-13-preview"]
AUTOMATION_JOBSCHEDULE_API_VERSION = "2019-06-01"
AUTOMATION_WEBHOOK_API_VERSION = "2019-06-01"
CONSUMPTION_BUDGET_API_VERSION = "2023-03-01"

RUNBOOK_NAME = "codex-expiry-cleanup"
RUNBOOK_SCHEDULE_SUFFIXES = ["00", "15", "30", "45"]

SENSITIVE_FLAGS = {"--password", "-p", "--client-secret", "--secret"}
CONFIG_FALSE_VALUES = {"0", "false", "no", "off"}
CODEX_SANDBOX_NETWORK_DISABLED_ENV = "CODEX_SANDBOX_NETWORK_DISABLED"

DURATION_TOKEN_RE = re.compile(r"(?i)(\d+)([smhd])")
AZURE_LOCATION_HINTS = ["eastus", "westus2", "centralus", "canadacentral", "westeurope"]
READINESS_MAX_WAIT_SECONDS = 180
READINESS_INITIAL_DELAY_SECONDS = 2
READINESS_MAX_DELAY_SECONDS = 20
AUTH_CACHE_WINDOW_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 8

RG_FROM_ID_RE = re.compile(r"/resourceGroups/([^/]+)", re.IGNORECASE)
PATH_SEGMENT_RE = re.compile(r"([A-Za-z0-9_\-]+)|\[(\d+)\]")

AUTH_SUBSCRIPTION_CACHE: dict[str, tuple[str, float]] = {}
T = TypeVar("T")

AZ_OUTPUT_VALUES = {"json", "jsonc", "none", "table", "tsv", "yaml", "yamlc"}
AZ_GLOBAL_PREFIX_FLAGS = {
    "--subscription",
    "-s",
    "--output",
    "-o",
    "--query",
    "--only-show-errors",
    "--verbose",
    "--debug",
}
GROUP_NAME_SCOPED_VERBS = {"show", "delete", "exists", "update", "wait", "export"}

REQUIRED_STATE_FIELDS: dict[str, type] = {
    "version": int,
    "workspace_path": str,
    "workspace_id": str,
    "sandbox_name": str,
    "subscription_id": str,
    "tenant_id": str,
    "resource_group_name": str,
    "resource_group_scope": str,
    "location": str,
    "service_principal_app_id": str,
    "service_principal_object_id": str,
    "service_principal_display_name": str,
    "service_principal_client_secret": str,
    "ttl_duration_seconds": int,
    "expires_at_utc": str,
    "last_touched_at_utc": str,
    "automation_account_name": str,
    "automation_account_id": str,
    "automation_identity_principal_id": str,
    "automation_runbook_name": str,
    "automation_schedule_names": list,
    "automation_job_schedule_ids": list,
    "budget_enabled": bool,
    "budget_threshold_percent": int,
    "budget_name": str,
    "budget_resource_id": str,
    "budget_action_group_name": str,
    "budget_action_group_id": str,
    "budget_webhook_name": str,
    "budget_webhook_resource_id": str,
    "created_at_utc": str,
    "updated_at_utc": str,
}


def resolve_sandbox_executable_hint() -> str:
    codex_home = os.environ.get("CODEX_HOME", "").strip()
    if codex_home:
        candidate = Path(codex_home).expanduser() / "skills" / SKILL_NAME / "scripts" / RUNTIME_SANDBOX_SCRIPT_NAME
        return str(candidate.resolve(strict=False))

    argv0 = sys.argv[0].strip()
    if argv0:
        argv0_path = Path(argv0).expanduser()
        if argv0_path.name == RUNTIME_SANDBOX_SCRIPT_NAME:
            return str(argv0_path.resolve(strict=False))

    return str((Path(__file__).resolve().parent.parent / RUNTIME_SANDBOX_SCRIPT_NAME).resolve(strict=False))


SANDBOX_EXECUTABLE_HINT = resolve_sandbox_executable_hint()


def preferred_sandbox_executable(paths: WorkspacePaths | None = None) -> str:
    selected_paths = paths
    if selected_paths is None:
        try:
            selected_paths = resolve_workspace_paths()
        except Exception:
            selected_paths = None

    if selected_paths is not None and selected_paths.runtime_sandbox_script.exists():
        return str(selected_paths.runtime_sandbox_script.resolve(strict=False))

    return SANDBOX_EXECUTABLE_HINT


def sandbox_az_command(args: str = "", *, paths: WorkspacePaths | None = None) -> str:
    base = preferred_sandbox_executable(paths)
    if args:
        return f"{base} {args}".strip()
    return base


def format_sandbox_az_invocation(az_args: list[str], *, paths: WorkspacePaths) -> str:
    quoted_args = " ".join(shlex.quote(token) for token in az_args)
    if not quoted_args:
        return sandbox_az_command(paths=paths)
    return f"{sandbox_az_command(paths=paths)} {quoted_args}"


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


class ProgressReporter:
    """Streams long-running command progress to stderr while preserving stdout payload semantics."""

    def __init__(
        self,
        *,
        enabled: bool,
        verbose: bool,
        debug: bool,
        stream: TextIO = sys.stderr,
    ):
        self.enabled = enabled
        self.verbose = verbose or debug
        self.debug = debug
        self.stream = stream

    def _emit(self, level: str, message: str) -> None:
        print(f"{level}: [{SKILL_NAME}] {message}", file=self.stream, flush=True)

    def info(self, message: str) -> None:
        if self.enabled:
            self._emit("INFO", message)

    def error(self, message: str) -> None:
        self._emit("ERROR", message)

    def step_start(self, *, index: int, total: int, name: str, detail: str = "") -> None:
        if not self.enabled:
            return
        text = f"({index}/{total}) {name}"
        if detail:
            text = f"{text} {detail}"
        self.info(text)

    def step_ok(self, name: str, *, seconds: float) -> None:
        if not self.enabled:
            return
        if self.verbose:
            self.info(f"✓ {name} ({seconds:.1f}s)")
            return
        self.info(f"✓ {name}")

    def step_fail(self, name: str, detail: str) -> None:
        self.error(f"✗ {name}: {detail}")

    def step_skip(self, *, index: int, total: int, name: str, detail: str) -> None:
        if not self.enabled:
            return
        self.info(f"({index}/{total}) {name} skipped: {detail}")

    def heartbeat(self, name: str, *, elapsed_seconds: float) -> None:
        if not self.enabled:
            return
        self.info(f"...still working on '{name}' ({int(elapsed_seconds)}s elapsed)")

    def debug_detail(self, message: str) -> None:
        if self.debug and self.enabled:
            self.info(f"[debug] {message}")

    def rollback_step(self, *, step: str, ok: bool, detail: str) -> None:
        badge = "✓" if ok else "✗"
        self.error(f"{badge} rollback {step}: {detail}")


def run_with_progress(
    *,
    reporter: ProgressReporter,
    index: int,
    total: int,
    step_name: str,
    detail: str,
    fn: Callable[[], T],
    result_ok: Callable[[T], tuple[bool, str] | bool] | None = None,
    heartbeat_seconds: int = HEARTBEAT_INTERVAL_SECONDS,
    emit_heartbeat: bool = True,
) -> T:
    reporter.step_start(index=index, total=total, name=step_name, detail=detail)
    start = time.monotonic()

    result_box: dict[str, T] = {}
    error_box: dict[str, BaseException] = {}

    def target() -> None:
        try:
            result_box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001
            error_box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()

    while worker.is_alive():
        worker.join(timeout=heartbeat_seconds)
        if worker.is_alive() and emit_heartbeat:
            reporter.heartbeat(step_name, elapsed_seconds=time.monotonic() - start)

    duration = time.monotonic() - start
    if "error" in error_box:
        detail_text = str(error_box["error"]).strip() or "step failed"
        reporter.step_fail(step_name, detail_text)
        raise error_box["error"]

    result = result_box["value"]
    if result_ok is not None:
        verdict = result_ok(result)
        if isinstance(verdict, tuple):
            ok, fail_detail = verdict
        else:
            ok, fail_detail = bool(verdict), ""
        if ok:
            reporter.step_ok(step_name, seconds=duration)
        else:
            reporter.step_fail(step_name, fail_detail or "operation returned an unsuccessful status")
    else:
        reporter.step_ok(step_name, seconds=duration)
    return result


@dataclass
class WorkspacePaths:
    workspace: Path
    runtime_root: Path
    sandboxes_dir: Path
    fleet_file: Path
    runtime_sandbox_script: Path
    runtime_az_shim: Path
    gitignore_file: Path


@dataclass
class SandboxPaths:
    name: str
    root: Path
    state_file: Path
    azure_config_dir: Path
    azure_extension_dir: Path
    azure_tmp_dir: Path
    azure_cache_dir: Path


def redact_command_for_logs(cmd: list[str]) -> str:
    redacted: list[str] = []
    redact_next = False

    for token in cmd:
        token_lower = token.lower()

        if redact_next:
            redacted.append("***REDACTED***")
            redact_next = False
            continue

        if token_lower in SENSITIVE_FLAGS:
            redacted.append(token)
            redact_next = True
            continue

        if "=" in token:
            key, _value = token.split("=", 1)
            if key.lower() in SENSITIVE_FLAGS:
                redacted.append(f"{key}=***REDACTED***")
                continue

        redacted.append(token)

    return " ".join(redacted)


def looks_like_role_propagation_delay(message: str) -> bool:
    lower = message.lower()
    return any(
        snippet in lower
        for snippet in (
            "no subscriptions found for",
            "does not have subscriptions",
            "principal does not exist in directory",
            "unable to find user or service principal",
            "insufficient privileges to complete the operation",
            "role assignment",
        )
    )


def looks_like_invalid_client_secret(message: str) -> bool:
    lower = message.lower()
    return any(
        snippet in lower
        for snippet in (
            "aadsts7000215",
            "invalid client secret provided",
            "invalid client secret",
        )
    )


def looks_like_already_exists(message: str) -> bool:
    lower = message.lower()
    return any(
        snippet in lower
        for snippet in (
            "already exists",
            "already been taken",
            "conflict",
            "cannot create duplicate",
        )
    )


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
            "resource not found",
        )
    )


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


def now_utc_iso() -> str:
    return now_utc().isoformat().replace("+00:00", "Z")


def parse_utc_iso(value: str) -> dt.datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    return dt.datetime.fromisoformat(normalized).astimezone(dt.UTC)


def resolve_workspace_root(cwd: Path | None = None) -> Path:
    base = (cwd or Path.cwd()).resolve()
    try:
        process = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=base,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        process = None

    if process and process.returncode == 0:
        top = process.stdout.strip()
        if top:
            return Path(top).resolve()

    return base


def resolve_workspace_paths(workspace: Path | None = None) -> WorkspacePaths:
    workspace_path = resolve_workspace_root(workspace)
    runtime_root = workspace_path / SANDBOX_ROOT_REL
    return WorkspacePaths(
        workspace=workspace_path,
        runtime_root=runtime_root,
        sandboxes_dir=runtime_root / SANDBOXES_DIR_NAME,
        fleet_file=runtime_root / FLEET_FILE_NAME,
        runtime_sandbox_script=runtime_root / RUNTIME_SANDBOX_SCRIPT_NAME,
        runtime_az_shim=runtime_root / RUNTIME_AZ_SHIM_NAME,
        gitignore_file=workspace_path / ".gitignore",
    )


def resolve_sandbox_paths(paths: WorkspacePaths, sandbox_name: str) -> SandboxPaths:
    root = paths.sandboxes_dir / sandbox_name
    return SandboxPaths(
        name=sandbox_name,
        root=root,
        state_file=root / STATE_FILE_NAME,
        azure_config_dir=root / AZURE_CONFIG_DIR_NAME,
        azure_extension_dir=root / AZURE_EXTENSION_DIR_NAME,
        azure_tmp_dir=root / AZURE_TMP_DIR_NAME,
        azure_cache_dir=root / AZURE_CACHE_DIR_NAME,
    )


def config_value_is_false(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in CONFIG_FALSE_VALUES


def ensure_directory(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)


def write_json_file(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, mode)
    temp.replace(path)
    os.chmod(path, mode)


def write_executable(path: Path, content: str) -> None:
    temp_file = path.with_suffix(".tmp")
    temp_file.write_text(content, encoding="utf-8")
    os.chmod(temp_file, 0o755)
    temp_file.replace(path)
    os.chmod(path, 0o755)


def ensure_workspace_runtime(paths: WorkspacePaths) -> None:
    ensure_directory(paths.runtime_root, 0o700)
    ensure_directory(paths.sandboxes_dir, 0o700)
    # Remove retired wrapper names; canonical entrypoint stays in skill scripts path.
    for name in REMOVED_RUNTIME_SHIM_NAMES:
        retired = paths.runtime_root / name
        if retired.exists():
            if retired.is_dir():
                shutil.rmtree(retired)
            else:
                retired.unlink()


def ensure_azure_cli_local_config(azure_config_dir: Path) -> None:
    try:
        ensure_directory(azure_config_dir, 0o700)
        ensure_directory(azure_config_dir / AZURE_COMMAND_LOG_DIR_NAME, 0o700)

        config_file = azure_config_dir / AZURE_CONFIG_FILE_NAME
        parser = configparser.ConfigParser()
        if config_file.exists():
            parser.read(config_file, encoding="utf-8")

        changed = False
        if not parser.has_section("logging"):
            parser.add_section("logging")
            changed = True
        if not config_value_is_false(parser.get("logging", "enable_log_file", fallback=None)):
            parser.set("logging", "enable_log_file", "no")
            changed = True

        if not parser.has_section("core"):
            parser.add_section("core")
            changed = True
        if not config_value_is_false(parser.get("core", "collect_telemetry", fallback=None)):
            parser.set("core", "collect_telemetry", "no")
            changed = True

        if changed or not config_file.exists():
            temp_file = config_file.with_suffix(".tmp")
            with temp_file.open("w", encoding="utf-8") as handle:
                parser.write(handle)
            os.chmod(temp_file, 0o600)
            temp_file.replace(config_file)
            os.chmod(config_file, 0o600)
    except OSError as exc:
        raise CliError(
            "Sandbox Azure config directory is not writable: "
            f"{azure_config_dir}. Run this command from the target workspace so Codex "
            "can write local auth/cache files there."
        ) from exc


def ensure_sandbox_cli_defaults(
    *,
    azure_config_dir: Path,
    resource_group: str,
    location: str,
) -> None:
    try:
        ensure_azure_cli_local_config(azure_config_dir)
        config_file = azure_config_dir / AZURE_CONFIG_FILE_NAME
        parser = configparser.ConfigParser()
        if config_file.exists():
            parser.read(config_file, encoding="utf-8")

        changed = False
        if not parser.has_section("defaults"):
            parser.add_section("defaults")
            changed = True

        if parser.get("defaults", "group", fallback="") != resource_group:
            parser.set("defaults", "group", resource_group)
            changed = True

        if parser.get("defaults", "location", fallback="") != location:
            parser.set("defaults", "location", location)
            changed = True

        if changed:
            temp_file = config_file.with_suffix(".tmp")
            with temp_file.open("w", encoding="utf-8") as handle:
                parser.write(handle)
            os.chmod(temp_file, 0o600)
            temp_file.replace(config_file)
            os.chmod(config_file, 0o600)
    except OSError as exc:
        raise CliError(
            "Failed to update sandbox Azure defaults in local config: "
            f"{azure_config_dir} ({exc})"
        ) from exc


def ensure_runtime_azure_dirs(azure_config_dir: Path) -> tuple[Path, Path, Path]:
    sandbox_root = azure_config_dir.parent
    extension_dir = sandbox_root / AZURE_EXTENSION_DIR_NAME
    tmp_dir = sandbox_root / AZURE_TMP_DIR_NAME
    cache_dir = sandbox_root / AZURE_CACHE_DIR_NAME
    ensure_directory(extension_dir, 0o700)
    ensure_directory(tmp_dir, 0o700)
    ensure_directory(cache_dir, 0o700)
    return extension_dir, tmp_dir, cache_dir


def az_env(azure_config_dir: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    if azure_config_dir is not None:
        ensure_azure_cli_local_config(azure_config_dir)
        extension_dir, tmp_dir, cache_dir = ensure_runtime_azure_dirs(azure_config_dir)
        env["AZURE_CONFIG_DIR"] = str(azure_config_dir)
        env["AZURE_EXTENSION_DIR"] = str(extension_dir)
        env["TMPDIR"] = str(tmp_dir)
        env["XDG_CACHE_HOME"] = str(cache_dir)
    return env


def run_cmd(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture_output: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        cmd,
        env=env,
        cwd=cwd,
        text=True,
        capture_output=capture_output,
    )
    if check and process.returncode != 0:
        raise CommandError(cmd, process.returncode, process.stdout or "", process.stderr or "")
    return process


def run_az(
    args: list[str],
    *,
    azure_config_dir: Path | None,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = az_env(azure_config_dir)
    return run_cmd(["az", *args], env=env, check=check, capture_output=capture_output)


def run_az_operator(
    args: list[str],
    *,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_az(args, azure_config_dir=None, check=check, capture_output=capture_output)


def run_az_runtime(
    args: list[str],
    *,
    sbx_paths: SandboxPaths,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_az(
        args,
        azure_config_dir=sbx_paths.azure_config_dir,
        check=check,
        capture_output=capture_output,
    )


def az_json(args: list[str], *, azure_config_dir: Path | None) -> Any:
    process = run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
    payload = process.stdout.strip()
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CliError(f"Failed to parse JSON from Azure CLI output for: {' '.join(args)}") from exc


def az_tsv(args: list[str], *, azure_config_dir: Path | None) -> str:
    process = run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
    return process.stdout.strip()


def az_rest(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    azure_config_dir: Path | None,
    check: bool = True,
) -> Any:
    args = ["rest", "--method", method, "--url", url, "--output", "json"]
    if body is not None:
        args.extend(["--body", json.dumps(body)])
    process = run_az(args, azure_config_dir=azure_config_dir, check=check, capture_output=True)
    payload = process.stdout.strip()
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": payload}


def az_json_operator(args: list[str]) -> Any:
    return az_json(args, azure_config_dir=None)


def az_json_runtime(args: list[str], *, sbx_paths: SandboxPaths) -> Any:
    return az_json(args, azure_config_dir=sbx_paths.azure_config_dir)


def az_tsv_operator(args: list[str]) -> str:
    return az_tsv(args, azure_config_dir=None)


def az_tsv_runtime(args: list[str], *, sbx_paths: SandboxPaths) -> str:
    return az_tsv(args, azure_config_dir=sbx_paths.azure_config_dir)


def az_rest_operator(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    check: bool = True,
) -> Any:
    return az_rest(method, url, body=body, azure_config_dir=None, check=check)


def az_rest_runtime(
    method: str,
    url: str,
    *,
    sbx_paths: SandboxPaths,
    body: dict[str, Any] | None = None,
    check: bool = True,
) -> Any:
    return az_rest(
        method,
        url,
        body=body,
        azure_config_dir=sbx_paths.azure_config_dir,
        check=check,
    )


def slugify(text: str) -> str:
    lower = text.strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "-", lower)
    normalized = normalized.strip("-")
    normalized = re.sub(r"-{2,}", "-", normalized)
    return normalized or "workspace"


def alnum_slugify(text: str) -> str:
    lowered = text.strip().lower()
    return re.sub(r"[^a-z0-9]", "", lowered) or "sandbox"


def validate_sandbox_name(name: str) -> str:
    candidate = name.strip()
    if not candidate:
        raise CliError("Sandbox name cannot be empty.")
    if "/" in candidate:
        raise CliError("Sandbox name cannot contain '/'.")
    if len(candidate) > 120:
        raise CliError("Sandbox name is too long (max 120).")
    return candidate


def workspace_identity(path: Path) -> tuple[str, str, str]:
    workspace_path = str(path.resolve())
    slug = slugify(path.name)
    digest = hashlib.sha256(workspace_path.encode("utf-8")).hexdigest()[:10]
    return slug, digest, f"{slug}-{digest}"


def default_resource_group_name(workspace_slug: str, digest: str, sandbox_name: str) -> str:
    prefix = "codex-sbx"
    candidate = f"{prefix}-{workspace_slug}-{sandbox_name}-{digest}"
    if len(candidate) <= 90:
        return candidate

    reserve = len(prefix) + len(sandbox_name) + len(digest) + 3
    allowed_workspace_len = max(1, 90 - reserve)
    trimmed_ws = workspace_slug[:allowed_workspace_len].strip("-") or "ws"
    return f"{prefix}-{trimmed_ws}-{sandbox_name}-{digest}"[:90].rstrip("-")


def default_automation_account_name(workspace_digest: str, sandbox_name: str) -> str:
    raw = f"codexaa{workspace_digest}{alnum_slugify(sandbox_name)}"
    return raw[:48]


def default_budget_name(sandbox_name: str) -> str:
    return f"codex-sbx-{sandbox_name}-budget"[:63]


def default_action_group_name(sandbox_name: str) -> str:
    return f"codex-sbx-{sandbox_name}-ag"[:63]


def default_webhook_name(sandbox_name: str) -> str:
    return f"codex-budget-hook-{sandbox_name}"[:63]


def parse_duration_seconds(raw: str | None, *, default_seconds: int = DEFAULT_TTL_SECONDS) -> int:
    if raw is None:
        return default_seconds

    text = raw.strip().lower()
    if not text:
        raise CliError("Invalid --expires-in value: empty string")

    total = 0
    cursor = 0
    for match in DURATION_TOKEN_RE.finditer(text):
        if match.start() != cursor:
            raise CliError(
                "Invalid --expires-in format. Use values like 15m, 1h, 2h30m, or 1d."
            )
        value = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "s":
            total += value
        elif unit == "m":
            total += value * 60
        elif unit == "h":
            total += value * 3600
        elif unit == "d":
            total += value * 86400
        cursor = match.end()

    if cursor != len(text):
        raise CliError("Invalid --expires-in format. Use values like 15m, 1h, 2h30m, or 1d.")

    if total < MIN_TTL_SECONDS or total > MAX_TTL_SECONDS:
        raise CliError(
            "Invalid --expires-in value. Supported range is 15m to 24h."
        )

    return total


def ttl_seconds_to_human(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def parse_budget_value(raw: str | None) -> float | None:
    if raw is None:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        raise CliError("--budget-usd must be a number greater than 0.") from exc
    if value <= 0:
        raise CliError("--budget-usd must be greater than 0.")
    return round(value, 2)


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
    return GITIGNORE_LINE in paths.gitignore_file.read_text(encoding="utf-8").splitlines()


def new_fleet(paths: WorkspacePaths) -> dict[str, Any]:
    ws_slug, ws_digest, workspace_id = workspace_identity(paths.workspace)
    _ = ws_slug
    _ = ws_digest
    return {
        "version": FLEET_VERSION,
        "workspace_path": str(paths.workspace),
        "workspace_id": workspace_id,
        "active_sandbox": None,
        "sandboxes": {},
    }


def validate_fleet_data(fleet: dict[str, Any], paths: WorkspacePaths) -> list[str]:
    errors: list[str] = []

    if fleet.get("version") != FLEET_VERSION:
        errors.append(
            f"Unsupported fleet version: {fleet.get('version')} (expected {FLEET_VERSION})"
        )

    expected_workspace = str(paths.workspace.resolve())
    if fleet.get("workspace_path") != expected_workspace:
        errors.append(
            "Fleet workspace_path does not match current workspace. "
            f"Expected '{expected_workspace}', found '{fleet.get('workspace_path')}'."
        )

    sandboxes = fleet.get("sandboxes")
    if not isinstance(sandboxes, dict):
        errors.append("Fleet field 'sandboxes' must be an object mapping names to summary objects.")
        return errors

    for name, summary in sandboxes.items():
        if not isinstance(name, str):
            errors.append("Fleet sandbox keys must be strings.")
            continue
        if not name.strip():
            errors.append("Fleet contains an empty sandbox key.")
            continue
        if "/" in name:
            errors.append(f"Fleet sandbox key '{name}' cannot contain '/'.")
        if not isinstance(summary, dict):
            errors.append(f"Fleet summary for sandbox '{name}' must be an object.")
            continue
        for key in (
            "state_file",
            "resource_group_name",
            "location",
            "expires_at_utc",
            "created_at_utc",
            "updated_at_utc",
        ):
            if key not in summary:
                errors.append(f"Fleet summary for sandbox '{name}' missing '{key}'.")

    active = fleet.get("active_sandbox")
    if active is not None and not isinstance(active, str):
        errors.append("Fleet 'active_sandbox' must be null or a sandbox name.")
    if isinstance(active, str) and active not in sandboxes:
        errors.append(
            f"Fleet active_sandbox '{active}' is not present in fleet sandboxes."
        )

    return errors


def load_fleet(paths: WorkspacePaths, *, required: bool) -> dict[str, Any]:
    if not paths.fleet_file.exists():
        if required:
            raise CliError(
                "No Azure sandboxes are initialized in this workspace. "
                f"Expected fleet file at {paths.fleet_file}. "
                f"Run '{sandbox_az_command('group create --location <location>')}' first. "
                f"Examples: {', '.join(AZURE_LOCATION_HINTS)}."
            )
        return new_fleet(paths)

    try:
        payload = json.loads(paths.fleet_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(f"Fleet file is not valid JSON: {paths.fleet_file}") from exc

    if not isinstance(payload, dict):
        raise CliError(f"Fleet file root must be a JSON object: {paths.fleet_file}")

    errors = validate_fleet_data(payload, paths)
    if errors:
        raise CliError("Fleet validation failed:\n- " + "\n- ".join(errors))

    return payload


def write_fleet(paths: WorkspacePaths, fleet: dict[str, Any]) -> None:
    ensure_directory(paths.runtime_root, 0o700)
    ensure_directory(paths.sandboxes_dir, 0o700)
    write_json_file(paths.fleet_file, fleet, mode=0o600)


def validate_state_data(state: dict[str, Any], paths: WorkspacePaths, sandbox_name: str) -> list[str]:
    errors: list[str] = []

    for field, expected in REQUIRED_STATE_FIELDS.items():
        if field not in state:
            errors.append(f"Missing state field: {field}")
            continue
        if not isinstance(state[field], expected):
            errors.append(
                f"Invalid type for '{field}': expected {expected.__name__}, got {type(state[field]).__name__}"
            )

    budget_usd = state.get("budget_usd")
    if budget_usd is not None and not isinstance(budget_usd, (float, int)):
        errors.append("Invalid type for 'budget_usd': expected number or null")

    if state.get("version") != STATE_VERSION:
        errors.append(f"Unsupported state version: {state.get('version')} (expected {STATE_VERSION})")

    expected_workspace = str(paths.workspace.resolve())
    if isinstance(state.get("workspace_path"), str) and state["workspace_path"] != expected_workspace:
        errors.append(
            "State workspace_path does not match current workspace. "
            f"Expected '{expected_workspace}', found '{state['workspace_path']}'"
        )

    if state.get("sandbox_name") != sandbox_name:
        errors.append(
            f"State sandbox_name mismatch: expected '{sandbox_name}', found '{state.get('sandbox_name')}'."
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

    ttl = state.get("ttl_duration_seconds")
    if isinstance(ttl, int) and (ttl < MIN_TTL_SECONDS or ttl > MAX_TTL_SECONDS):
        errors.append("State ttl_duration_seconds is outside allowed range (15m to 24h).")

    schedules = state.get("automation_schedule_names")
    if isinstance(schedules, list) and len(schedules) != 4:
        errors.append("State automation_schedule_names must contain 4 schedules.")

    jobs = state.get("automation_job_schedule_ids")
    if isinstance(jobs, list) and len(jobs) != 4:
        errors.append("State automation_job_schedule_ids must contain 4 ids.")

    return errors


def load_state(paths: WorkspacePaths, sandbox_name: str) -> dict[str, Any]:
    sbx_paths = resolve_sandbox_paths(paths, sandbox_name)
    if not sbx_paths.state_file.exists():
        raise CliError(
            f"Sandbox '{sandbox_name}' is missing local state. "
            f"Expected state file at {sbx_paths.state_file}."
        )

    try:
        payload = json.loads(sbx_paths.state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(f"State file is not valid JSON: {sbx_paths.state_file}") from exc

    if not isinstance(payload, dict):
        raise CliError(f"State file root must be a JSON object: {sbx_paths.state_file}")

    errors = validate_state_data(payload, paths, sandbox_name)
    if errors:
        raise CliError("State validation failed:\n- " + "\n- ".join(errors))

    return payload


def write_state(sbx_paths: SandboxPaths, state: dict[str, Any]) -> None:
    ensure_directory(sbx_paths.root, 0o700)
    write_json_file(sbx_paths.state_file, state, mode=0o600)


def fleet_summary_from_state(sbx_paths: SandboxPaths, state: dict[str, Any]) -> dict[str, Any]:
    return {
        "state_file": str(sbx_paths.state_file),
        "resource_group_name": state["resource_group_name"],
        "location": state["location"],
        "expires_at_utc": state["expires_at_utc"],
        "budget_usd": state.get("budget_usd"),
        "created_at_utc": state["created_at_utc"],
        "updated_at_utc": state["updated_at_utc"],
    }


def update_fleet_summary(
    paths: WorkspacePaths,
    fleet: dict[str, Any],
    sbx_paths: SandboxPaths,
    state: dict[str, Any],
) -> None:
    fleet["sandboxes"][sbx_paths.name] = fleet_summary_from_state(sbx_paths, state)
    write_fleet(paths, fleet)


def ensure_az_extension(name: str) -> None:
    show = run_az_operator(["extension", "show", "--name", name, "--output", "none"], check=False)
    if show.returncode == 0:
        return
    run_az_operator(["extension", "add", "--name", name, "--output", "none"], check=True)


def resolve_subscription_and_tenant(subscription_arg: str | None) -> tuple[str, str]:
    args = ["account", "show", "--output", "json"]
    if subscription_arg:
        args.extend(["--subscription", subscription_arg])

    try:
        account = az_json_operator(args)
    except CommandError as exc:
        details = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise CliError(
            "Azure operator account is not authenticated. "
            "Run: az login\n"
            f"Then rerun: {sandbox_az_command('group create --location <location>')}\n\n"
            f"Azure CLI output: {details}"
        ) from exc

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


def add_az_global_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--subscription", "-s")
    parser.add_argument("--output", "-o", default="json")
    parser.add_argument("--query")
    parser.add_argument("--only-show-errors", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")


def strip_leading_az_global_args(args: list[str]) -> tuple[list[str], list[str]]:
    prefix: list[str] = []
    cursor = 0
    while cursor < len(args):
        token = args[cursor]
        if token not in AZ_GLOBAL_PREFIX_FLAGS and not any(
            token.startswith(f"{flag}=")
            for flag in ("--subscription", "--output", "--query")
        ):
            break

        if token in {"--only-show-errors", "--verbose", "--debug"}:
            prefix.append(token)
            cursor += 1
            continue

        if token.startswith("--subscription=") or token.startswith("--output=") or token.startswith("--query="):
            prefix.append(token)
            cursor += 1
            continue

        if token in {"--subscription", "-s", "--output", "-o", "--query"}:
            if cursor + 1 >= len(args):
                raise CliError(f"Missing value for option {token}")
            prefix.extend([token, args[cursor + 1]])
            cursor += 2
            continue

        break

    return prefix, args[cursor:]


def normalize_output_name(value: str | None, *, json_alias: bool = False) -> str:
    if json_alias:
        return "json"
    output = (value or "json").strip().lower()
    if output not in AZ_OUTPUT_VALUES:
        choices = ", ".join(sorted(AZ_OUTPUT_VALUES))
        raise CliError(f"Unsupported --output value '{output}'. Allowed values: {choices}.")
    return output


def scalar_to_cli_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def normalize_table_rows(payload: Any) -> tuple[list[str], list[list[str]]] | None:
    if isinstance(payload, dict):
        columns = list(payload.keys())
        rows = [[scalar_to_cli_text(payload.get(column)) for column in columns]]
        return columns, rows

    if isinstance(payload, list) and payload and all(isinstance(item, dict) for item in payload):
        columns: list[str] = []
        seen: set[str] = set()
        for item in payload:
            for key in item.keys():
                if key not in seen:
                    seen.add(key)
                    columns.append(key)
        rows = [[scalar_to_cli_text(item.get(column)) for column in columns] for item in payload]
        return columns, rows

    return None


def format_payload_as_table(payload: Any) -> str:
    normalized = normalize_table_rows(payload)
    if normalized is None:
        if isinstance(payload, list):
            return "\n".join(scalar_to_cli_text(item) for item in payload)
        return scalar_to_cli_text(payload)

    columns, rows = normalized
    widths = [len(column) for column in columns]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    header = "  ".join(columns[index].ljust(widths[index]) for index in range(len(columns)))
    divider = "  ".join("-" * widths[index] for index in range(len(columns)))
    body = [
        "  ".join(row[index].ljust(widths[index]) for index in range(len(columns)))
        for row in rows
    ]
    return "\n".join([header, divider, *body])


def format_payload_as_tsv(payload: Any) -> str:
    normalized = normalize_table_rows(payload)
    if normalized is not None:
        _columns, rows = normalized
        return "\n".join("\t".join(row) for row in rows)

    if isinstance(payload, list):
        return "\n".join(scalar_to_cli_text(item) for item in payload)
    return scalar_to_cli_text(payload)


def fallback_basic_query(payload: Any, query: str) -> Any:
    expression = query.strip()
    if not expression or expression == "@":
        return payload

    def resolve_path(value: Any, path: str) -> Any:
        current = value
        for key, index in PATH_SEGMENT_RE.findall(path):
            if key:
                if not isinstance(current, dict):
                    return None
                current = current.get(key)
            else:
                if not isinstance(current, list):
                    return None
                idx = int(index)
                if idx < 0 or idx >= len(current):
                    return None
                current = current[idx]
        return current

    filter_match = re.fullmatch(r"\[\?\s*([A-Za-z0-9_.\-]+)\s*==\s*'([^']*)'\s*\](?:\.(.+))?", expression)
    if filter_match:
        if not isinstance(payload, list):
            return []
        key_path, expected_value, projection = filter_match.groups()
        filtered = [item for item in payload if scalar_to_cli_text(resolve_path(item, key_path)) == expected_value]
        if projection:
            return [resolve_path(item, projection) for item in filtered]
        return filtered

    projection_match = re.fullmatch(r"\[\]\.(.+)", expression)
    if projection_match:
        if not isinstance(payload, list):
            return []
        path = projection_match.group(1)
        return [resolve_path(item, path) for item in payload]

    index_match = re.fullmatch(r"\[(\d+)\](?:\.(.+))?", expression)
    if index_match:
        if not isinstance(payload, list):
            return None
        idx = int(index_match.group(1))
        if idx < 0 or idx >= len(payload):
            return None
        selected = payload[idx]
        path = index_match.group(2)
        if not path:
            return selected
        return resolve_path(selected, path)

    return resolve_path(payload, expression)


def apply_query_to_payload(payload: Any, query: str | None) -> Any:
    if not query:
        return payload
    try:
        import jmespath  # type: ignore
    except ModuleNotFoundError:
        return fallback_basic_query(payload, query)
    return jmespath.search(query, payload)


def format_payload_for_output(payload: Any, output: str) -> str | None:
    if output == "none":
        return None
    if output in {"json", "jsonc"}:
        return json.dumps(payload, indent=2, sort_keys=True)
    if output in {"yaml", "yamlc"}:
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError:
            return json.dumps(payload, indent=2, sort_keys=True)
        return yaml.safe_dump(payload, sort_keys=True)
    if output == "table":
        return format_payload_as_table(payload)
    if output == "tsv":
        return format_payload_as_tsv(payload)
    return json.dumps(payload, indent=2, sort_keys=True)


def emit_intercept_output(
    payload: Any,
    *,
    output: str,
    query: str | None,
) -> None:
    queried = apply_query_to_payload(payload, query)
    rendered = format_payload_for_output(queried, output)
    if rendered is None:
        return
    print(rendered)


def tags_for_state(state: dict[str, Any]) -> dict[str, str]:
    tags = {
        "codex-sandbox": "true",
        "codex-workspace-id": state["workspace_id"],
        "codex-skill": SKILL_NAME,
        "codex-sandbox-name": state["sandbox_name"],
        "codex-expires-at-utc": state["expires_at_utc"],
        "codex-ttl-seconds": str(state["ttl_duration_seconds"]),
    }
    if state.get("budget_enabled") and state.get("budget_usd") is not None:
        tags["codex-budget-usd"] = str(state["budget_usd"])
    return tags


def make_group_payload(
    state: dict[str, Any],
    *,
    active: bool,
    include_health: bool = False,
    health_report: dict[str, Any] | None = None,
    state_file: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": state["resource_group_scope"],
        "name": state["resource_group_name"],
        "location": state["location"],
        "managedBy": None,
        "tags": tags_for_state(state),
        "type": "Microsoft.Resources/resourceGroups",
        "properties": {"provisioningState": "Succeeded"},
        "sandbox": {
            "name": state["sandbox_name"],
            "active": active,
            "expiresAtUtc": state["expires_at_utc"],
            "budgetUsd": state.get("budget_usd"),
            "subscriptionId": state["subscription_id"],
        },
    }

    if include_health and health_report is not None:
        payload["sandbox"].update(
            {
                "healthy": health_report.get("healthy"),
                "checks": health_report.get("checks", []),
                "remediation": health_report.get("remediation", []),
            }
        )
    if state_file is not None:
        payload["sandbox"]["stateFile"] = state_file
    return payload


def make_degraded_group_payload(
    *,
    sandbox_name: str,
    summary: dict[str, Any],
    active: bool,
    error: str,
) -> dict[str, Any]:
    rg_name = str(summary.get("resource_group_name", sandbox_name)).strip() or sandbox_name
    location = str(summary.get("location", "")).strip() or "unknown"
    state_file = str(summary.get("state_file", "")).strip()
    expires_at = str(summary.get("expires_at_utc", "")).strip() or None
    budget_usd = summary.get("budget_usd")

    payload: dict[str, Any] = {
        "id": f"/resourceGroups/{rg_name}",
        "name": rg_name,
        "location": location,
        "managedBy": None,
        "tags": {
            "codex-sandbox": "true",
            "codex-skill": SKILL_NAME,
            "codex-sandbox-name": sandbox_name,
        },
        "type": "Microsoft.Resources/resourceGroups",
        "properties": {"provisioningState": "Unknown"},
        "sandbox": {
            "name": sandbox_name,
            "active": active,
            "expiresAtUtc": expires_at,
            "budgetUsd": budget_usd,
            "subscriptionId": None,
            "healthy": False,
            "checks": [{"name": "state-schema", "ok": False, "details": error}],
            "remediation": [
                "Local sandbox state is invalid or missing. Recreate with "
                f"'{sandbox_az_command('group create --name <rg-name> --location <location> --recreate')}'."
            ],
        },
    }
    if state_file:
        payload["sandbox"]["stateFile"] = state_file
    return payload


def tag_filter_matches(filter_expr: str | None, tags: dict[str, str]) -> bool:
    if filter_expr is None:
        return True
    expr = filter_expr.strip()
    if expr == "":
        return True
    if "=" in expr:
        key, expected = expr.split("=", 1)
        return tags.get(key) == expected
    return expr in tags


def missing_sandbox_message(paths: WorkspacePaths) -> str:
    hints = ", ".join(AZURE_LOCATION_HINTS)
    return (
        "No Azure sandboxes are initialized in this workspace. "
        f"Expected fleet file at {paths.fleet_file}. "
        f"Run '{sandbox_az_command('group create --location <location>', paths=paths)}' first. "
        f"Examples: {hints}."
    )


def codex_sandbox_network_disabled() -> bool:
    value = os.environ.get(CODEX_SANDBOX_NETWORK_DISABLED_ENV, "").strip()
    if not value:
        return False
    return value.lower() not in CONFIG_FALSE_VALUES


def network_disabled_remediation_message(paths: WorkspacePaths, *, az_args: list[str] | None = None) -> str:
    one_shot = (
        f"codex --cd {shlex.quote(str(paths.workspace))} -s workspace-write "
        "-c 'sandbox_workspace_write.network_access=true'"
    )
    snippet = "[sandbox_workspace_write]\nnetwork_access = true"
    rerun = (
        format_sandbox_az_invocation(az_args, paths=paths)
        if az_args
        else sandbox_az_command("<az-command>", paths=paths)
    )

    return (
        "Network access is disabled for this Codex sandbox, so Azure CLI cannot reach Azure.\n"
        f"One-shot run config:\n  {one_shot}\n"
        "Persistent global config (~/.codex/config.toml):\n"
        f"{snippet}\n"
        "Project-scoped .codex/config.toml may be ignored when the project is untrusted.\n"
        "After changing config, open or fork a new conversation, then rerun:\n"
        f"  {rerun}"
    )


def ensure_runtime_network_enabled(paths: WorkspacePaths, *, az_args: list[str] | None = None) -> None:
    if codex_sandbox_network_disabled():
        raise CliError(network_disabled_remediation_message(paths, az_args=az_args))


def ensure_sandboxes_exist(paths: WorkspacePaths, fleet: dict[str, Any]) -> None:
    if not fleet["sandboxes"]:
        raise CliError(missing_sandbox_message(paths))


def fleet_keys_for_resource_group(fleet: dict[str, Any], resource_group_name: str) -> list[str]:
    expected = resource_group_name.lower()
    matches: list[str] = []
    for key, summary in fleet["sandboxes"].items():
        if str(summary.get("resource_group_name", "")).lower() == expected:
            matches.append(key)
    return matches


def resolve_key_by_resource_group(fleet: dict[str, Any], resource_group_name: str) -> str | None:
    matches = fleet_keys_for_resource_group(fleet, resource_group_name)
    if not matches:
        return None
    if len(matches) > 1:
        raise CliError(
            f"Resource group '{resource_group_name}' matches multiple sandbox entries. "
            "Use '--sandbox <name>' to disambiguate."
        )
    return matches[0]


def resolve_key_by_name_or_resource_group(fleet: dict[str, Any], value: str) -> str:
    candidate = value.strip()
    if candidate in fleet["sandboxes"]:
        return candidate

    rg_key = resolve_key_by_resource_group(fleet, candidate)
    if rg_key is not None:
        return rg_key

    raise CliError(
        f"Sandbox '{candidate}' is not in this workspace. "
        f"Run '{sandbox_az_command('group list')}' to see available sandbox resource groups."
    )


def resource_group_from_id(resource_id: str) -> str | None:
    match = RG_FROM_ID_RE.search(resource_id)
    if not match:
        return None
    return match.group(1)


def resolve_key_from_ids(fleet: dict[str, Any], ids: list[str]) -> str | None:
    matches: set[str] = set()
    for resource_id in ids:
        rg_name = resource_group_from_id(resource_id)
        if not rg_name:
            continue
        key = resolve_key_by_resource_group(fleet, rg_name)
        if key is not None:
            matches.add(key)

    if not matches:
        return None
    if len(matches) > 1:
        raise CliError(
            "Command references resource IDs in multiple sandboxes. "
            "Run one sandbox-targeted command at a time."
        )
    return next(iter(matches))


def resolve_key_from_group_name_scoped_verb(fleet: dict[str, Any], az_args: list[str]) -> str | None:
    _global_prefix, command_args = strip_leading_az_global_args(az_args)
    if len(command_args) < 2 or command_args[0] != "group":
        return None
    verb = command_args[1]
    if verb not in GROUP_NAME_SCOPED_VERBS:
        return None

    name_values = parse_option_values(command_args[2:], "--name", "-n")
    if not name_values:
        return None

    unique = {value for value in name_values if value}
    if len(unique) > 1:
        raise CliError("Multiple --name values were provided; use exactly one target resource group.")

    candidate = next(iter(unique))
    key = resolve_key_by_resource_group(fleet, candidate)
    if key is None:
        raise CliError(
            f"Resource group '{candidate}' is not a sandbox in this workspace. "
            f"Run '{sandbox_az_command('group list')}' to see available sandbox resource groups."
        )
    return key


def resolve_passthrough_target_sandbox(
    *,
    paths: WorkspacePaths,
    fleet: dict[str, Any],
    az_args: list[str],
    explicit_name: str | None,
) -> tuple[str, bool]:
    ensure_sandboxes_exist(paths, fleet)

    rg_values = parse_option_values(az_args, "--resource-group", "-g")
    unique_rgs = {value for value in rg_values if value}
    if unique_rgs:
        if len(unique_rgs) > 1:
            raise CliError("Multiple --resource-group values were provided; use exactly one target resource group.")
        rg = next(iter(unique_rgs))
        rg_key = resolve_key_by_resource_group(fleet, rg)
        if rg_key is None:
            raise CliError(
                f"Resource group '{rg}' is not a sandbox in this workspace. "
                f"Run '{sandbox_az_command('group list')}' to see available sandbox resource groups."
            )
        return rg_key, False

    ids_target = resolve_key_from_ids(fleet, parse_ids_values(az_args))
    if ids_target is not None:
        return ids_target, False

    group_name_target = resolve_key_from_group_name_scoped_verb(fleet, az_args)
    if group_name_target is not None:
        return group_name_target, False

    if explicit_name:
        return resolve_key_by_name_or_resource_group(fleet, explicit_name), False

    return resolve_target_sandbox_name(fleet, explicit_name=None)


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


def best_effort_az(args: list[str], *, azure_config_dir: Path | None) -> tuple[bool, str]:
    try:
        run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
        return True, "ok"
    except CommandError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        if looks_like_not_found(message):
            return True, f"already absent ({message})"
        return False, message


def best_effort_az_operator(args: list[str]) -> tuple[bool, str]:
    return best_effort_az(args, azure_config_dir=None)


def best_effort_az_runtime(args: list[str], *, sbx_paths: SandboxPaths) -> tuple[bool, str]:
    return best_effort_az(args, azure_config_dir=sbx_paths.azure_config_dir)


def reset_service_principal_secret(app_id: str, *, append: bool = True) -> tuple[str, str]:
    args = [
        "ad",
        "app",
        "credential",
        "reset",
        "--id",
        app_id,
        "--output",
        "json",
    ]
    if append:
        args.insert(-2, "--append")

    payload = az_json_operator(args)

    secret = str(payload.get("password", "")).strip()
    tenant = str(payload.get("tenant", "")).strip()
    if not secret:
        raise CliError(
            "Unable to recover sandbox credential: 'az ad app credential reset' did not return a password."
        )
    return secret, tenant


def ensure_sandbox_login(state: dict[str, Any], sbx_paths: SandboxPaths) -> tuple[bool, str]:
    expected_sub = state["subscription_id"]
    invalid_secret_retry_limit = 3
    cache_key = str(sbx_paths.azure_config_dir)

    cached = AUTH_SUBSCRIPTION_CACHE.get(cache_key)
    if cached is not None:
        cached_sub, checked_at = cached
        if (
            cached_sub.lower() == expected_sub.lower()
            and (time.monotonic() - checked_at) < AUTH_CACHE_WINDOW_SECONDS
        ):
            ensure_sandbox_cli_defaults(
                azure_config_dir=sbx_paths.azure_config_dir,
                resource_group=state["resource_group_name"],
                location=state["location"],
            )
            return True, "cached-authenticated"

    try:
        account = az_json(
            ["account", "show", "--output", "json"],
            azure_config_dir=sbx_paths.azure_config_dir,
        )
        if str(account.get("id", "")).lower() == expected_sub.lower():
            ensure_sandbox_cli_defaults(
                azure_config_dir=sbx_paths.azure_config_dir,
                resource_group=state["resource_group_name"],
                location=state["location"],
            )
            AUTH_SUBSCRIPTION_CACHE[cache_key] = (expected_sub, time.monotonic())
            return True, "already authenticated"
    except (CommandError, CliError):
        pass

    delay_seconds = LOGIN_RETRY_INITIAL_DELAY_SECONDS
    for attempt in range(1, LOGIN_RETRY_ATTEMPTS + 1):
        try:
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
                azure_config_dir=sbx_paths.azure_config_dir,
                check=True,
                capture_output=True,
            )
            run_az(
                ["account", "set", "--subscription", expected_sub],
                azure_config_dir=sbx_paths.azure_config_dir,
                check=True,
                capture_output=True,
            )

            account_after = az_json(
                ["account", "show", "--output", "json"],
                azure_config_dir=sbx_paths.azure_config_dir,
            )
            if str(account_after.get("id", "")).lower() != expected_sub.lower():
                raise CliError(
                    "Service principal login succeeded, but Azure CLI is not on the expected subscription "
                    f"'{expected_sub}'."
                )

            ensure_sandbox_cli_defaults(
                azure_config_dir=sbx_paths.azure_config_dir,
                resource_group=state["resource_group_name"],
                location=state["location"],
            )
            AUTH_SUBSCRIPTION_CACHE[cache_key] = (expected_sub, time.monotonic())
            if attempt == 1:
                return True, "re-authenticated"
            return True, f"re-authenticated after {attempt} attempts"
        except (CommandError, CliError) as exc:
            message = str(exc)
            if looks_like_invalid_client_secret(message):
                # Newly issued client secrets can take a short time to become valid.
                if attempt < invalid_secret_retry_limit:
                    sleep_seconds = min(delay_seconds, 10)
                    time.sleep(sleep_seconds)
                    delay_seconds = min(delay_seconds * 2, 10)
                    continue
                raise
            if attempt >= LOGIN_RETRY_ATTEMPTS or not looks_like_role_propagation_delay(message):
                AUTH_SUBSCRIPTION_CACHE.pop(cache_key, None)
                raise
            time.sleep(delay_seconds)
            delay_seconds = min(delay_seconds * 2, LOGIN_RETRY_MAX_DELAY_SECONDS)

    AUTH_SUBSCRIPTION_CACHE.pop(cache_key, None)
    raise CliError("Failed to authenticate sandbox service principal after retries.")


def ensure_sandbox_login_with_secret_recovery(
    state: dict[str, Any],
    sbx_paths: SandboxPaths,
    *,
    allow_operator_recovery: bool = False,
) -> None:
    try:
        ensure_sandbox_login(state, sbx_paths)
        return
    except (CliError, CommandError) as exc:
        if not allow_operator_recovery or not looks_like_invalid_client_secret(str(exc)):
            raise

    rotated_secret, tenant_from_reset = reset_service_principal_secret(state["service_principal_app_id"])
    state["service_principal_client_secret"] = rotated_secret
    if tenant_from_reset:
        state["tenant_id"] = tenant_from_reset
    ensure_sandbox_login(state, sbx_paths)


def ensure_runtime_subscription_binding(state: dict[str, Any], sbx_paths: SandboxPaths) -> None:
    expected_sub = state["subscription_id"]
    run_az(
        ["account", "set", "--subscription", expected_sub],
        azure_config_dir=sbx_paths.azure_config_dir,
        check=True,
        capture_output=True,
    )
    account_after = az_json_runtime(
        ["account", "show", "--output", "json"],
        sbx_paths=sbx_paths,
    )
    if str(account_after.get("id", "")).lower() != expected_sub.lower():
        raise CliError(
            "Service principal authentication is not bound to the expected subscription "
            f"'{expected_sub}'."
        )


def resolve_target_sandbox_name(
    fleet: dict[str, Any],
    *,
    explicit_name: str | None,
) -> tuple[str, bool]:
    sandboxes = fleet["sandboxes"]
    if explicit_name:
        if explicit_name not in sandboxes:
            raise CliError(f"Sandbox '{explicit_name}' is not in this workspace fleet.")
        return explicit_name, False

    active = fleet.get("active_sandbox")
    if isinstance(active, str) and active in sandboxes:
        return active, False

    names = sorted(sandboxes.keys())
    if not names:
        raise CliError(
            "No Azure sandboxes are initialized in this workspace. "
            f"Run '{sandbox_az_command('group create --location <location>')}' first."
        )

    if len(names) == 1:
        return names[0], True

    raise CliError(
        "Multiple sandboxes available; use '-g <sandbox-rg>' or "
        f"'{sandbox_az_command('group show --name <rg>')}'."
    )


def next_sandbox_name(fleet: dict[str, Any]) -> str:
    sandboxes = fleet["sandboxes"]
    if "default" not in sandboxes:
        return "default"
    index = 2
    while True:
        name = f"sandbox-{index}"
        if name not in sandboxes:
            return name
        index += 1


def set_active_sandbox(paths: WorkspacePaths, fleet: dict[str, Any], sandbox_name: str | None) -> None:
    fleet["active_sandbox"] = sandbox_name
    write_fleet(paths, fleet)


def compute_expiration(ttl_seconds: int) -> tuple[str, str]:
    touched = now_utc()
    expires = touched + dt.timedelta(seconds=ttl_seconds)
    touched_iso = touched.isoformat().replace("+00:00", "Z")
    expires_iso = expires.isoformat().replace("+00:00", "Z")
    return touched_iso, expires_iso


def apply_expiration_tag(
    state: dict[str, Any],
    *,
    azure_config_dir: Path | None,
    strict: bool,
) -> None:
    args = [
        "group",
        "update",
        "--name",
        state["resource_group_name"],
        "--subscription",
        state["subscription_id"],
        "--set",
        f"tags.codex-expires-at-utc={state['expires_at_utc']}",
        "tags.codex-sandbox=true",
        f"tags.codex-sandbox-name={state['sandbox_name']}",
        f"tags.codex-workspace-id={state['workspace_id']}",
        f"tags.codex-skill={SKILL_NAME}",
        f"tags.codex-ttl-seconds={state['ttl_duration_seconds']}",
        "--output",
        "none",
    ]
    try:
        run_az(args, azure_config_dir=azure_config_dir, check=True, capture_output=True)
    except CommandError:
        if strict:
            raise


def touch_sandbox_expiration(
    paths: WorkspacePaths,
    fleet: dict[str, Any],
    sbx_paths: SandboxPaths,
    state: dict[str, Any],
    *,
    strict_tag_update: bool,
    azure_config_dir_for_tag: Path | None,
    update_cloud_tag: bool = True,
) -> None:
    touched_iso, expires_iso = compute_expiration(state["ttl_duration_seconds"])
    state["last_touched_at_utc"] = touched_iso
    state["expires_at_utc"] = expires_iso
    state["updated_at_utc"] = touched_iso

    write_state(sbx_paths, state)
    update_fleet_summary(paths, fleet, sbx_paths, state)

    if update_cloud_tag:
        apply_expiration_tag(
            state,
            azure_config_dir=azure_config_dir_for_tag,
            strict=strict_tag_update,
        )


def ensure_owner_role_assignment(
    *,
    assignee_object_id: str,
    scope: str,
    subscription_id: str,
) -> None:
    try:
        run_az_operator(
            [
                "role",
                "assignment",
                "create",
                "--assignee-object-id",
                assignee_object_id,
                "--assignee-principal-type",
                "ServicePrincipal",
                "--role",
                "Owner",
                "--scope",
                scope,
                "--subscription",
                subscription_id,
                "--output",
                "none",
            ],
            check=True,
            capture_output=True,
        )
    except CommandError as exc:
        msg = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        if "already exists" in msg.lower():
            return
        raise


def ensure_automation_system_identity(
    *,
    account_id: str,
) -> dict[str, Any]:
    payload: dict[str, Any] | None = None
    last_error: CommandError | None = None

    for version in AUTOMATION_ACCOUNT_API_VERSIONS:
        url = f"https://management.azure.com{account_id}?api-version={version}"
        try:
            payload = az_rest_operator(
                "PATCH",
                url,
                body={"identity": {"type": "SystemAssigned"}},
                check=True,
            )
            break
        except CommandError as exc:
            last_error = exc
            continue

    if payload is None:
        if last_error is not None:
            raise last_error
        raise CliError("Failed to enable system-assigned identity on Automation Account.")

    return payload


def cleanup_runbook_content() -> str:
    return """param(
    [bool]$ForceDelete = $false,
    [string]$ResourceGroupName,
    [string]$SubscriptionId
)

$ErrorActionPreference = 'Stop'

function Write-Log($message) {
    Write-Output "[codex-sbx-cleanup] $message"
}

try {
    Connect-AzAccount -Identity -Subscription $SubscriptionId | Out-Null
} catch {
    throw "Managed identity login failed: $($_.Exception.Message)"
}

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Log "Resource group '$ResourceGroupName' not found. Nothing to do."
    return
}

if ($ForceDelete) {
    Write-Log "ForceDelete=true. Deleting resource group '$ResourceGroupName'."
    Remove-AzResourceGroup -Name $ResourceGroupName -Force -ErrorAction SilentlyContinue | Out-Null
    return
}

$expiresAtRaw = $rg.Tags['codex-expires-at-utc']
if (-not $expiresAtRaw) {
    Write-Log "Expiry tag missing; skipping delete."
    return
}

try {
    $expiresAt = [DateTime]::Parse($expiresAtRaw).ToUniversalTime()
} catch {
    Write-Log "Invalid codex-expires-at-utc tag '$expiresAtRaw'; skipping delete."
    return
}

$now = [DateTime]::UtcNow
if ($now -ge $expiresAt) {
    Write-Log "Expiry reached. Deleting resource group '$ResourceGroupName'."
    Remove-AzResourceGroup -Name $ResourceGroupName -Force -ErrorAction SilentlyContinue | Out-Null
    return
}

Write-Log "Not expired yet. now=$($now.ToString('o')) expires=$($expiresAt.ToString('o'))"
"""


def ensure_cleanup_automation(
    *,
    subscription_id: str,
    resource_group: str,
    location: str,
    resource_group_scope: str,
    workspace_id: str,
    sandbox_name: str,
    workspace_digest: str,
) -> dict[str, Any]:
    ensure_az_extension(AUTOMATION_EXTENSION_NAME)

    account_name = default_automation_account_name(workspace_digest, sandbox_name)

    account = az_json_operator(
        [
            "automation",
            "account",
            "create",
            "--automation-account-name",
            account_name,
            "--resource-group",
            resource_group,
            "--location",
            location,
            "--sku",
            "Basic",
            "--subscription",
            subscription_id,
            "--output",
            "json",
        ]
    )
    account_id = str(account.get("id", "")).strip()
    if not account_id:
        account_id = az_tsv_operator(
            [
                "automation",
                "account",
                "show",
                "--automation-account-name",
                account_name,
                "--resource-group",
                resource_group,
                "--subscription",
                subscription_id,
                "--query",
                "id",
                "--output",
                "tsv",
            ]
        )
    if not account_id:
        raise CliError("Failed to resolve Automation Account resource id.")

    ensure_automation_system_identity(account_id=account_id)

    identity_principal_id = az_tsv_operator(
        [
            "automation",
            "account",
            "show",
            "--automation-account-name",
            account_name,
            "--resource-group",
            resource_group,
            "--subscription",
            subscription_id,
            "--query",
            "identity.principalId",
            "--output",
            "tsv",
        ]
    )
    if not identity_principal_id:
        raise CliError("Failed to resolve Automation Account managed identity principal id.")

    ensure_owner_role_assignment(
        assignee_object_id=identity_principal_id,
        scope=resource_group_scope,
        subscription_id=subscription_id,
    )

    runbook_exists = run_az_operator(
        [
            "automation",
            "runbook",
            "show",
            "--automation-account-name",
            account_name,
            "--resource-group",
            resource_group,
            "--name",
            RUNBOOK_NAME,
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ],
        check=False,
    ).returncode == 0

    if not runbook_exists:
        run_az_operator(
            [
                "automation",
                "runbook",
                "create",
                "--automation-account-name",
                account_name,
                "--resource-group",
                resource_group,
                "--name",
                RUNBOOK_NAME,
                "--type",
                "PowerShell",
                "--location",
                location,
                "--subscription",
                subscription_id,
                "--output",
                "none",
            ],
            check=True,
            capture_output=True,
        )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".ps1", encoding="utf-8") as handle:
        handle.write(cleanup_runbook_content())
        runbook_file = handle.name

    try:
        run_az_operator(
            [
                "automation",
                "runbook",
                "replace-content",
                "--automation-account-name",
                account_name,
                "--resource-group",
                resource_group,
                "--name",
                RUNBOOK_NAME,
                "--subscription",
                subscription_id,
                "--content",
                f"@{runbook_file}",
            ],
            check=True,
            capture_output=True,
        )
    finally:
        Path(runbook_file).unlink(missing_ok=True)

    run_az_operator(
        [
            "automation",
            "runbook",
            "publish",
            "--automation-account-name",
            account_name,
            "--resource-group",
            resource_group,
            "--name",
            RUNBOOK_NAME,
            "--subscription",
            subscription_id,
            "--output",
            "none",
        ],
        check=True,
        capture_output=True,
    )

    now = now_utc()
    earliest_start = now + dt.timedelta(minutes=6)

    schedule_names: list[str] = []
    job_schedule_ids: list[str] = []

    for suffix in RUNBOOK_SCHEDULE_SUFFIXES:
        minute = int(suffix)
        schedule_name = f"codex-expiry-q{suffix}"
        schedule_names.append(schedule_name)
        start = earliest_start.replace(minute=minute, second=0, microsecond=0)
        if start < earliest_start:
            start += dt.timedelta(hours=1)

        exists = run_az_operator(
            [
                "automation",
                "schedule",
                "show",
                "--automation-account-name",
                account_name,
                "--resource-group",
                resource_group,
                "--name",
                schedule_name,
                "--subscription",
                subscription_id,
                "--output",
                "none",
            ],
            check=False,
        ).returncode == 0

        if not exists:
            run_az_operator(
                [
                    "automation",
                    "schedule",
                    "create",
                    "--automation-account-name",
                    account_name,
                    "--resource-group",
                    resource_group,
                    "--name",
                    schedule_name,
                    "--frequency",
                    "Hour",
                    "--interval",
                    "1",
                    "--start-time",
                    start.isoformat().replace("+00:00", "Z"),
                    "--time-zone",
                    "UTC",
                    "--subscription",
                    subscription_id,
                    "--output",
                    "none",
                ],
                check=True,
                capture_output=True,
            )

        schedule_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{workspace_id}:{sandbox_name}:{schedule_name}:cleanup"))
        job_schedule_ids.append(schedule_guid)

        job_url = (
            "https://management.azure.com"
            f"/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Automation/automationAccounts/{account_name}"
            f"/jobSchedules/{schedule_guid}?api-version={AUTOMATION_JOBSCHEDULE_API_VERSION}"
        )
        job_body = {
            "properties": {
                "schedule": {"name": schedule_name},
                "runbook": {"name": RUNBOOK_NAME},
                "parameters": {
                    "ForceDelete": False,
                    "ResourceGroupName": resource_group,
                    "SubscriptionId": subscription_id,
                },
            }
        }
        az_rest_operator("PUT", job_url, body=job_body, check=True)

    return {
        "automation_account_name": account_name,
        "automation_account_id": account_id,
        "automation_identity_principal_id": identity_principal_id,
        "automation_runbook_name": RUNBOOK_NAME,
        "automation_schedule_names": schedule_names,
        "automation_job_schedule_ids": job_schedule_ids,
    }


def put_budget_resource(
    *,
    subscription_id: str,
    resource_group: str,
    budget_name: str,
    amount_usd: float,
    action_group_id: str,
    azure_config_dir: Path | None,
) -> dict[str, Any]:
    now = now_utc()
    start = now.replace(day=1).date().isoformat()
    end = (now + dt.timedelta(days=366)).date().isoformat()

    url = (
        "https://management.azure.com"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Consumption/budgets/{budget_name}"
        f"?api-version={CONSUMPTION_BUDGET_API_VERSION}"
    )

    body = {
        "properties": {
            "category": "Cost",
            "amount": amount_usd,
            "timeGrain": "Monthly",
            "timePeriod": {
                "startDate": start,
                "endDate": end,
            },
            "notifications": {
                "actual100": {
                    "enabled": True,
                    "operator": "GreaterThanOrEqualTo",
                    "threshold": BUDGET_THRESHOLD_PERCENT,
                    "thresholdType": "Actual",
                    "contactGroups": [action_group_id],
                },
                "forecast100": {
                    "enabled": True,
                    "operator": "GreaterThanOrEqualTo",
                    "threshold": BUDGET_THRESHOLD_PERCENT,
                    "thresholdType": "Forecasted",
                    "contactGroups": [action_group_id],
                },
            },
        }
    }

    payload = az_rest("PUT", url, body=body, azure_config_dir=azure_config_dir, check=True)
    payload_id = str(payload.get("id", "")).strip()
    return {"id": payload_id, "name": budget_name}


def delete_budget_resource(
    *,
    subscription_id: str,
    resource_group: str,
    budget_name: str,
    azure_config_dir: Path | None,
) -> tuple[bool, str]:
    if not budget_name:
        return True, "no budget configured"
    url = (
        "https://management.azure.com"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Consumption/budgets/{budget_name}"
        f"?api-version={CONSUMPTION_BUDGET_API_VERSION}"
    )
    try:
        az_rest("DELETE", url, azure_config_dir=azure_config_dir, check=True)
        return True, "ok"
    except CommandError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        if looks_like_not_found(message):
            return True, f"already absent ({message})"
        return False, message


def ensure_budget_stack(
    state: dict[str, Any],
    *,
    amount_usd: float,
    azure_config_dir: Path | None,
) -> dict[str, Any]:
    subscription_id = state["subscription_id"]
    resource_group = state["resource_group_name"]
    account_name = state["automation_account_name"]
    runbook_name = state["automation_runbook_name"]

    webhook_name = state.get("budget_webhook_name") or default_webhook_name(state["sandbox_name"])
    action_group_name = state.get("budget_action_group_name") or default_action_group_name(state["sandbox_name"])
    budget_name = state.get("budget_name") or default_budget_name(state["sandbox_name"])

    webhook_url = (
        "https://management.azure.com"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Automation/automationAccounts/{account_name}"
        f"/webhooks/{webhook_name}?api-version={AUTOMATION_WEBHOOK_API_VERSION}"
    )

    az_rest("DELETE", webhook_url, azure_config_dir=azure_config_dir, check=False)

    webhook_body = {
        "properties": {
            "isEnabled": True,
            "expiryTime": (now_utc() + dt.timedelta(days=3650)).isoformat().replace("+00:00", "Z"),
            "runbook": {"name": runbook_name},
            "parameters": {
                "ForceDelete": "true",
                "ResourceGroupName": resource_group,
                "SubscriptionId": subscription_id,
            },
        }
    }
    webhook = az_rest(
        "PUT",
        webhook_url,
        body=webhook_body,
        azure_config_dir=azure_config_dir,
        check=True,
    )
    webhook_uri = str(webhook.get("properties", {}).get("uri", "")).strip()
    webhook_resource_id = str(webhook.get("id", "")).strip()
    if not webhook_uri:
        raise CliError("Failed to retrieve automation webhook URI for budget trigger.")

    run_az(
        [
            "monitor",
            "action-group",
            "delete",
            "--resource-group",
            resource_group,
            "--name",
            action_group_name,
            "--subscription",
            subscription_id,
            "--yes",
        ],
        azure_config_dir=azure_config_dir,
        check=False,
        capture_output=True,
    )

    short_name = re.sub(r"[^A-Za-z0-9]", "", action_group_name)[:12] or "codexsbx"
    action_group = az_json(
        [
            "monitor",
            "action-group",
            "create",
            "--resource-group",
            resource_group,
            "--name",
            action_group_name,
            "--short-name",
            short_name,
            "--action",
            "webhook",
            "budgetDestroy",
            webhook_uri,
            "--subscription",
            subscription_id,
            "--output",
            "json",
        ],
        azure_config_dir=azure_config_dir,
    )
    action_group_id = str(action_group.get("id", "")).strip()
    if not action_group_id:
        action_group_id = az_tsv(
            [
                "monitor",
                "action-group",
                "show",
                "--resource-group",
                resource_group,
                "--name",
                action_group_name,
                "--subscription",
                subscription_id,
                "--query",
                "id",
                "--output",
                "tsv",
            ],
            azure_config_dir=azure_config_dir,
        )

    budget = put_budget_resource(
        subscription_id=subscription_id,
        resource_group=resource_group,
        budget_name=budget_name,
        amount_usd=amount_usd,
        action_group_id=action_group_id,
        azure_config_dir=azure_config_dir,
    )

    return {
        "budget_enabled": True,
        "budget_usd": amount_usd,
        "budget_threshold_percent": BUDGET_THRESHOLD_PERCENT,
        "budget_name": budget_name,
        "budget_resource_id": budget["id"],
        "budget_action_group_name": action_group_name,
        "budget_action_group_id": action_group_id,
        "budget_webhook_name": webhook_name,
        "budget_webhook_resource_id": webhook_resource_id,
    }


def clear_budget_stack(
    state: dict[str, Any],
    *,
    azure_config_dir: Path | None,
) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []

    ok_budget, detail_budget = delete_budget_resource(
        subscription_id=state["subscription_id"],
        resource_group=state["resource_group_name"],
        budget_name=state.get("budget_name", ""),
        azure_config_dir=azure_config_dir,
    )
    ops.append({"step": "delete-budget", "ok": ok_budget, "details": detail_budget})

    if state.get("budget_action_group_name"):
        ok_ag, detail_ag = best_effort_az(
            [
                "monitor",
                "action-group",
                "delete",
                "--resource-group",
                state["resource_group_name"],
                "--name",
                state["budget_action_group_name"],
                "--subscription",
                state["subscription_id"],
                "--yes",
            ],
            azure_config_dir=azure_config_dir,
        )
    else:
        ok_ag, detail_ag = True, "no action group configured"
    ops.append({"step": "delete-action-group", "ok": ok_ag, "details": detail_ag})

    webhook_name = state.get("budget_webhook_name", "")
    if webhook_name:
        webhook_url = (
            "https://management.azure.com"
            f"/subscriptions/{state['subscription_id']}"
            f"/resourceGroups/{state['resource_group_name']}"
            f"/providers/Microsoft.Automation/automationAccounts/{state['automation_account_name']}"
            f"/webhooks/{webhook_name}?api-version={AUTOMATION_WEBHOOK_API_VERSION}"
        )
        try:
            az_rest("DELETE", webhook_url, azure_config_dir=azure_config_dir, check=True)
            ok_hook, detail_hook = True, "ok"
        except CommandError as exc:
            msg = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            if looks_like_not_found(msg):
                ok_hook, detail_hook = True, f"already absent ({msg})"
            else:
                ok_hook, detail_hook = False, msg
    else:
        ok_hook, detail_hook = True, "no webhook configured"

    ops.append({"step": "delete-webhook", "ok": ok_hook, "details": detail_hook})
    return ops


def parse_create_args(raw_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=sandbox_az_command("group create"), add_help=True)
    parser.add_argument("--name", "--resource-group", "-g", "-n", dest="name")
    parser.add_argument("--location", "-l")
    parser.add_argument("--expires-in")
    parser.add_argument("--budget-usd")
    parser.add_argument("--recreate", action="store_true")
    parser.add_argument("--json", action="store_true")
    add_az_global_arguments(parser)

    parsed, unknown = parser.parse_known_args(raw_args)
    if unknown:
        joined = " ".join(unknown)
        raise CliError(
            f"Unsupported arguments for '{sandbox_az_command('group create')}': "
            f"{joined}. Use '{sandbox_az_command('group create [--name|--resource-group <rg-name>] [--location <location>]')} "
            "[--subscription <id>] [--output <format>] [--query <jmespath>] [--expires-in <duration>] "
            "[--budget-usd <amount>] [--recreate] [--json]'."
        )
    return parsed


def parse_list_args(raw_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=sandbox_az_command("group list"), add_help=True)
    parser.add_argument("--tag")
    parser.add_argument("--json", action="store_true")
    add_az_global_arguments(parser)
    parsed, unknown = parser.parse_known_args(raw_args)
    if unknown:
        raise CliError(
            f"Unsupported arguments for '{sandbox_az_command('group list')}'. "
            f"Use '{sandbox_az_command('group list [--tag key[=value]] [--subscription <id>]')} "
            "[--output <format>] [--query <jmespath>] [--json]'."
        )
    return parsed


def parse_group_show_args(raw_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=sandbox_az_command("group show"), add_help=True)
    parser.add_argument("--name", "--resource-group", "-g", "-n", dest="name")
    parser.add_argument("--json", action="store_true")
    add_az_global_arguments(parser)
    parsed, unknown = parser.parse_known_args(raw_args)
    if unknown:
        raise CliError(
            f"Unsupported arguments for '{sandbox_az_command('group show')}'. "
            f"Use '{sandbox_az_command('group show [--name|--resource-group <rg-name>]')} "
            "[--subscription <id>] [--output <format>] [--query <jmespath>] [--json]'."
        )
    return parsed


def parse_group_delete_args(raw_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=sandbox_az_command("group delete"), add_help=True)
    parser.add_argument("--name", "--resource-group", "-g", "-n", dest="name")
    parser.add_argument("--yes", "-y", action="store_true")
    parser.add_argument("--no-wait", action="store_true")
    parser.add_argument("--force-deletion-types", "-f", nargs="+")
    parser.add_argument("--json", action="store_true")
    add_az_global_arguments(parser)
    parsed, unknown = parser.parse_known_args(raw_args)
    if unknown:
        raise CliError(
            f"Unsupported arguments for '{sandbox_az_command('group delete')}'. "
            f"Use '{sandbox_az_command('group delete --name|--resource-group <rg-name> --yes')} "
            "[--no-wait] [--force-deletion-types ...] [--subscription <id>] "
            "[--output <format>] [--query <jmespath>] [--json]'."
        )
    if not parsed.name:
        raise CliError(f"{sandbox_az_command('group delete')} requires --name <rg-name>.")
    if not parsed.yes:
        raise CliError(f"{sandbox_az_command('group delete')} requires --yes for non-interactive execution.")
    return parsed


def parse_group_exists_args(raw_args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=sandbox_az_command("group exists"), add_help=True)
    parser.add_argument("--name", "--resource-group", "-g", "-n", dest="name")
    parser.add_argument("--json", action="store_true")
    add_az_global_arguments(parser)
    parsed, unknown = parser.parse_known_args(raw_args)
    if unknown:
        raise CliError(
            f"Unsupported arguments for '{sandbox_az_command('group exists')}'. "
            f"Use '{sandbox_az_command('group exists --name|--resource-group <rg-name>')} "
            "[--subscription <id>] [--output <format>] [--query <jmespath>] [--json]'."
        )
    if not parsed.name:
        raise CliError(f"{sandbox_az_command('group exists')} requires --name <rg-name>.")
    return parsed


def parse_passthrough_target(args: list[str]) -> tuple[str | None, list[str]]:
    if not args:
        return None, []

    explicit: str | None = None
    consumed = 0

    token0 = args[0]
    if token0 == "--sandbox":
        if len(args) < 2:
            raise CliError(f"Usage: {sandbox_az_command('--sandbox <name> <azure-cli-args...>')}")
        explicit = args[1]
        consumed = 2
        if len(args) > consumed and args[consumed] == "--":
            consumed += 1
    elif token0.startswith("--sandbox="):
        explicit = token0.split("=", 1)[1]
        consumed = 1
        if len(args) > consumed and args[consumed] == "--":
            consumed += 1
    elif token0 == "--":
        consumed = 1
        if len(args) > consumed and args[consumed] == "--sandbox":
            if len(args) <= consumed + 1:
                raise CliError(f"Usage: {sandbox_az_command('-- --sandbox <name> -- <azure-cli-args...>')}")
            explicit = args[consumed + 1]
            consumed += 2
            if len(args) > consumed and args[consumed] == "--":
                consumed += 1
        elif len(args) > consumed and args[consumed].startswith("--sandbox="):
            explicit = args[consumed].split("=", 1)[1]
            consumed += 1
            if len(args) > consumed and args[consumed] == "--":
                consumed += 1

    return explicit, args[consumed:]


def check_health_quick(
    paths: WorkspacePaths,
    fleet: dict[str, Any],
    sandbox_name: str,
    state: dict[str, Any],
    *,
    allow_relogin: bool,
) -> dict[str, Any]:
    sbx_paths = resolve_sandbox_paths(paths, sandbox_name)

    checks: list[dict[str, Any]] = []
    remediations: list[str] = []

    def add_check(name: str, ok: bool, details: str, remediation: str | None = None) -> None:
        checks.append({"name": name, "ok": ok, "details": details})
        if not ok and remediation:
            remediations.append(remediation)

    add_check(
        "state-schema",
        True,
        f"State for sandbox '{sandbox_name}' is valid (version {state['version']}).",
    )

    rg_exists = False
    try:
        exists = az_tsv_runtime(
            [
                "group",
                "exists",
                "--name",
                state["resource_group_name"],
                "--subscription",
                state["subscription_id"],
                "--output",
                "tsv",
            ],
            sbx_paths=sbx_paths,
        )
        rg_exists = exists.strip().lower() == "true"
        add_check(
            "resource-group-exists",
            rg_exists,
            f"Resource group '{state['resource_group_name']}' exists={rg_exists}.",
            f"Run '{sandbox_az_command('group create --name <rg-name> --location <location> --recreate')}'.",
        )
    except CommandError as exc:
        add_check(
            "resource-group-exists",
            False,
            exc.stderr.strip() or exc.stdout.strip() or str(exc),
            "Ensure runtime sandbox credentials can read the bound subscription scope.",
        )

    auth_ok = False
    auth_detail = ""
    try:
        account = az_json_runtime(["account", "show", "--output", "json"], sbx_paths=sbx_paths)
        auth_ok = str(account.get("id", "")).lower() == state["subscription_id"].lower()
        auth_detail = f"Sandbox AZURE_CONFIG_DIR account id={account.get('id', '')}."
    except (CommandError, CliError) as exc:
        auth_detail = str(exc)

    if not auth_ok and allow_relogin:
        try:
            ensure_sandbox_login_with_secret_recovery(
                state,
                sbx_paths,
                allow_operator_recovery=False,
            )
            auth_ok = True
            auth_detail = "Recovered sandbox authentication."
            write_state(sbx_paths, state)
            update_fleet_summary(paths, fleet, sbx_paths, state)
        except (CommandError, CliError) as exc:
            auth_detail = str(exc)

    add_check(
        "runtime-auth",
        auth_ok,
        auth_detail,
        f"Run '{sandbox_az_command('group create --name <rg-name> --location <location> --recreate')}' if credentials are invalid.",
    )

    ignore_ok = gitignore_has_line(paths)
    add_check(
        "gitignore-protection",
        ignore_ok,
        f"{paths.gitignore_file} contains '{GITIGNORE_LINE}'={ignore_ok}.",
        "Add '.sandbox/azure/' to workspace .gitignore.",
    )

    healthy = all(check["ok"] for check in checks)
    return {
        "sandbox": sandbox_name,
        "mode": "quick",
        "healthy": healthy,
        "checks": checks,
        "remediation": remediations,
        "active": fleet.get("active_sandbox") == sandbox_name,
        "expires_at_utc": state["expires_at_utc"],
    }


def check_health_deep(
    paths: WorkspacePaths,
    fleet: dict[str, Any],
    sandbox_name: str,
    state: dict[str, Any],
    *,
    allow_relogin: bool,
) -> dict[str, Any]:
    sbx_paths = resolve_sandbox_paths(paths, sandbox_name)

    checks: list[dict[str, Any]] = []
    remediations: list[str] = []

    def add_check(name: str, ok: bool, details: str, remediation: str | None = None) -> None:
        checks.append({"name": name, "ok": ok, "details": details})
        if not ok and remediation:
            remediations.append(remediation)

    add_check(
        "state-schema",
        True,
        f"State for sandbox '{sandbox_name}' is valid (version {state['version']}).",
    )

    rg_exists = False
    try:
        exists = az_tsv_runtime(
            [
                "group",
                "exists",
                "--name",
                state["resource_group_name"],
                "--subscription",
                state["subscription_id"],
                "--output",
                "tsv",
            ],
            sbx_paths=sbx_paths,
        )
        rg_exists = exists.strip().lower() == "true"
        add_check(
            "resource-group-exists",
            rg_exists,
            f"Resource group '{state['resource_group_name']}' exists={rg_exists}.",
            f"Run '{sandbox_az_command('group create --name <rg-name> --location <location> --recreate')}'.",
        )
    except CommandError as exc:
        add_check(
            "resource-group-exists",
            False,
            exc.stderr.strip() or exc.stdout.strip() or str(exc),
            "Ensure runtime sandbox credentials can read the bound subscription scope.",
        )

    auth_ok = False
    auth_detail = ""
    try:
        account = az_json_runtime(["account", "show", "--output", "json"], sbx_paths=sbx_paths)
        auth_ok = str(account.get("id", "")).lower() == state["subscription_id"].lower()
        auth_detail = f"Sandbox AZURE_CONFIG_DIR account id={account.get('id', '')}."
    except (CommandError, CliError) as exc:
        auth_detail = str(exc)

    if not auth_ok and allow_relogin:
        try:
            ensure_sandbox_login_with_secret_recovery(
                state,
                sbx_paths,
                allow_operator_recovery=False,
            )
            auth_ok = True
            auth_detail = "Recovered sandbox authentication."
            write_state(sbx_paths, state)
            update_fleet_summary(paths, fleet, sbx_paths, state)
        except (CommandError, CliError) as exc:
            auth_detail = str(exc)

    add_check(
        "runtime-auth",
        auth_ok,
        auth_detail,
        "Recreate sandbox if credentials are expired and cannot be rotated.",
    )

    automation_ok = False
    try:
        run_az_runtime(
            [
                "automation",
                "account",
                "show",
                "--automation-account-name",
                state["automation_account_name"],
                "--resource-group",
                state["resource_group_name"],
                "--subscription",
                state["subscription_id"],
                "--output",
                "none",
            ],
            sbx_paths=sbx_paths,
            check=True,
            capture_output=True,
        )
        automation_ok = True
        add_check(
            "cleanup-automation-account",
            True,
            f"Automation account '{state['automation_account_name']}' exists.",
        )
    except CommandError as exc:
        add_check(
            "cleanup-automation-account",
            False,
            exc.stderr.strip() or exc.stdout.strip() or str(exc),
            "Recreate sandbox cleanup automation stack (create --recreate).",
        )

    if automation_ok:
        try:
            runbook_state = az_tsv_runtime(
                [
                    "automation",
                    "runbook",
                    "show",
                    "--automation-account-name",
                    state["automation_account_name"],
                    "--resource-group",
                    state["resource_group_name"],
                    "--name",
                    state["automation_runbook_name"],
                    "--subscription",
                    state["subscription_id"],
                    "--query",
                    "state",
                    "--output",
                    "tsv",
                ],
                sbx_paths=sbx_paths,
            )
            ok = runbook_state.lower() == "published"
            add_check(
                "cleanup-runbook-published",
                ok,
                f"Runbook state is '{runbook_state}'.",
                "Publish the cleanup runbook.",
            )
        except CommandError as exc:
            add_check(
                "cleanup-runbook-published",
                False,
                exc.stderr.strip() or exc.stdout.strip() or str(exc),
                "Recreate cleanup runbook and publish it.",
            )
    else:
        add_check(
            "cleanup-runbook-published",
            False,
            "Skipped because cleanup automation account is missing.",
            "Repair cleanup automation account first.",
        )

    schedule_ok = True
    if automation_ok:
        missing_schedules: list[str] = []
        for schedule_name in state["automation_schedule_names"]:
            proc = run_az_runtime(
                [
                    "automation",
                    "schedule",
                    "show",
                    "--automation-account-name",
                    state["automation_account_name"],
                    "--resource-group",
                    state["resource_group_name"],
                    "--name",
                    schedule_name,
                    "--subscription",
                    state["subscription_id"],
                    "--output",
                    "none",
                ],
                sbx_paths=sbx_paths,
                check=False,
            )
            if proc.returncode != 0:
                schedule_ok = False
                missing_schedules.append(schedule_name)

        add_check(
            "cleanup-schedules",
            schedule_ok,
            "All cleanup schedules exist." if schedule_ok else f"Missing schedules: {', '.join(missing_schedules)}",
            "Recreate cleanup schedules and job schedule bindings.",
        )
    else:
        add_check(
            "cleanup-schedules",
            False,
            "Skipped because cleanup automation account is missing.",
            "Repair cleanup automation account first.",
        )

    job_bind_ok = True
    if automation_ok:
        missing_jobs: list[str] = []
        for job_id in state["automation_job_schedule_ids"]:
            job_url = (
                "https://management.azure.com"
                f"/subscriptions/{state['subscription_id']}"
                f"/resourceGroups/{state['resource_group_name']}"
                f"/providers/Microsoft.Automation/automationAccounts/{state['automation_account_name']}"
                f"/jobSchedules/{job_id}?api-version={AUTOMATION_JOBSCHEDULE_API_VERSION}"
            )
            proc = run_az_runtime(
                ["rest", "--method", "GET", "--url", job_url, "--output", "json"],
                sbx_paths=sbx_paths,
                check=False,
            )
            if proc.returncode != 0:
                job_bind_ok = False
                missing_jobs.append(job_id)

        add_check(
            "cleanup-job-schedules",
            job_bind_ok,
            "All cleanup job schedules exist." if job_bind_ok else f"Missing job schedules: {', '.join(missing_jobs)}",
            "Recreate cleanup job schedule links.",
        )
    else:
        add_check(
            "cleanup-job-schedules",
            False,
            "Skipped because cleanup automation account is missing.",
            "Repair cleanup automation account first.",
        )

    budget_enabled = bool(state.get("budget_enabled"))
    if budget_enabled:
        budget_ok = True
        budget_errors: list[str] = []

        budget_url = (
            "https://management.azure.com"
            f"/subscriptions/{state['subscription_id']}"
            f"/resourceGroups/{state['resource_group_name']}"
            f"/providers/Microsoft.Consumption/budgets/{state['budget_name']}"
            f"?api-version={CONSUMPTION_BUDGET_API_VERSION}"
        )
        budget_proc = run_az_runtime(
            ["rest", "--method", "GET", "--url", budget_url, "--output", "json"],
            sbx_paths=sbx_paths,
            check=False,
        )
        if budget_proc.returncode != 0:
            budget_ok = False
            budget_errors.append("budget")

        action_proc = run_az_runtime(
            [
                "monitor",
                "action-group",
                "show",
                "--resource-group",
                state["resource_group_name"],
                "--name",
                state["budget_action_group_name"],
                "--subscription",
                state["subscription_id"],
                "--output",
                "none",
            ],
            sbx_paths=sbx_paths,
            check=False,
        )
        if action_proc.returncode != 0:
            budget_ok = False
            budget_errors.append("action-group")

        webhook_url = (
            "https://management.azure.com"
            f"/subscriptions/{state['subscription_id']}"
            f"/resourceGroups/{state['resource_group_name']}"
            f"/providers/Microsoft.Automation/automationAccounts/{state['automation_account_name']}"
            f"/webhooks/{state['budget_webhook_name']}?api-version={AUTOMATION_WEBHOOK_API_VERSION}"
        )
        webhook_proc = run_az_runtime(
            ["rest", "--method", "GET", "--url", webhook_url, "--output", "json"],
            sbx_paths=sbx_paths,
            check=False,
        )
        if webhook_proc.returncode != 0:
            budget_ok = False
            budget_errors.append("webhook")

        add_check(
            "budget-stack",
            budget_ok,
            "Budget auto-destroy stack is healthy." if budget_ok else f"Missing budget components: {', '.join(budget_errors)}",
            (
                f"Run '{sandbox_az_command('group create --name <rg-name> --location <location> --budget-usd <amount> --recreate')}' "
                "to recreate budget stack."
            ),
        )
    else:
        add_check("budget-stack", True, "Budget auto-destroy is disabled for this sandbox.")

    ignore_ok = gitignore_has_line(paths)
    add_check(
        "gitignore-protection",
        ignore_ok,
        f"{paths.gitignore_file} contains '{GITIGNORE_LINE}'={ignore_ok}.",
        "Add '.sandbox/azure/' to workspace .gitignore.",
    )

    healthy = all(check["ok"] for check in checks)
    return {
        "sandbox": sandbox_name,
        "mode": "deep",
        "healthy": healthy,
        "checks": checks,
        "remediation": remediations,
        "active": fleet.get("active_sandbox") == sandbox_name,
        "expires_at_utc": state["expires_at_utc"],
    }


def print_status_report(report: dict[str, Any]) -> None:
    print(f"sandbox: {report.get('sandbox', 'unknown')}")
    print(f"healthy: {str(report['healthy']).lower()}")
    if "active" in report:
        print(f"active: {str(bool(report['active'])).lower()}")
    if "expires_at_utc" in report:
        print(f"expires_at_utc: {report['expires_at_utc']}")
    for check in report["checks"]:
        badge = "OK" if check["ok"] else "FAIL"
        print(f"[{badge}] {check['name']}: {check['details']}")
    if report["remediation"]:
        print("remediation:")
        for item in report["remediation"]:
            print(f"- {item}")


def run_best_effort_step_with_progress(
    *,
    reporter: ProgressReporter | None,
    index: int,
    total: int,
    step_name: str,
    detail: str,
    fn: Callable[[], tuple[bool, str]],
) -> tuple[bool, str]:
    if reporter is None:
        return fn()
    return run_with_progress(
        reporter=reporter,
        index=index,
        total=total,
        step_name=step_name,
        detail=detail,
        fn=fn,
        result_ok=lambda result: (result[0], result[1]),
    )


def destroy_single_sandbox(
    *,
    paths: WorkspacePaths,
    fleet: dict[str, Any],
    sandbox_name: str,
    no_wait: bool = False,
    force_deletion_types: list[str] | None = None,
    reporter: ProgressReporter | None = None,
) -> dict[str, Any]:
    sbx_paths = resolve_sandbox_paths(paths, sandbox_name)
    state = load_state(paths, sandbox_name)

    operations: list[dict[str, Any]] = []

    group_delete_args = [
        "group",
        "delete",
        "--name",
        state["resource_group_name"],
        "--subscription",
        state["subscription_id"],
        "--yes",
    ]
    if no_wait:
        group_delete_args.append("--no-wait")
    if force_deletion_types:
        group_delete_args.extend(["--force-deletion-types", *force_deletion_types])

    rg_ok, rg_detail = run_best_effort_step_with_progress(
        reporter=reporter,
        index=1,
        total=5,
        step_name="Delete resource group",
        detail=f"for '{state['resource_group_name']}'.",
        fn=lambda: best_effort_az_operator(group_delete_args),
    )
    operations.append({"step": "delete-resource-group", "ok": rg_ok, "details": rg_detail})

    role_ok, role_detail = run_best_effort_step_with_progress(
        reporter=reporter,
        index=2,
        total=5,
        step_name="Delete runtime role assignment",
        detail="for service principal Owner scope.",
        fn=lambda: best_effort_az_operator(
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
        ),
    )
    operations.append({"step": "delete-runtime-sp-role", "ok": role_ok, "details": role_detail})

    sp_ok, sp_detail = run_best_effort_step_with_progress(
        reporter=reporter,
        index=3,
        total=5,
        step_name="Delete runtime service principal",
        detail=f"for app '{state['service_principal_app_id']}'.",
        fn=lambda: best_effort_az_operator(["ad", "sp", "delete", "--id", state["service_principal_app_id"]]),
    )
    operations.append({"step": "delete-runtime-sp", "ok": sp_ok, "details": sp_detail})

    app_ok, app_detail = run_best_effort_step_with_progress(
        reporter=reporter,
        index=4,
        total=5,
        step_name="Delete runtime app registration",
        detail=f"for app '{state['service_principal_app_id']}'.",
        fn=lambda: best_effort_az_operator(["ad", "app", "delete", "--id", state["service_principal_app_id"]]),
    )
    operations.append({"step": "delete-runtime-app", "ok": app_ok, "details": app_detail})

    def remove_local_state() -> tuple[bool, str]:
        if sbx_paths.root.exists():
            shutil.rmtree(sbx_paths.root, ignore_errors=True)
            return True, "ok"
        return True, "already absent"

    local_ok, local_detail = run_best_effort_step_with_progress(
        reporter=reporter,
        index=5,
        total=5,
        step_name="Remove local sandbox files",
        detail=f"under '{sbx_paths.root}'.",
        fn=remove_local_state,
    )
    operations.append({"step": "remove-local-sandbox-dir", "ok": local_ok, "details": local_detail})

    fleet["sandboxes"].pop(sandbox_name, None)
    if fleet.get("active_sandbox") == sandbox_name:
        remaining = sorted(fleet["sandboxes"].keys())
        fleet["active_sandbox"] = remaining[0] if remaining else None
    write_fleet(paths, fleet)

    healthy = all(op["ok"] for op in operations)
    return {
        "sandbox": sandbox_name,
        "healthy": healthy,
        "operations": operations,
        "resource_group_name": state["resource_group_name"],
        "service_principal_app_id": state["service_principal_app_id"],
    }


def resolve_default_location_from_operator_profile() -> str | None:
    try:
        payload = az_json_operator(["config", "get", "defaults.location", "--output", "json"])
    except (CliError, CommandError):
        return None

    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip().lower()
            value = str(item.get("value", "")).strip()
            if name == "defaults.location" and value:
                return value
        for item in payload:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value", "")).strip()
            if value:
                return value

    if isinstance(payload, dict):
        value = str(payload.get("value", "")).strip()
        if value:
            return value
        nested = payload.get("defaults", {})
        if isinstance(nested, dict):
            nested_value = str(nested.get("location", "")).strip()
            if nested_value:
                return nested_value

    return None


def require_location_for_group_create(location: str | None, *, paths: WorkspacePaths) -> str:
    if location and location.strip():
        return location.strip()

    from_operator_profile = resolve_default_location_from_operator_profile()
    if from_operator_profile:
        return from_operator_profile

    from_env = os.environ.get("AZURE_DEFAULTS_LOCATION", "").strip()
    if from_env:
        return from_env

    hints = ", ".join(AZURE_LOCATION_HINTS)
    raise CliError(
        f"{sandbox_az_command('group create', paths=paths)} requires --location <location>. "
        f"Examples: {hints}."
    )


def rollback_partial_sandbox_create(
    *,
    sbx_paths: SandboxPaths,
    subscription_id: str,
    resource_group: str,
    app_id: str,
    object_id: str,
    scope: str,
    reporter: ProgressReporter | None = None,
) -> None:
    if sbx_paths.root.exists():
        shutil.rmtree(sbx_paths.root, ignore_errors=True)
        if reporter is not None:
            reporter.rollback_step(step="remove-local-sandbox-dir", ok=True, detail="ok")
    elif reporter is not None:
        reporter.rollback_step(step="remove-local-sandbox-dir", ok=True, detail="already absent")

    if object_id:
        role_ok, role_detail = best_effort_az_operator(
            [
                "role",
                "assignment",
                "delete",
                "--assignee-object-id",
                object_id,
                "--role",
                "Owner",
                "--scope",
                scope,
                "--subscription",
                subscription_id,
            ]
        )
        if reporter is not None:
            reporter.rollback_step(step="delete-runtime-sp-role", ok=role_ok, detail=role_detail)
    elif reporter is not None:
        reporter.rollback_step(step="delete-runtime-sp-role", ok=True, detail="skipped (missing object id)")

    if app_id:
        sp_ok, sp_detail = best_effort_az_operator(["ad", "sp", "delete", "--id", app_id])
        app_ok, app_detail = best_effort_az_operator(["ad", "app", "delete", "--id", app_id])
        if reporter is not None:
            reporter.rollback_step(step="delete-runtime-sp", ok=sp_ok, detail=sp_detail)
            reporter.rollback_step(step="delete-runtime-app", ok=app_ok, detail=app_detail)
    elif reporter is not None:
        reporter.rollback_step(step="delete-runtime-sp", ok=True, detail="skipped (missing app id)")
        reporter.rollback_step(step="delete-runtime-app", ok=True, detail="skipped (missing app id)")

    rg_ok, rg_detail = best_effort_az_operator(
        [
            "group",
            "delete",
            "--name",
            resource_group,
            "--subscription",
            subscription_id,
            "--yes",
        ]
    )
    if reporter is not None:
        reporter.rollback_step(step="delete-resource-group", ok=rg_ok, detail=rg_detail)


def wait_for_runtime_identity_readiness(
    state: dict[str, Any],
    sbx_paths: SandboxPaths,
    *,
    reporter: ProgressReporter | None = None,
    step_name: str = "runtime identity readiness",
) -> None:
    deadline = time.monotonic() + READINESS_MAX_WAIT_SECONDS
    delay = READINESS_INITIAL_DELAY_SECONDS
    reset_attempted = False
    last_error = ""
    attempt = 0
    started = time.monotonic()

    while time.monotonic() < deadline:
        attempt += 1
        if reporter is not None and reporter.enabled:
            reporter.info(f"Attempt {attempt}: verifying service principal login and subscription binding.")
        try:
            ensure_sandbox_login(state, sbx_paths)
            ensure_runtime_subscription_binding(state, sbx_paths)
            return
        except (CliError, CommandError) as exc:
            message = str(exc)
            last_error = message
            terse = message.strip().splitlines()[0] if message.strip() else "runtime readiness check failed"
            if reporter is not None and reporter.debug:
                reporter.debug_detail(f"Attempt {attempt} error: {message}")
            if looks_like_invalid_client_secret(message) and not reset_attempted:
                if reporter is not None and reporter.enabled:
                    reporter.info("Detected invalid secret; rotating once and retrying.")
                rotated_secret, tenant_from_reset = reset_service_principal_secret(
                    state["service_principal_app_id"]
                )
                state["service_principal_client_secret"] = rotated_secret
                if tenant_from_reset:
                    state["tenant_id"] = tenant_from_reset
                reset_attempted = True
                continue
            if reporter is not None and reporter.enabled:
                reporter.info(f"Attempt {attempt}: {terse}")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        jitter = random.uniform(0.0, 0.75)
        sleep_for = min(delay + jitter, remaining)
        if reporter is not None and reporter.enabled:
            reporter.info(f"Attempt {attempt}: role propagation still pending; retrying in {int(round(sleep_for))}s.")
        slept = 0.0
        while slept < sleep_for:
            chunk = min(HEARTBEAT_INTERVAL_SECONDS, sleep_for - slept)
            time.sleep(chunk)
            slept += chunk
            if reporter is not None and reporter.enabled and slept < sleep_for:
                reporter.heartbeat(step_name, elapsed_seconds=time.monotonic() - started)
        delay = min(delay * 2, READINESS_MAX_DELAY_SECONDS)

    if last_error:
        raise CliError(
            "sandbox created identity not ready in time; rolled back; retry create. "
            f"Last error: {last_error}"
        )
    raise CliError("sandbox created identity not ready in time; rolled back; retry create")


def cmd_create(args: argparse.Namespace) -> int:
    paths = resolve_workspace_paths()
    ensure_workspace_runtime(paths)
    output_name = normalize_output_name(args.output, json_alias=args.json)
    reporter = ProgressReporter(
        enabled=not bool(getattr(args, "only_show_errors", False)),
        verbose=bool(getattr(args, "verbose", False)),
        debug=bool(getattr(args, "debug", False)),
    )

    fleet = load_fleet(paths, required=False)
    ttl_seconds = parse_duration_seconds(args.expires_in)
    budget_usd = parse_budget_value(args.budget_usd)

    location = require_location_for_group_create(args.location, paths=paths)

    ws_slug, ws_digest, workspace_id = workspace_identity(paths.workspace)
    resource_group = args.name.strip() if args.name else default_resource_group_name(ws_slug, ws_digest, "default")
    if not resource_group:
        raise CliError(f"{sandbox_az_command('group create')} requires a non-empty --name when provided.")

    existing_key = resolve_key_by_resource_group(fleet, resource_group)
    if existing_key and not args.recreate:
        sbx_state = load_state(paths, existing_key)
        payload = make_group_payload(
            sbx_state,
            active=fleet.get("active_sandbox") == existing_key,
            state_file=str(resolve_sandbox_paths(paths, existing_key).state_file),
        )
        payload["sandbox"]["status"] = "alreadyExists"
        emit_intercept_output(payload, output=output_name, query=args.query)
        return 0

    if existing_key and args.recreate:
        reporter.info(f"Recreate requested: deleting existing sandbox '{existing_key}' first.")
        destroy_single_sandbox(
            paths=paths,
            fleet=fleet,
            sandbox_name=existing_key,
            reporter=reporter,
        )

    subscription_id, tenant_id = resolve_subscription_and_tenant(args.subscription)
    sandbox_name = resource_group
    sp_name = resource_group
    scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"

    touched_iso, expires_iso = compute_expiration(ttl_seconds)
    total_steps = 8

    rg_create_args = [
        "group",
        "create",
        "--name",
        resource_group,
        "--location",
        location,
        "--subscription",
        subscription_id,
        "--tags",
        "codex-sandbox=true",
        f"codex-workspace-id={workspace_id}",
        f"codex-skill={SKILL_NAME}",
        f"codex-sandbox-name={sandbox_name}",
        f"codex-expires-at-utc={expires_iso}",
        f"codex-ttl-seconds={ttl_seconds}",
        "--output",
        "none",
    ]

    def step_detail(base: str, cmd: list[str] | None = None) -> str:
        if not reporter.debug or cmd is None:
            return base
        return f"{base} (command: {redact_command_for_logs(['az', *cmd])})"

    run_with_progress(
        reporter=reporter,
        index=1,
        total=total_steps,
        step_name="Create resource group",
        detail=step_detail(f"for '{resource_group}' in '{location}'.", rg_create_args),
        fn=lambda: run_az_operator(rg_create_args, check=True, capture_output=True),
    )

    app_id = ""
    sp_object_id = ""
    client_secret = ""
    sbx_paths = resolve_sandbox_paths(paths, sandbox_name)
    state: dict[str, Any] | None = None
    try:
        create_sp_args = [
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
        create_payload: dict[str, Any] = {}

        def create_runtime_sp() -> None:
            nonlocal app_id, tenant_id, create_payload
            create_payload = az_json_operator(create_sp_args)
            app_id = str(create_payload.get("appId", "")).strip()
            initial_client_secret = str(create_payload.get("password", "")).strip()
            tenant_from_create = str(create_payload.get("tenant", "")).strip()
            if not app_id or not initial_client_secret:
                raise CliError(
                    "Unexpected output from 'az ad sp create-for-rbac': missing appId/password. "
                    "No local state was written."
                )
            if tenant_from_create:
                tenant_id = tenant_from_create

        run_with_progress(
            reporter=reporter,
            index=2,
            total=total_steps,
            step_name="Create runtime service principal",
            detail=step_detail(f"named '{sp_name}'.", create_sp_args),
            fn=create_runtime_sp,
        )

        sp_show_args = ["ad", "sp", "show", "--id", app_id, "--query", "id", "--output", "tsv"]

        def resolve_sp_object_id() -> None:
            nonlocal sp_object_id
            sp_object_id = az_tsv_operator(sp_show_args)
            if not sp_object_id:
                raise CliError("Failed to resolve runtime service principal object id after creation.")

        run_with_progress(
            reporter=reporter,
            index=3,
            total=total_steps,
            step_name="Resolve runtime principal object id",
            detail=step_detail("", sp_show_args),
            fn=resolve_sp_object_id,
        )

        # Harden credential readiness by minting a fresh secret and using it for runtime auth.
        def rotate_runtime_secret() -> None:
            nonlocal tenant_id, client_secret
            rotated_secret, tenant_from_reset = reset_service_principal_secret(app_id, append=False)
            if tenant_from_reset:
                tenant_id = tenant_from_reset
            client_secret = rotated_secret

        run_with_progress(
            reporter=reporter,
            index=4,
            total=total_steps,
            step_name="Reset runtime credential",
            detail=step_detail(f"for app '{app_id}'."),
            fn=rotate_runtime_secret,
        )

        ensure_directory(sbx_paths.root, 0o700)
        ensure_directory(sbx_paths.azure_config_dir, 0o700)

        state_now = now_utc_iso()
        state = {
            "version": STATE_VERSION,
            "workspace_path": str(paths.workspace),
            "workspace_id": workspace_id,
            "sandbox_name": sandbox_name,
            "subscription_id": subscription_id,
            "tenant_id": tenant_id,
            "resource_group_name": resource_group,
            "resource_group_scope": scope,
            "location": location,
            "service_principal_app_id": app_id,
            "service_principal_object_id": sp_object_id,
            "service_principal_display_name": sp_name,
            "service_principal_client_secret": client_secret,
            "ttl_duration_seconds": ttl_seconds,
            "expires_at_utc": expires_iso,
            "last_touched_at_utc": touched_iso,
            "automation_account_name": "",
            "automation_account_id": "",
            "automation_identity_principal_id": "",
            "automation_runbook_name": RUNBOOK_NAME,
            "automation_schedule_names": [],
            "automation_job_schedule_ids": [],
            "budget_enabled": False,
            "budget_usd": None,
            "budget_threshold_percent": BUDGET_THRESHOLD_PERCENT,
            "budget_name": "",
            "budget_resource_id": "",
            "budget_action_group_name": "",
            "budget_action_group_id": "",
            "budget_webhook_name": "",
            "budget_webhook_resource_id": "",
            "created_at_utc": state_now,
            "updated_at_utc": state_now,
        }

        run_with_progress(
            reporter=reporter,
            index=5,
            total=total_steps,
            step_name="Wait for runtime identity readiness",
            detail=step_detail(
                f"(timeout: {READINESS_MAX_WAIT_SECONDS}s).",
            ),
            fn=lambda: wait_for_runtime_identity_readiness(
                state,
                sbx_paths,
                reporter=reporter,
                step_name="runtime identity readiness",
            ),
        )

        automation_meta = run_with_progress(
            reporter=reporter,
            index=6,
            total=total_steps,
            step_name="Configure cleanup automation",
            detail=step_detail("for autonomous expiry cleanup."),
            fn=lambda: ensure_cleanup_automation(
                subscription_id=subscription_id,
                resource_group=resource_group,
                location=location,
                resource_group_scope=scope,
                workspace_id=workspace_id,
                sandbox_name=sandbox_name,
                workspace_digest=ws_digest,
            ),
        )
        state.update(automation_meta)

        if budget_usd is not None:
            budget_meta = run_with_progress(
                reporter=reporter,
                index=7,
                total=total_steps,
                step_name="Configure budget auto-destroy",
                detail=step_detail(f"(USD {budget_usd:.2f}, threshold {BUDGET_THRESHOLD_PERCENT}%)."),
                fn=lambda: ensure_budget_stack(
                    state,
                    amount_usd=budget_usd,
                    azure_config_dir=None,
                ),
            )
            state.update(budget_meta)
        else:
            reporter.step_skip(
                index=7,
                total=total_steps,
                name="Configure budget auto-destroy",
                detail="not requested",
            )

        def persist_local_state() -> None:
            state["updated_at_utc"] = now_utc_iso()
            write_state(sbx_paths, state)
            fleet["sandboxes"][sandbox_name] = fleet_summary_from_state(sbx_paths, state)
            fleet["active_sandbox"] = sandbox_name
            write_fleet(paths, fleet)
            ensure_gitignore_line(paths)

        run_with_progress(
            reporter=reporter,
            index=8,
            total=total_steps,
            step_name="Persist local sandbox state",
            detail=step_detail("to workspace runtime files."),
            fn=persist_local_state,
            emit_heartbeat=False,
        )
    except (CliError, CommandError) as exc:
        reporter.error("Create failed; starting rollback.")
        rollback_partial_sandbox_create(
            sbx_paths=sbx_paths,
            subscription_id=subscription_id,
            resource_group=resource_group,
            app_id=app_id,
            object_id=sp_object_id,
            scope=scope,
            reporter=reporter,
        )
        reporter.error("Rollback completed.")
        if isinstance(exc, CliError):
            raise CliError(str(exc)) from exc
        raise

    assert state is not None

    payload = make_group_payload(
        state,
        active=True,
        state_file=str(sbx_paths.state_file),
    )
    payload["sandbox"]["status"] = "created"
    payload["sandbox"]["workspace"] = str(paths.workspace)
    payload["sandbox"]["ttlSeconds"] = ttl_seconds
    payload["sandbox"]["ttl"] = ttl_seconds_to_human(ttl_seconds)
    payload["sandbox"]["tenantId"] = tenant_id

    emit_intercept_output(payload, output=output_name, query=args.query)

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    paths = resolve_workspace_paths()
    output_name = normalize_output_name(args.output, json_alias=args.json)
    fleet = load_fleet(paths, required=True)
    ensure_sandboxes_exist(paths, fleet)

    groups: list[dict[str, Any]] = []
    for name in sorted(fleet["sandboxes"].keys()):
        summary = fleet["sandboxes"].get(name, {})
        try:
            state = load_state(paths, name)
            if args.subscription and str(state.get("subscription_id", "")).lower() != args.subscription.lower():
                continue
            tags = tags_for_state(state)
            if not tag_filter_matches(args.tag, tags):
                continue
            groups.append(
                make_group_payload(
                    state,
                    active=fleet.get("active_sandbox") == name,
                    state_file=str(resolve_sandbox_paths(paths, name).state_file),
                )
            )
        except CliError as exc:
            degraded = make_degraded_group_payload(
                sandbox_name=name,
                summary=summary if isinstance(summary, dict) else {},
                active=fleet.get("active_sandbox") == name,
                error=str(exc),
            )
            degraded_tags = degraded.get("tags", {})
            if not isinstance(degraded_tags, dict):
                degraded_tags = {}
            if not tag_filter_matches(args.tag, {str(k): str(v) for k, v in degraded_tags.items()}):
                continue
            groups.append(degraded)

    emit_intercept_output(groups, output=output_name, query=args.query)

    return 0


def cmd_group_show(args: argparse.Namespace) -> int:
    paths = resolve_workspace_paths()
    ensure_runtime_network_enabled(paths, az_args=["group", "show"])
    output_name = normalize_output_name(args.output, json_alias=args.json)
    fleet = load_fleet(paths, required=True)
    ensure_sandboxes_exist(paths, fleet)

    if args.name:
        target_name = resolve_key_by_name_or_resource_group(fleet, args.name)
        should_persist_active = False
    else:
        target_name, should_persist_active = resolve_target_sandbox_name(
            fleet,
            explicit_name=None,
        )

    if should_persist_active:
        fleet["active_sandbox"] = target_name
        write_fleet(paths, fleet)

    state = load_state(paths, target_name)
    if args.subscription and state["subscription_id"].lower() != args.subscription.lower():
        raise CliError(
            f"Resource group '{state['resource_group_name']}' was not found in subscription '{args.subscription}'."
        )
    sbx_paths = resolve_sandbox_paths(paths, target_name)
    ensure_sandbox_cli_defaults(
        azure_config_dir=sbx_paths.azure_config_dir,
        resource_group=state["resource_group_name"],
        location=state["location"],
    )
    report = check_health_quick(paths, fleet, target_name, state, allow_relogin=True)
    touch_sandbox_expiration(
        paths,
        fleet,
        sbx_paths,
        state,
        strict_tag_update=False,
        azure_config_dir_for_tag=sbx_paths.azure_config_dir,
    )

    payload = make_group_payload(
        state,
        active=fleet.get("active_sandbox") == target_name,
        include_health=True,
        health_report=report,
        state_file=str(sbx_paths.state_file),
    )
    emit_intercept_output(payload, output=output_name, query=args.query)

    return 0 if report["healthy"] else 1


def cmd_group_delete(args: argparse.Namespace) -> int:
    paths = resolve_workspace_paths()
    output_name = normalize_output_name(args.output, json_alias=args.json)
    reporter = ProgressReporter(
        enabled=not bool(getattr(args, "only_show_errors", False)),
        verbose=bool(getattr(args, "verbose", False)),
        debug=bool(getattr(args, "debug", False)),
    )
    fleet = load_fleet(paths, required=True)
    ensure_sandboxes_exist(paths, fleet)

    target_key = resolve_key_by_name_or_resource_group(fleet, args.name)
    state = load_state(paths, target_key)
    if args.subscription and state["subscription_id"].lower() != args.subscription.lower():
        raise CliError(
            f"Resource group '{state['resource_group_name']}' was not found in subscription '{args.subscription}'."
        )

    result = destroy_single_sandbox(
        paths=paths,
        fleet=fleet,
        sandbox_name=target_key,
        no_wait=bool(args.no_wait),
        force_deletion_types=args.force_deletion_types,
        reporter=reporter,
    )

    payload = {
        "id": state["resource_group_scope"],
        "name": state["resource_group_name"],
        "type": "Microsoft.Resources/resourceGroups",
        "properties": {
            "provisioningState": "Deleting"
            if args.no_wait
            else ("Deleted" if result["healthy"] else "DeleteFailed")
        },
        "sandbox": {
            "name": target_key,
            "deleted": result["healthy"],
            "operations": result["operations"],
            "remainingSandboxes": sorted(fleet["sandboxes"].keys()),
            "activeSandbox": fleet.get("active_sandbox"),
        },
    }

    emit_intercept_output(payload, output=output_name, query=args.query)

    return 0 if result["healthy"] else 1


def cmd_group_exists(args: argparse.Namespace) -> int:
    paths = resolve_workspace_paths()
    ensure_runtime_network_enabled(paths, az_args=["group", "exists", "--name", args.name])
    output_name = normalize_output_name(args.output, json_alias=args.json)
    fleet = load_fleet(paths, required=False)
    if not fleet["sandboxes"]:
        emit_intercept_output(False, output=output_name, query=args.query)
        return 0

    target_key = resolve_key_by_resource_group(fleet, args.name)
    if target_key is None:
        emit_intercept_output(False, output=output_name, query=args.query)
        return 0

    state = load_state(paths, target_key)
    if args.subscription and state["subscription_id"].lower() != args.subscription.lower():
        emit_intercept_output(False, output=output_name, query=args.query)
        return 0

    sbx_paths = resolve_sandbox_paths(paths, target_key)
    ensure_sandbox_login_with_secret_recovery(
        state,
        sbx_paths,
        allow_operator_recovery=False,
    )
    exists_raw = az_tsv_runtime(
        [
            "group",
            "exists",
            "--name",
            state["resource_group_name"],
            "--subscription",
            state["subscription_id"],
            "--output",
            "tsv",
        ],
        sbx_paths=sbx_paths,
    )
    exists = exists_raw.strip().lower() == "true"
    emit_intercept_output(exists, output=output_name, query=args.query)
    return 0


def cmd_passthrough(az_args: list[str], *, explicit_sandbox: str | None) -> int:
    if not az_args:
        raise CliError(f"Usage: {sandbox_az_command('<azure-cli-args...>')}")

    paths = resolve_workspace_paths()
    ensure_runtime_network_enabled(paths, az_args=az_args)
    fleet = load_fleet(paths, required=False)
    target_name, persist_active = resolve_passthrough_target_sandbox(
        paths=paths,
        fleet=fleet,
        az_args=az_args,
        explicit_name=explicit_sandbox,
    )
    if persist_active:
        fleet["active_sandbox"] = target_name
        write_fleet(paths, fleet)

    state = load_state(paths, target_name)
    sbx_paths = resolve_sandbox_paths(paths, target_name)

    enforce_guardrails(az_args, state)
    ensure_sandbox_login_with_secret_recovery(
        state,
        sbx_paths,
        allow_operator_recovery=False,
    )

    # Keep local TTL refresh fast; push the RG tag as a best-effort follow-up.
    touch_sandbox_expiration(
        paths,
        fleet,
        sbx_paths,
        state,
        strict_tag_update=False,
        azure_config_dir_for_tag=sbx_paths.azure_config_dir,
        update_cloud_tag=False,
    )

    env = az_env(sbx_paths.azure_config_dir)
    result = subprocess.run(["az", *az_args], env=env)

    try:
        apply_expiration_tag(
            state,
            azure_config_dir=sbx_paths.azure_config_dir,
            strict=False,
        )
    except (CliError, CommandError):
        pass

    return result.returncode


def legacy_verb_guidance(verb: str) -> str:
    mapping = {
        "create": f"Use '{sandbox_az_command('group create --location <location>')}'.",
        "list": f"Use '{sandbox_az_command('group list')}'.",
        "status": (
            f"Use '{sandbox_az_command('group show --name <rg>')}' or "
            f"'{sandbox_az_command('group list')}'."
        ),
        "use": (
            "Use '-g <sandbox-rg>' on your az command, or "
            f"'{sandbox_az_command('--sandbox <name> <az-args>')}'."
        ),
        "update": (
            f"Use '{sandbox_az_command('group create --name <rg> --location <location> --recreate [--expires-in <duration>] [--budget-usd <amount>]')}'."
        ),
        "destroy": f"Use '{sandbox_az_command('group delete --name <rg> --yes')}'.",
    }
    return mapping.get(verb, f"Use '{sandbox_az_command('group list')}' to discover sandbox commands.")


def cmd_az(args: argparse.Namespace) -> int:
    if not args.az_args:
        raise CliError(f"Usage: {sandbox_az_command('<args>')}")

    az_args = list(args.az_args)
    leading_globals, remainder = strip_leading_az_global_args(az_args)
    dispatch_args = remainder or az_args

    first = dispatch_args[0]
    if first in {"create", "list", "status", "use", "update", "destroy"}:
        raise CliError(legacy_verb_guidance(first))

    if first == "group":
        if len(dispatch_args) < 2:
            raise CliError(
                f"Usage: {sandbox_az_command('group <create|list|show|delete|exists> [args...]')}"
            )
        action = dispatch_args[1]
        group_args = [*leading_globals, *dispatch_args[2:]]
        if action == "create":
            return cmd_create(parse_create_args(group_args))
        if action == "list":
            return cmd_list(parse_list_args(group_args))
        if action == "show":
            return cmd_group_show(parse_group_show_args(group_args))
        if action == "delete":
            return cmd_group_delete(parse_group_delete_args(group_args))
        if action == "exists":
            return cmd_group_exists(parse_group_exists_args(group_args))

    explicit_sandbox, passthrough_args = parse_passthrough_target(az_args)
    if not passthrough_args:
        raise CliError(f"Usage: {sandbox_az_command('<azure-cli-args...>')}")

    return cmd_passthrough(passthrough_args, explicit_sandbox=explicit_sandbox)


def help_text() -> str:
    cmd = sandbox_az_command()
    return "\n".join(
        [
            "Workspace-scoped Azure sandbox fleet tool.",
            "",
            "Usage:",
            f"  {cmd} group create --location <location> [--name <rg-name>]",
            f"  {cmd} group list",
            f"  {cmd} group show [--name <rg-name>]",
            f"  {cmd} group exists --name <rg-name>",
            f"  {cmd} group delete --name <rg-name> --yes",
            f"  {cmd} <any az command...>",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv or argv[0] in {"-h", "--help", "help"}:
            print(help_text())
            return 0

        if argv[0] == "az":
            raise CliError(
                "Legacy syntax is no longer supported. "
                f"Use '{sandbox_az_command('<azure-cli-args...>')}' (without the extra 'az')."
            )

        top_level_map = {
            "init": f"Use '{sandbox_az_command('group create --location <location>')}'.",
            "create": legacy_verb_guidance("create"),
            "list": legacy_verb_guidance("list"),
            "status": legacy_verb_guidance("status"),
            "use": legacy_verb_guidance("use"),
            "update": legacy_verb_guidance("update"),
            "destroy": legacy_verb_guidance("destroy"),
        }
        if argv[0] in top_level_map:
            raise CliError(top_level_map[argv[0]])

        return cmd_az(argparse.Namespace(az_args=argv))
    except CliError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except CommandError as exc:
        cmd_text = redact_command_for_logs(exc.cmd)
        details = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        print(f"ERROR: Command failed: {cmd_text}\n{details}", file=sys.stderr)
        return exc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
