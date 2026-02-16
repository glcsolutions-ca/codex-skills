# Azure RG Sandbox v4 State and Health

## Runtime Layout

All runtime files are workspace-local:
- State: `.sandbox/azure/state.json`
- Azure CLI config/cache: `.sandbox/azure/config`
- Workspace entrypoint: `.sandbox/azure/sandbox`
- Workspace `az` shim: `.sandbox/azure/az`

The script sets:
- `AZURE_CONFIG_DIR=<workspace>/.sandbox/azure/config`

## Command Surface

- `sandbox az init --location <azure-location> [--subscription <id>] [--resource-group <name>] [--recreate] [--json]`
- `sandbox az status [--json]`
- `sandbox az destroy --yes [--json]`
- `sandbox az <azure-cli-args...>`
- `sandbox az -- <azure-cli-args...>` (forced passthrough)

Top-level aliases are intentionally unsupported:
- `sandbox init|status|destroy` fails with guidance to use `sandbox az ...`.

## Missing Init Behavior

`sandbox az <args>` never auto-initializes.
If `.sandbox/azure/state.json` is missing or invalid, it fails non-zero and tells you to run:
- `sandbox az init --location <location>`

## Guardrails

The passthrough path enforces:
1. `--subscription` must match the bound subscription.
2. `-g/--resource-group` must match the bound resource group.
3. `--ids` entries must start with the bound RG scope.
4. `--scope` and `--scopes` must remain within the bound RG scope.

## Health Checks (`sandbox az status`)

1. State schema and workspace binding.
2. Resource group existence.
3. Service principal existence.
4. Owner role assignment at exact RG scope.
5. Drift: no SP role assignments outside RG scope.
6. Sandbox auth validity in workspace `AZURE_CONFIG_DIR`.
7. `.gitignore` protection entry for `.sandbox/azure/`.

## Workspace-Only Network Auto-Configure

When Codex sandbox networking is disabled (`CODEX_SANDBOX_NETWORK_DISABLED` is set):
1. The script updates only `<workspace>/.codex/config.toml`.
2. It ensures:

```toml
[sandbox_workspace_write]
network_access = true
```

3. It exits non-zero with a clear restart-and-retry message.
4. It never edits `~/.codex/config.toml`.

## Git Ignore Protection

`init` ensures this workspace entry exists:
- `.sandbox/azure/`
