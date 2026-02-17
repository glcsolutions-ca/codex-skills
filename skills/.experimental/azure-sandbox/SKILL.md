---
name: azure-sandbox
description: Use when Azure work should stay inside a workspace-scoped sandbox. Run normal Azure CLI by replacing `az` with `azs`; auth and scope guardrails are automatic.
---

# Azure Sandbox

Run normal Azure CLI with a workspace-scoped boundary. For sandboxed work, run normal `az` commands with `azs` instead.
No skill installation or extra Python packages are required; the script runs directly from the skill folder.

## Quick start

```bash
AZS="${CODEX_HOME:-$HOME/.codex}/skills/azure-sandbox/scripts/azs"

"$AZS" group create --location canadacentral
"$AZS" group list -o table
"$AZS" storage account create --name sbx$RANDOM$RANDOM --resource-group <sandbox-rg> --location canadacentral --sku Standard_LRS
"$AZS" group delete --name <sandbox-rg> --yes
```

`group create` and `group delete` stream progress to `stderr` and keep final az-style output on `stdout`. Use `--only-show-errors` to keep lifecycle commands quiet.

## If network is disabled

If `azs` reports network-restricted execution, ask:
`Do you want me to enable network and retry?`

Run (from any workspace):

```bash
codex --cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)" -s workspace-write -c sandbox_workspace_write.network_access=true
```

For a global default across workspaces, set this in `~/.codex/config.toml`:

```toml
[sandbox_workspace_write]
network_access = true
```

After changing config, retry in a new or forked conversation so the new session picks it up.

## Do not

- Do not run raw `az` unless you intentionally need out-of-sandbox permissions.
