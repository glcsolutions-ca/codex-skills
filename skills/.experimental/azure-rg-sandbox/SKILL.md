---
name: azure-rg-sandbox
description: Use this skill for safe Azure CLI work scoped to one workspace sandbox resource group. Use `sandbox az ...` for all operations.
---

Use `sandbox az ...` for Azure operations in this workspace.

If the sandbox is not initialized, run once:
- `sandbox az init --location <azure-location>`

Commands:
- `sandbox az init --location <azure-location> [--subscription <id>] [--resource-group <name>] [--recreate] [--json]`
- `sandbox az status [--json]`
- `sandbox az destroy --yes [--json]`
- `sandbox az <azure-cli-args...>`
- `sandbox az -- <azure-cli-args...>`

Runtime files are workspace-local under `.sandbox/azure/`.
