---
name: azure-rg-sandbox
description: Create, use, audit, and tear down a per-workspace Azure CLI sandbox bound to one dedicated resource group and one service principal with Owner only at that scope. Use when Codex needs safe, repeatable Azure operations with reduced blast radius, including sandbox setup (`sandbox init`), scoped command execution (`sandbox az ...`), health/drift checks (`sandbox status`), and cleanup or re-creation (`sandbox destroy`, `sandbox init --recreate`).
---

# Azure RG Sandbox

## Overview

Use this skill to create a strict Azure boundary per workspace and run Azure CLI commands inside it.
The boundary is one resource group plus one service principal that has `Owner` only on that resource group.

## Prerequisites

- Install Azure CLI (`az`) and authenticate your human operator context (`az login`).
- Ensure the operator identity can create resource groups, create service principals, and assign RBAC roles.
- Run commands from the workspace root that should own the sandbox boundary.

## Quick Start

1. Initialize sandbox boundary:
   - `./skills/.experimental/azure-rg-sandbox/scripts/sandbox init --location canadacentral`
2. Run scoped Azure commands:
   - `./skills/.experimental/azure-rg-sandbox/scripts/sandbox az group show -g <sandbox-rg>`
3. Check health and drift:
   - `./skills/.experimental/azure-rg-sandbox/scripts/sandbox status --json`
4. Destroy boundary when done:
   - `./skills/.experimental/azure-rg-sandbox/scripts/sandbox destroy --yes`

## Permission Bootstrap (Codex Runtime)

- If Codex is running in a sandboxed mode that requires approval for networked commands, bootstrap one persistent rule before normal use.
- Before bootstrap, check the current approved prefix list from the runtime permissions context.
- If the prefix is not already approved, run a harmless scoped command first (`sandbox az account show -o none`) and request escalated execution with prefix rule:
  - `["<absolute-path-to-sandbox-script>", "az"]`
- Use the absolute script path inside the installed skill directory (for example, `$CODEX_HOME/skills/azure-rg-sandbox/scripts/sandbox`).
- In the approval UI, select the persistent approval option so future `sandbox az ...` commands do not prompt again.
- Until the prefix is confirmed as approved, keep including the same `prefix_rule` on escalated `sandbox az ...` requests.
- After the prefix is approved, run `sandbox az ...` without forcing explicit escalation metadata.
- Do not bypass this skill by switching to raw `az` commands just to avoid approval prompts.

## Command Contract

- `sandbox init --location <azure-location> [--subscription <id>] [--resource-group <name>] [--recreate] [--json]`
  - Create or validate boundary objects.
  - Require `--location`.
  - Reuse healthy existing state unless `--recreate` is passed.
- `sandbox az <azure-cli-args...>`
  - Enforce scope guardrails, then pass through to `az` using sandbox auth.
- `sandbox status [--json]`
  - Validate state, resource existence, RBAC scope, sandbox auth, and `.gitignore` protection.
- `sandbox destroy --yes [--json]`
  - Delete resource group, role assignment, service principal/application, and local sandbox state.

## Guardrails

- Reject `--subscription` that does not match bound subscription.
- Reject `-g/--resource-group` that does not match bound sandbox resource group.
- Reject `--ids` and `--scope`/`--scopes` values outside the sandbox resource group scope.
- Use dedicated `AZURE_CONFIG_DIR` at `.codex/azure-rg-sandbox/azure-config`.

## Local State and Security

- Persist state at `.codex/azure-rg-sandbox/state.json`.
- Persist service principal secret in that state file by design.
- Enforce local file permissions (`0700` sandbox dir, `0600` state file).
- Ensure `.gitignore` includes `.codex/azure-rg-sandbox/` to reduce accidental commit risk.

## Resources

- `scripts/azure_rg_sandbox.py`: lifecycle and guardrail implementation.
- `scripts/sandbox`: executable wrapper.
- `references/state-and-health.md`: state schema and health check details.

## Operational Notes

- If `status` reports drift or missing bindings, run `init --recreate`.
- Keep one subscription binding per workspace.
- Do not share state files between workspaces.
- In restricted runtimes, `sandbox init`, `sandbox status`, and `sandbox destroy` may still require approval unless separately approved by policy.
