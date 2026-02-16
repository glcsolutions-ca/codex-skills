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
