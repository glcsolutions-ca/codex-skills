"""Authentication and subscription-binding facade."""

from __future__ import annotations

from .commands import (
    ensure_runtime_subscription_binding,
    ensure_sandbox_login,
    ensure_sandbox_login_with_secret_recovery,
    reset_service_principal_secret,
)

__all__ = [
    "ensure_runtime_subscription_binding",
    "ensure_sandbox_login",
    "ensure_sandbox_login_with_secret_recovery",
    "reset_service_principal_secret",
]
