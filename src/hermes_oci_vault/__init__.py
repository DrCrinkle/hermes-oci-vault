"""OCI Vault SecretSource plugin for Hermes."""

from .source import OciVaultSource


def register(ctx) -> None:
    ctx.register_secret_source(OciVaultSource())
