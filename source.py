"""Resolve Hermes secret bindings from OCI Vault with the OCI Python SDK.

Configuration::

    secrets:
      oci_vault:
        enabled: true
        auth: instance_principal
        env:
          OPENAI_API_KEY: ocid1.secret.oc1.phx...

On OCI Compute, Instance Principals require only a dynamic group and an IAM policy;
the OCI CLI and a config file are not needed. ``api_key`` reads the standard OCI
config file. Secret OCIDs may end in ``#json.path`` to select a string field.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Dict, Optional, Tuple

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource, get_source_environment, is_valid_env_name

_OCID = re.compile(r"^ocid1\.secret\.oc[0-9a-z.-]+\.[A-Za-z0-9._:/+-]+(?:#[A-Za-z][A-Za-z0-9_.-]*)?$")
_DEFAULT_TIMEOUT = 30.0


def _parse_ref(raw: object) -> Tuple[str, Optional[str]]:
    if not isinstance(raw, str) or not _OCID.fullmatch(raw.strip()):
        raise ValueError("reference must be an OCI secret OCID, optionally followed by #json.path")
    secret_id, _, selector = raw.strip().partition("#")
    return secret_id, selector or None


def _select(value: str, selector: Optional[str]) -> str:
    if not selector:
        return value
    current = json.loads(value)
    for part in selector.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"OCI secret JSON does not contain field #{selector}")
        current = current[part]
    if not isinstance(current, str):
        raise ValueError(f"OCI secret field #{selector} must be a string")
    return current


def _client(cfg: dict):
    source_env = get_source_environment()
    try:
        import oci
    except ImportError as exc:
        raise RuntimeError("OCI Python SDK is not installed; install the Hermes OCI Vault plugin extra") from exc
    auth = str(cfg.get("auth") or "instance_principal").strip().lower()
    if auth == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        client = oci.secrets.SecretsClient(config={}, signer=signer)
    elif auth == "api_key":
        config_file = str(cfg.get("config_file") or source_env.get("OCI_CLI_CONFIG_FILE") or "").strip() or None
        profile = str(cfg.get("profile") or source_env.get("OCI_CLI_PROFILE") or "DEFAULT").strip()
        config = oci.config.from_file(file_location=config_file, profile_name=profile)
        client = oci.secrets.SecretsClient(config)
    else:
        raise ValueError("auth must be instance_principal or api_key; OCI CLI-only auth modes are not supported")
    region = str(cfg.get("region") or source_env.get("OCI_CLI_REGION") or "").strip()
    if region:
        client.base_client.set_region(region)
    return client


class OciVaultSource(SecretSource):
    name = "oci_vault"
    label = "OCI Vault"
    shape = "mapped"
    scheme = "ocivault"
    override_existing_default = True
    remediation_hints = {
        ErrorKind.AUTH_FAILED: "Check the OCI dynamic-group policy or API-key profile used by secrets.oci_vault.",
        ErrorKind.NETWORK: "Check OCI service-network access and the configured region.",
        ErrorKind.BINARY_MISSING: "Install the OCI Vault plugin extra with `uv sync --extra oci-vault`.",
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "auth": {"description": "instance_principal or api_key", "default": "instance_principal"},
            "env": {"description": "Environment variable names mapped to OCI secret OCIDs", "default": {}},
            "region": {"description": "Optional OCI region override", "default": ""},
            "config_file": {"description": "OCI API-key config file path", "default": ""},
            "profile": {"description": "OCI API-key profile", "default": "DEFAULT"},
            "timeout_seconds": {"description": "Fetch timeout", "default": _DEFAULT_TIMEOUT},
            "override_existing": {"description": "Replace existing environment values", "default": True},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        result = FetchResult()
        refs = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        valid: Dict[str, Tuple[str, Optional[str]]] = {}
        for name, raw in refs.items():
            if not is_valid_env_name(name):
                result.warnings.append(f"Skipping invalid environment variable name {name!r}")
                continue
            try:
                valid[name] = _parse_ref(raw)
            except ValueError as exc:
                result.warnings.append(f"Skipping {name}: {exc}")
        if not valid:
            return result
        try:
            client = _client(cfg)
            for name, (secret_id, selector) in valid.items():
                response = client.get_secret_bundle(secret_id=secret_id, stage="CURRENT")
                content = response.data.secret_bundle_content.content
                if not content:
                    raise ValueError(f"empty OCI secret bundle for {name}")
                value = _select(base64.b64decode(content).decode("utf-8"), selector)
                if not value:
                    raise ValueError(f"empty OCI secret value for {name}")
                result.secrets[name] = value
        except PermissionError as exc:
            return result.fail(f"OCI Vault authentication or permission failure: {type(exc).__name__}", ErrorKind.AUTH_FAILED)
        except TimeoutError:
            return result.fail("OCI Vault request timed out", ErrorKind.TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — startup secret sources never raise
            text = str(exc).lower()
            status = getattr(exc, "status", None)
            if status in (401, 403):
                kind = ErrorKind.AUTH_FAILED
            elif status == 404:
                kind = ErrorKind.REF_INVALID
            elif status == 429 or (isinstance(status, int) and status >= 500):
                kind = ErrorKind.NETWORK
            elif any(token in text for token in ("timeout", "connection", "network", "dns")):
                kind = ErrorKind.NETWORK
            else:
                kind = ErrorKind.INTERNAL
            return result.fail(f"OCI Vault fetch failed: {type(exc).__name__}", kind)
        return result
