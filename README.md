# Hermes OCI Vault Secret Source

A standalone Hermes Agent secret-source plugin for Oracle Cloud Infrastructure Vault.
It uses the OCI Python SDK directly, so the OCI CLI is not required.

On OCI Compute, the default `instance_principal` mode uses the instance's dynamic-group identity. Grant that dynamic group permission to read the required secrets. Outside OCI, set `auth: api_key` and use the standard OCI config file/profile.

Configure in Hermes:

```yaml
secrets:
  oci_vault:
    enabled: true
    auth: instance_principal
    env:
      OPENAI_API_KEY: ocid1.secret.oc1.phx...#apiKey
```

Install from GitHub with `hermes plugins install DrCrinkle/hermes-oci-vault`, or copy this directory to `$HERMES_HOME/plugins/oci_vault`. The OCI SDK must be installed in the Hermes environment (`uv pip install oci==2.181.1`).

Secret references are OCI secret OCIDs, optionally followed by `#field.path` for JSON payloads. Fetch failures are fail-open and reported through Hermes' normal secret-source diagnostics.
