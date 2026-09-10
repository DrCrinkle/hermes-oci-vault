from types import SimpleNamespace

from plugins.oci_vault.source import OciVaultSource

import pytest

from tests.secret_sources.conformance import SecretSourceConformance


class TestOciVaultConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return OciVaultSource()


def test_instance_principal_fetch_decodes_base64_and_selects_json(monkeypatch, tmp_path):
    import sys

    class FakeSigner:
        pass

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.base_client = SimpleNamespace(set_region=lambda value: None)

        def get_secret_bundle(self, *, secret_id, stage):
            import base64

            assert secret_id.startswith("ocid1.secret.")
            assert stage == "CURRENT"
            encoded = base64.b64encode(b'{"apiKey":"fixture-secret"}').decode()
            return SimpleNamespace(data=SimpleNamespace(secret_bundle_content=SimpleNamespace(content=encoded)))

    fake_oci = SimpleNamespace(
        auth=SimpleNamespace(signers=SimpleNamespace(InstancePrincipalsSecurityTokenSigner=FakeSigner)),
        secrets=SimpleNamespace(SecretsClient=FakeClient),
    )
    monkeypatch.setitem(sys.modules, "oci", fake_oci)
    result = OciVaultSource().fetch({
        "enabled": True,
        "auth": "instance_principal",
        "env": {"OPENAI_API_KEY": "ocid1.secret.oc1.phx.fixture#apiKey"},
    }, tmp_path)
    assert result.error is None
    assert result.secrets == {"OPENAI_API_KEY": "fixture-secret"}
