import pytest

from ciphersweet import (
    BoringCrypto,
    CipherSweet,
    CipherSweetException,
    CryptoOperationException,
    EncryptedField,
    EncryptedRow,
    EnvProvider,
    FileProvider,
    FIPSCrypto,
    KeyProviderException,
    ModernCrypto,
    MultiTenantProvider,
    RandomProvider,
    StringProvider,
)
from ciphersweet._util import b64url_encode

RAW = bytes(range(32))


def test_string_provider_encodings():
    for value in (RAW, RAW.hex(), RAW.hex().upper(), b64url_encode(RAW)):
        assert StringProvider(value).get_symmetric_key().get_raw_key() == RAW
    with pytest.raises(CryptoOperationException):
        StringProvider("abc")
    assert "00" not in repr(StringProvider(RAW))


def test_env_provider(monkeypatch):
    monkeypatch.setenv("MY_KEY", RAW.hex())
    assert EnvProvider("MY_KEY").get_symmetric_key().get_raw_key() == RAW
    monkeypatch.delenv("MY_KEY")
    with pytest.raises(KeyProviderException):
        EnvProvider("MY_KEY").get_symmetric_key()


def test_file_provider(tmp_path):
    raw = tmp_path / "raw.key"
    raw.write_bytes(RAW)
    assert FileProvider(raw).get_symmetric_key().get_raw_key() == RAW
    hexfile = tmp_path / "hex.key"
    hexfile.write_text(RAW.hex() + "\n")
    assert FileProvider(hexfile, encoding="auto").get_symmetric_key().get_raw_key() == RAW
    with pytest.raises(KeyProviderException):
        FileProvider(tmp_path / "missing").get_symmetric_key()


def test_default_backend_is_boring():
    assert isinstance(CipherSweet(RandomProvider()).get_backend(), BoringCrypto)


def test_keys_are_domain_separated():
    engine = CipherSweet(StringProvider(RAW), ModernCrypto())
    keys = {
        engine.get_field_symmetric_key("t", "a").get_raw_key(),
        engine.get_field_symmetric_key("t", "b").get_raw_key(),
        engine.get_field_symmetric_key("u", "a").get_raw_key(),
        engine.get_blind_index_root_key("t", "a").get_raw_key(),
    }
    assert len(keys) == 4


class TenantFromRow(MultiTenantProvider):
    def get_tenant_from_row(self, row, table_name):
        return row["tenant"]

    def inject_tenant_metadata(self, row, table_name):
        row = dict(row)
        row["tenant"] = self.active
        return row


@pytest.mark.parametrize("backend", [FIPSCrypto, BoringCrypto])
def test_multi_tenant(backend):
    provider = TenantFromRow({"a": RandomProvider(), "b": RandomProvider()}, "a")
    engine = CipherSweet(provider, backend())
    assert engine.is_multi_tenant_supported()
    row = EncryptedRow(engine, "t").add_text_field("secret")
    enc_a = row.encrypt_row({"secret": "for a"})
    assert enc_a["tenant"] == "a"
    engine.set_active_tenant("b")
    enc_b = row.encrypt_row({"secret": "for b"})
    assert row.decrypt_row(enc_a)["secret"] == "for a"
    assert row.decrypt_row(enc_b)["secret"] == "for b"


def test_multi_tenant_not_supported_by_modern():
    provider = MultiTenantProvider({"a": RandomProvider()}, "a")
    assert not CipherSweet(provider, ModernCrypto()).is_multi_tenant_supported()
    with pytest.raises(CipherSweetException):
        EncryptedField(CipherSweet(RandomProvider(), FIPSCrypto()), "t", "f").set_active_tenant("a")
