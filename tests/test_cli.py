import io
import os
import subprocess
import sys

import pytest

from ciphersweet import BlindIndex, CipherSweet, EncryptedField, Lowercase, StringProvider
from ciphersweet.cli import main
from ciphersweet.laravel import backend_from_name
from conftest import load_vectors

VEC = load_vectors("php_interop.json")
KEY = VEC["key"]
NEW_KEY = "11" * 32
FIELD = ["--table", "contacts", "--column", "email"]


def run(argv, stdin=b""):
    out, err = io.BytesIO(), io.StringIO()
    code = main(argv, stdin=io.BytesIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("CIPHERSWEET_KEY", "CIPHERSWEET_OLD_KEY", "CIPHERSWEET_BACKEND"):
        monkeypatch.delenv(var, raising=False)


def field(backend="nacl", key=KEY):
    return EncryptedField(CipherSweet(StringProvider(key), backend_from_name(backend)), "contacts", "email")


def test_generate_key_hex_and_base64():
    code, out, _ = run(["generate-key"])
    assert code == 0
    assert len(out.strip()) == 64
    bytes.fromhex(out.strip().decode())
    code, out, _ = run(["generate-key", "--base64"])
    assert code == 0 and len(out.strip()) == 44
    StringProvider(out.strip().decode())


@pytest.mark.parametrize("backend", ["nacl", "boring", "fips"])
def test_decrypt_php_vectors_infers_backend(backend, monkeypatch):
    vec = VEC["backends"]["brng" if backend == "boring" else backend]["field"]
    monkeypatch.setenv("CIPHERSWEET_KEY", KEY)
    code, out, _ = run(["decrypt", *FIELD, vec["ct"]])
    assert code == 0
    assert out == vec["plaintext"].encode() + b"\n"
    code, out, _ = run(["decrypt", *FIELD, "--aad", vec["aad"]], stdin=vec["ct_aad"].encode() + b"\n")
    assert code == 0
    assert out == vec["plaintext"].encode() + b"\n"


@pytest.mark.parametrize("backend", ["nacl", "boring", "fips"])
def test_encrypt_roundtrip_and_library_compat(backend, tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text(KEY + "\n")
    code, out, _ = run(
        ["encrypt", *FIELD, "--backend", backend, "--key-file", str(key_file), "--aad", "7", "hi"]
    )
    assert code == 0
    ciphertext = out.strip().decode()
    assert field(backend).decrypt_value(ciphertext, "7") == "hi"
    code, out, _ = run(["decrypt", *FIELD, "--key-file", str(key_file), "--aad", "7", ciphertext])
    assert out == b"hi\n"


def test_encrypt_reads_stdin_and_strips_one_newline(monkeypatch):
    monkeypatch.setenv("MY_KEY", KEY)
    code, out, _ = run(["encrypt", *FIELD, "--key-env", "MY_KEY"], stdin=b"line one\n\n")
    assert code == 0
    assert field().decrypt_value(out.strip().decode()) == "line one\n"


def test_backend_from_env(monkeypatch):
    monkeypatch.setenv("CIPHERSWEET_KEY", KEY)
    monkeypatch.setenv("CIPHERSWEET_BACKEND", "fips")
    _, out, _ = run(["encrypt", *FIELD, "x"])
    assert out.startswith(b"fips:")


def test_blind_index_matches_php():
    vec = VEC["backends"]["nacl"]["field"]
    argv = ["blind-index", *FIELD, "--key", KEY, "--name", "email_lower", "--bits", "32", "--fast"]
    code, out, _ = run([*argv, "--transform", "lowercase", vec["plaintext"]])
    assert code == 0
    assert out == vec["indexes"]["email_lower"].encode() + b"\n"
    _, out, _ = run([*argv, "--transform", "lowercase", "--typed", vec["plaintext"]])
    assert out == f"{vec['types']['email_lower']} {vec['indexes']['email_lower']}\n".encode()
    f = field().add_blind_index(BlindIndex("email_slow", [Lowercase()], 64))
    _, out, _ = run(
        [
            "blind-index",
            *FIELD,
            "--key",
            KEY,
            "--name",
            "email_slow",
            "--bits",
            "64",
            "--transform",
            "lowercase",
        ],
        stdin=vec["plaintext"].encode(),
    )
    assert (
        out.strip().decode()
        == f.get_blind_index(vec["plaintext"], "email_slow")
        == vec["indexes"]["email_slow"]
    )


def test_rotate_key_and_backend(monkeypatch):
    monkeypatch.setenv("CIPHERSWEET_OLD_KEY", KEY)
    monkeypatch.setenv("CIPHERSWEET_KEY", NEW_KEY)
    old_nacl = field("nacl").encrypt_value("a")
    old_brng = field("boring").encrypt_value("b")
    current = field("fips", NEW_KEY).encrypt_value("c")
    stdin = "\n".join([old_nacl, "", old_brng, current]).encode() + b"\n"
    code, out, err = run(["rotate", *FIELD, "--new-backend", "fips"], stdin=stdin)
    assert code == 0, err
    lines = out.decode().split("\n")
    assert lines[-1] == ""
    lines = lines[:-1]
    assert len(lines) == 4
    assert lines[1] == ""
    assert lines[3] == current
    new = field("fips", NEW_KEY)
    assert [new.decrypt_value(lines[i]) for i in (0, 2, 3)] == ["a", "b", "c"]
    assert "rotated 2, already current 1" in err


def test_rotate_writes_nothing_on_failure(monkeypatch):
    monkeypatch.setenv("CIPHERSWEET_OLD_KEY", KEY)
    good = field().encrypt_value("a")
    bad = field(key=NEW_KEY).encrypt_value("b")  # neither old nor new key
    code, out, err = run(["rotate", *FIELD, "--new-key", "22" * 32, "-q"], stdin=f"{good}\n{bad}\n".encode())
    assert code == 1
    assert out == b""
    assert "line 2" in err


def test_wrong_key_fails_cleanly():
    ct = field().encrypt_value("a")
    code, out, err = run(["decrypt", *FIELD, "--key", NEW_KEY, ct])
    assert code == 1 and out == b""
    assert err.startswith("ciphersweet: error: decryption failed")


def test_errors():
    code, _, err = run(["encrypt", *FIELD, "x"])
    assert code == 1 and "CIPHERSWEET_KEY" in err
    code, _, err = run(["encrypt", *FIELD, "--key", "abc", "x"])
    assert code == 1 and "invalid key" in err
    code, _, err = run(["decrypt", *FIELD, "--key", KEY, "nope:abc"])
    assert code == 1 and "--backend" in err
    code, _, err = run(["encrypt", *FIELD, "--key-file", "/nonexistent/key", "x"])
    assert code == 1 and "invalid key" in err
    with pytest.raises(SystemExit) as exc:
        run(["encrypt", "x"])
    assert exc.value.code == 2


def test_python_dash_m():
    env = {**os.environ, "CIPHERSWEET_KEY": KEY}
    result = subprocess.run(
        [sys.executable, "-m", "ciphersweet", "encrypt", *FIELD, "hello"],
        capture_output=True,
        env=env,
        check=True,
    )
    assert field().decrypt_value(result.stdout.strip().decode()) == "hello"
