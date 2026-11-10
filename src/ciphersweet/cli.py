"""The ``ciphersweet`` command-line tool.

::

    ciphersweet generate-key
    ciphersweet encrypt  --table users --column email "alice@example.com"
    ciphersweet decrypt  --table users --column email "nacl:..."
    ciphersweet blind-index --table users --column email --name email_index --fast "alice@example.com"
    ciphersweet rotate   --table users --column email < old.txt > new.txt

The key is read from ``CIPHERSWEET_KEY`` unless ``--key-file``, ``--key-env``
or ``--key`` says otherwise, and the backend from ``--backend`` or
``CIPHERSWEET_BACKEND`` (default ``nacl``, as in Laravel). ``decrypt`` and
``rotate`` pick the backend from the ciphertext prefix when none is given.

Exit status: 0 on success, 1 when a key or ciphertext is rejected, 2 on a
usage error.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import BinaryIO, Callable, Dict, List, Optional, Sequence, TextIO

from . import __version__
from .backend import Backend
from .blind_index import BlindIndex
from .encrypted_field import EncryptedField
from .engine import CipherSweet
from .exceptions import CipherSweetException
from .key_rotation import FieldRotator
from .keyprovider import FileProvider, KeyProvider, StringProvider
from .laravel import BACKENDS, backend_from_name, generate_key
from .transformation import (
    AlphaCharactersOnly,
    AlphaNumericCharactersOnly,
    DigitsOnly,
    FirstCharacter,
    LastFourDigits,
    Lowercase,
)

# ciphertext prefix -> Laravel backend name
PREFIXES: Dict[str, str] = {"nacl:": "nacl", "brng:": "boring", "fips:": "fips"}

TRANSFORMS: Dict[str, Callable[[], Callable]] = {
    "lowercase": Lowercase,
    "alpha": AlphaCharactersOnly,
    "alphanumeric": AlphaNumericCharactersOnly,
    "digits": DigitsOnly,
    "first-character": FirstCharacter,
    "last-four-digits": LastFourDigits,
}


class CliError(Exception):
    """A problem worth a one-line message rather than a traceback."""


# -- helpers ------------------------------------------------------------


def _key_provider(
    args: argparse.Namespace, prefix: str = "", default_env: str = "CIPHERSWEET_KEY"
) -> KeyProvider:
    key = getattr(args, f"{prefix}key")
    key_file = getattr(args, f"{prefix}key_file")
    key_env = getattr(args, f"{prefix}key_env")
    try:
        if key is not None:
            return StringProvider(key)
        if key_file is not None:
            provider = FileProvider(key_file, encoding="auto")
            provider.get_symmetric_key()  # fail early with a clear message
            return provider
        var = key_env or default_env
        value = os.environ.get(var)
        if not value:
            flag = f"--{prefix.replace('_', '-')}key"
            raise CliError(f"no key given: set {var} or pass {flag}-file / {flag}-env")
        return StringProvider(value)
    except CipherSweetException as exc:
        raise CliError(f"invalid key: {exc}") from exc


def _backend_for(name: Optional[str], ciphertext: Optional[str] = None) -> Backend:
    if name is None and ciphertext is not None:
        for prefix, backend_name in PREFIXES.items():
            if ciphertext.startswith(prefix):
                name = backend_name
                break
        else:
            raise CliError("cannot tell the backend from the ciphertext prefix; pass --backend")
    if name is None:
        name = os.environ.get("CIPHERSWEET_BACKEND") or "nacl"
    try:
        return backend_from_name(name)
    except CipherSweetException as exc:
        raise CliError(str(exc)) from exc


def _read_value(value: Optional[str], stdin: BinaryIO) -> bytes:
    """The positional value, or stdin with one trailing newline removed."""
    if value is not None and value != "-":
        return value.encode("utf-8")
    data = stdin.read()
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n"):
        return data[:-1]
    return data


def _field(engine: CipherSweet, args: argparse.Namespace) -> EncryptedField:
    return EncryptedField(engine, args.table, args.column)


# -- commands -----------------------------------------------------------


def cmd_generate_key(args: argparse.Namespace, stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    stdout.write(generate_key(base64=args.base64).encode("ascii") + b"\n")
    return 0


def cmd_encrypt(args: argparse.Namespace, stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    plaintext = _read_value(args.value, stdin)
    engine = CipherSweet(_key_provider(args), _backend_for(args.backend))
    stdout.write(_field(engine, args).encrypt_value(plaintext, args.aad).encode("ascii") + b"\n")
    return 0


def cmd_decrypt(args: argparse.Namespace, stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    ciphertext = _read_value(args.value, stdin).strip().decode("ascii", "replace")
    engine = CipherSweet(_key_provider(args), _backend_for(args.backend, ciphertext))
    try:
        plaintext = _field(engine, args).decrypt_value_bytes(ciphertext, args.aad)
    except (CipherSweetException, ValueError) as exc:
        raise CliError(f"decryption failed: {exc}") from exc
    stdout.write(plaintext + b"\n")
    return 0


def cmd_blind_index(args: argparse.Namespace, stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    plaintext = _read_value(args.value, stdin)
    engine = CipherSweet(_key_provider(args), _backend_for(args.backend))
    transforms = [TRANSFORMS[name]() for name in args.transform]
    field = _field(engine, args).add_blind_index(BlindIndex(args.name, transforms, args.bits, args.fast))
    value = field.get_blind_index(plaintext, args.name)
    if args.typed:
        stdout.write(f"{field.get_blind_index_type(args.name)} ".encode("ascii"))
    stdout.write(str(value).encode("ascii") + b"\n")
    return 0


def cmd_rotate(args: argparse.Namespace, stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    """Re-encrypt one ciphertext per input line from the old key/backend to
    the new one. Blank lines and lines already under the new configuration are
    passed through. Nothing is written unless every line succeeds."""
    old_provider = _key_provider(args, "old_", "CIPHERSWEET_OLD_KEY")
    new_provider = _key_provider(args, "new_", "CIPHERSWEET_KEY")
    new_field = _field(CipherSweet(new_provider, _backend_for(args.new_backend)), args)
    old_fields: Dict[str, EncryptedField] = {}

    def old_field_for(ciphertext: str) -> EncryptedField:
        backend = _backend_for(args.old_backend, ciphertext)
        name = backend.get_prefix()
        if name not in old_fields:
            old_fields[name] = _field(CipherSweet(old_provider, backend), args)
        return old_fields[name]

    out: List[bytes] = []
    rotated = kept = 0
    for lineno, raw in enumerate(stdin.read().splitlines(), start=1):
        line = raw.strip().decode("ascii", "replace")
        if not line:
            out.append(b"")
            continue
        try:
            rotator = FieldRotator(old_field_for(line), new_field)
            if not rotator.needs_re_encrypt(line, args.aad):
                out.append(line.encode("ascii"))
                kept += 1
                continue
            ciphertext, _ = rotator.prepare_for_update(line, args.aad, args.aad)
        except (CipherSweetException, ValueError, CliError) as exc:
            raise CliError(f"line {lineno}: {exc}") from exc
        out.append(ciphertext.encode("ascii"))
        rotated += 1
    for item in out:
        stdout.write(item + b"\n")
    if not args.quiet:
        print(f"rotated {rotated}, already current {kept}", file=stderr)
    return 0


# -- parser -------------------------------------------------------------


def _add_key_options(
    parser: argparse.ArgumentParser, prefix: str = "", default_env: str = "CIPHERSWEET_KEY"
) -> None:
    group = parser.add_mutually_exclusive_group()
    flag = f"--{prefix}key"
    dest = f"{prefix.replace('-', '_')}key"
    group.add_argument(
        f"{flag}-env",
        dest=f"{dest}_env",
        metavar="VAR",
        help=f"environment variable holding the key (default: {default_env})",
    )
    group.add_argument(
        f"{flag}-file",
        dest=f"{dest}_file",
        metavar="PATH",
        help="file holding the key as hex or base64url",
    )
    group.add_argument(
        flag,
        dest=dest,
        metavar="KEY",
        help="the key itself (visible in the process list; prefer --key-env or --key-file)",
    )


def _add_field_options(parser: argparse.ArgumentParser, aad: bool = True) -> None:
    parser.add_argument("--table", required=True, help="table name used for key derivation")
    parser.add_argument("--column", required=True, help="column name used for key derivation")
    if aad:
        parser.add_argument("--aad", default="", help="additional authenticated data, e.g. the row id")


def _backend_option(parser: argparse.ArgumentParser, flag: str = "--backend", help_extra: str = "") -> None:
    parser.add_argument(
        flag,
        choices=sorted(BACKENDS),
        help=f"backend (default: $CIPHERSWEET_BACKEND or nacl{help_extra})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciphersweet",
        description="Encrypt, decrypt, index and rotate CipherSweet values (PHP/Laravel compatible).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    p = sub.add_parser("generate-key", help="print a new random 32-byte key")
    p.add_argument("--base64", action="store_true", help="base64url instead of hex")
    p.set_defaults(func=cmd_generate_key)

    p = sub.add_parser("encrypt", help="encrypt a value")
    _add_field_options(p)
    _backend_option(p)
    _add_key_options(p)
    p.add_argument("value", nargs="?", help="plaintext (default: read stdin)")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt a value")
    _add_field_options(p)
    _backend_option(p, help_extra="; inferred from the ciphertext prefix")
    _add_key_options(p)
    p.add_argument("value", nargs="?", help="ciphertext (default: read stdin)")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("blind-index", help="compute a blind index, e.g. to search for a value")
    _add_field_options(p, aad=False)
    p.add_argument("--name", required=True, help="index name")
    p.add_argument("--bits", type=int, default=256, help="filter bit length (default: 256)")
    p.add_argument("--fast", action="store_true", help="fast hash (default: slow, like PHP)")
    p.add_argument(
        "--transform",
        action="append",
        default=[],
        choices=sorted(TRANSFORMS),
        help="transformation to apply first; repeat for several, applied in order",
    )
    p.add_argument("--typed", action="store_true", help="also print the index type column value")
    _backend_option(p)
    _add_key_options(p)
    p.add_argument("value", nargs="?", help="plaintext (default: read stdin)")
    p.set_defaults(func=cmd_blind_index)

    p = sub.add_parser(
        "rotate",
        help="re-encrypt ciphertexts (one per line on stdin) under a new key or backend",
        description=(
            "Read one ciphertext per line from stdin and write it re-encrypted under the new key and "
            "backend to stdout, in the same order. Blank lines and values that are already current "
            "are passed through unchanged. Nothing is written if any line fails."
        ),
    )
    _add_field_options(p)
    _backend_option(p, "--old-backend", "; inferred from each ciphertext prefix")
    _backend_option(p, "--new-backend")
    _add_key_options(p, "old-", "CIPHERSWEET_OLD_KEY")
    _add_key_options(p, "new-", "CIPHERSWEET_KEY")
    p.add_argument("-q", "--quiet", action="store_true", help="do not print a summary to stderr")
    p.set_defaults(func=cmd_rotate)
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    stdin: Optional[BinaryIO] = None,
    stdout: Optional[BinaryIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    args = build_parser().parse_args(argv)
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    stderr = stderr if stderr is not None else sys.stderr
    try:
        code = args.func(args, stdin, stdout, stderr)
    except CliError as exc:
        print(f"ciphersweet: error: {exc}", file=stderr)
        return 1
    stdout.flush()
    return code


def main_entry() -> None:  # pragma: no cover - console script wrapper
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    main_entry()
