import json
import pathlib

import pytest

from ciphersweet import BoringCrypto, CipherSweet, FIPSCrypto, ModernCrypto, StringProvider

VECTORS = pathlib.Path(__file__).parent / "vectors"
UPSTREAM_KEY = "4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc"

BACKENDS = {"nacl": ModernCrypto, "fips": FIPSCrypto, "brng": BoringCrypto}


def load_vectors(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def make_engine(backend_cls, key=UPSTREAM_KEY):
    return CipherSweet(StringProvider(key), backend_cls())


@pytest.fixture(params=sorted(BACKENDS))
def backend_name(request):
    return request.param


@pytest.fixture
def engine(backend_name):
    return make_engine(BACKENDS[backend_name])


@pytest.fixture
def random_engine(backend_name):
    import os

    return make_engine(BACKENDS[backend_name], os.urandom(32).hex())
