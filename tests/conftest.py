import sys
from pathlib import Path

import pytest

# Make handshake.py and secure_record.py (one level up) importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import handshake  # noqa: E402
import secure_record  # noqa: E402


@pytest.fixture(scope="session")
def params():
    """The ffdhe3072 group from Lab Preparation (hw2/ffdhe3072.pem)."""
    return handshake.load_group()


@pytest.fixture(scope="session")
def rsa_keys():
    """Long-term 3072-bit RSA signing keys. Generated once: keygen is slow."""
    return {
        "gateway": handshake.generate_signing_key(),
        "node": handshake.generate_signing_key(),
        "attacker": handshake.generate_signing_key(),
    }


@pytest.fixture
def parties(params, rsa_keys):
    """Factory for a fresh (gateway, node) pair; kwargs override trust setup."""
    def make(**kwargs):
        return handshake.make_parties(
            params, rsa_keys["gateway"], rsa_keys["node"], **kwargs)
    return make


@pytest.fixture
def channel(parties):
    """A completed handshake turned into the four record-layer states."""
    gw_session, node_session = handshake.run_handshake(*parties())
    gw_send, gw_recv = secure_record.states_from_session(gw_session)
    node_send, node_recv = secure_record.states_from_session(node_session)
    return {"gw_send": gw_send, "gw_recv": gw_recv,
            "node_send": node_send, "node_recv": node_recv}
