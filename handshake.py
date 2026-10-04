#!/usr/bin/env python3
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
KDF_LABEL = b"CSCE465-KDF-v1"

ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"

NONCE_LEN = 16
DH_LEN = 384  # byte width of the 3072-bit ffdhe3072 modulus
GROUP_FILE = Path(__file__).resolve().parent / "ffdhe3072.pem"

TAG_HS1, TAG_HS2, TAG_HS3 = b"HS1", b"HS2", b"HS3"


class HandshakeError(Exception):
    """Any handshake failure. No session keys are released after one."""


# --------------------------------------------------------------------------
# Length-prefixed (TLV) encoding
# --------------------------------------------------------------------------

def encode_fields(fields) -> bytes:
    """Each field preceded by its length as a 4-byte big-endian integer."""
    return b"".join(len(f).to_bytes(4, "big") + f for f in fields)


def decode_fields(data: bytes, count: int) -> list[bytes]:
    """Strict inverse of encode_fields. Rejects a truncated length prefix, a
    declared length that overruns the buffer, trailing bytes, or the wrong
    number of fields."""
    fields, pos = [], 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise HandshakeError("malformed encoding: truncated length prefix")
        n = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        if n > len(data) - pos:
            raise HandshakeError("malformed encoding: declared length exceeds data")
        fields.append(data[pos:pos + n])
        pos += n
    if len(fields) != count:
        raise HandshakeError(
            f"malformed encoding: expected {count} fields, got {len(fields)}")
    return fields


# --------------------------------------------------------------------------
# Transcript
# --------------------------------------------------------------------------

def build_transcript(id_g: bytes, id_n: bytes, dh_g: bytes, dh_n: bytes,
                     nonce_g: bytes, nonce_n: bytes) -> bytes:
    return encode_fields([PROTOCOL_LABEL, GROUP_ID, id_g, id_n,
                          dh_g, dh_n, nonce_g, nonce_n])


def parse_transcript(transcript: bytes) -> list[bytes]:
    """Validate the canonical transcript structure field by field."""
    label, group, id_g, id_n, dh_g, dh_n, nonce_g, nonce_n = \
        decode_fields(transcript, 8)
    if label != PROTOCOL_LABEL:
        raise HandshakeError("malformed transcript: wrong protocol label")
    if group != GROUP_ID:
        raise HandshakeError("malformed transcript: wrong group identifier")
    if not id_g or not id_n:
        raise HandshakeError("malformed transcript: empty identity")
    if len(dh_g) != DH_LEN or len(dh_n) != DH_LEN:
        raise HandshakeError("malformed transcript: DH value is not 384 bytes")
    if len(nonce_g) != NONCE_LEN or len(nonce_n) != NONCE_LEN:
        raise HandshakeError("malformed transcript: nonce is not 16 bytes")
    return [label, group, id_g, id_n, dh_g, dh_n, nonce_g, nonce_n]


def transcript_hash(transcript: bytes) -> bytes:
    """TH = SHA-256(transcript). The transcript is validated first, so a
    field with an incorrectly declared length is rejected before hashing."""
    parse_transcript(transcript)
    return hashlib.sha256(transcript).digest()


# --------------------------------------------------------------------------
# Group, signatures, key derivation
# --------------------------------------------------------------------------

def load_group(path=GROUP_FILE) -> dh.DHParameters:
    try:
        pem = Path(path).read_bytes()
    except FileNotFoundError:
        raise HandshakeError(
            f"{path} not found. Generate it with: openssl genpkey -genparam "
            "-algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem") from None
    params = serialization.load_pem_parameters(pem)
    numbers = params.parameter_numbers()
    if numbers.p.bit_length() != 3072 or numbers.g != 2:
        raise HandshakeError("group file is not ffdhe3072")
    return params


def generate_signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.DIGEST_LENGTH)


def sign_transcript(key: rsa.RSAPrivateKey, role: bytes, th: bytes) -> bytes:
    """RSA-PSS/SHA-256 signature over role || SHA-256(transcript)."""
    return key.sign(role + th, _pss(), hashes.SHA256())


def verify_transcript(public_key: rsa.RSAPublicKey, role: bytes, th: bytes,
                      signature: bytes) -> None:
    try:
        public_key.verify(signature, role + th, _pss(), hashes.SHA256())
    except InvalidSignature:
        raise HandshakeError(
            f"invalid RSA-PSS signature for role {role.decode()}") from None


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


@dataclass(frozen=True)
class Session:
    session_id: bytes   # 8 bytes
    k_g2n_enc: bytes
    k_g2n_mac: bytes
    k_n2g_enc: bytes
    k_n2g_mac: bytes
    transcript_hash: bytes
    role: bytes
    peer_identity: bytes


def derive_session(z: bytes, th: bytes, role: bytes, peer_identity: bytes) -> Session:
    """The assignment-specified KDF. z is the 384-byte shared secret."""
    if len(z) != DH_LEN:
        raise HandshakeError("shared secret is not 384 bytes")
    k_master = hashlib.sha256(KDF_LABEL + z + th).digest()
    return Session(
        session_id=_hmac(k_master, b"session identifier" + th)[:8],
        k_g2n_enc=_hmac(k_master, b"gateway-to-node encryption" + th),
        k_g2n_mac=_hmac(k_master, b"gateway-to-node MAC" + th),
        k_n2g_enc=_hmac(k_master, b"node-to-gateway encryption" + th),
        k_n2g_mac=_hmac(k_master, b"node-to-gateway MAC" + th),
        transcript_hash=th,
        role=role,
        peer_identity=peer_identity,
    )


# --------------------------------------------------------------------------
# Parties
# --------------------------------------------------------------------------

class Party:
    """One end of the handshake. Holds a long-term RSA signing key and the
    identity and RSA public key it expects from its peer."""

    def __init__(self, role: bytes, identity: bytes,
                 signing_key: rsa.RSAPrivateKey,
                 peer_identity: bytes, peer_public_key: rsa.RSAPublicKey,
                 params: dh.DHParameters):
        if role not in (ROLE_GATEWAY, ROLE_NODE):
            raise ValueError("role must be gateway or node")
        self.role = role
        self.identity = identity
        self.signing_key = signing_key
        self.peer_identity = peer_identity
        self.peer_public_key = peer_public_key
        self.params = params
        self._state = "idle"
        self._dh_priv = None
        self._dh_pub = None
        self._nonce = None
        self._th = None
        self._z = None

    # ---- helpers ---------------------------------------------------------

    def _fresh_ephemerals(self) -> None:
        """Fresh DH private value and 16-byte nonce for every session."""
        self._dh_priv = self.params.generate_private_key()
        y = self._dh_priv.public_key().public_numbers().y
        self._dh_pub = y.to_bytes(DH_LEN, "big")
        self._nonce = os.urandom(NONCE_LEN)

    def _fail(self, reason: str):
        self._wipe()
        self._state = "failed"
        raise HandshakeError(reason)

    def _wipe(self) -> None:
        self._dh_priv = None
        self._z = None

    def _check_peer_values(self, peer_id: bytes, peer_nonce: bytes,
                           peer_dh: bytes) -> None:
        if peer_id != self.peer_identity:
            self._fail(f"unexpected peer identity {peer_id!r}")
        if peer_id == self.identity:
            self._fail("reflected handshake message: peer claims our identity")
        if len(peer_nonce) != NONCE_LEN:
            self._fail("peer nonce is not 16 bytes")
        if len(peer_dh) != DH_LEN:
            self._fail("peer DH value is not 384 bytes")
        if peer_nonce == self._nonce or peer_dh == self._dh_pub:
            self._fail("reflected handshake message: our own values came back")

    def _shared_secret(self, peer_dh: bytes) -> bytes:
        numbers = self.params.parameter_numbers()
        y = int.from_bytes(peer_dh, "big")
        if not 2 <= y <= numbers.p - 2:
            self._fail("peer DH public value out of range")
        try:
            peer_key = dh.DHPublicNumbers(y, numbers).public_key()
            z = self._dh_priv.exchange(peer_key)
        except ValueError:
            self._fail("peer DH public value rejected")
        return z.rjust(DH_LEN, b"\x00")  # 384-byte big-endian, left-padded

    def _decode(self, message: bytes, tag: bytes, count: int) -> list[bytes]:
        try:
            fields = decode_fields(message, count)
        except HandshakeError as exc:
            self._fail(str(exc))
        if fields[0] != tag:
            self._fail(f"unexpected or reflected handshake message: wanted "
                       f"{tag.decode()}, got {fields[0]!r}")
        return fields[1:]

    def _hash(self, transcript: bytes) -> bytes:
        try:
            return transcript_hash(transcript)
        except HandshakeError as exc:
            self._fail(str(exc))

    def _verify_peer(self, peer_role: bytes, signature: bytes) -> None:
        try:
            verify_transcript(self.peer_public_key, peer_role, self._th, signature)
        except HandshakeError as exc:
            self._fail(str(exc))

    def _require(self, role: bytes, state: str) -> None:
        if self.role != role or self._state != state:
            raise HandshakeError(
                f"{self.role.decode()} in state {self._state} cannot do this step")

    # ---- gateway side ----------------------------------------------------

    def start(self) -> bytes:
        """Gateway: produce msg1."""
        self._require(ROLE_GATEWAY, "idle")
        self._fresh_ephemerals()
        self._state = "sent_hs1"
        return encode_fields([TAG_HS1, self.identity, self._nonce, self._dh_pub])

    def finish(self, msg2: bytes) -> tuple[bytes, Session]:
        """Gateway: verify msg2, then return (msg3, session)."""
        self._require(ROLE_GATEWAY, "sent_hs1")
        id_n, nonce_n, dh_n, sig_n = self._decode(msg2, TAG_HS2, 5)
        self._check_peer_values(id_n, nonce_n, dh_n)

        transcript = build_transcript(self.identity, id_n, self._dh_pub, dh_n,
                                      self._nonce, nonce_n)
        self._th = self._hash(transcript)
        self._verify_peer(ROLE_NODE, sig_n)  # authenticate before using DH_n

        z = self._shared_secret(dh_n)
        session = derive_session(z, self._th, self.role, id_n)
        sig_g = sign_transcript(self.signing_key, ROLE_GATEWAY, self._th)
        self._wipe()  # ephemeral private value is gone: forward secrecy
        self._state = "done"
        return encode_fields([TAG_HS3, sig_g]), session

    # ---- node side -------------------------------------------------------

    def respond(self, msg1: bytes) -> bytes:
        """Node: process msg1 and produce msg2. No session exists yet."""
        self._require(ROLE_NODE, "idle")
        id_g, nonce_g, dh_g = self._decode(msg1, TAG_HS1, 4)
        self._fresh_ephemerals()
        self._check_peer_values(id_g, nonce_g, dh_g)

        transcript = build_transcript(id_g, self.identity, dh_g, self._dh_pub,
                                      nonce_g, self._nonce)
        self._th = self._hash(transcript)
        self._z = self._shared_secret(dh_g)
        sig_n = sign_transcript(self.signing_key, ROLE_NODE, self._th)
        self._state = "sent_hs2"
        return encode_fields([TAG_HS2, self.identity, self._nonce,
                              self._dh_pub, sig_n])

    def accept(self, msg3: bytes) -> Session:
        """Node: verify the gateway's signature, then release the session."""
        self._require(ROLE_NODE, "sent_hs2")
        (sig_g,) = self._decode(msg3, TAG_HS3, 2)
        self._verify_peer(ROLE_GATEWAY, sig_g)
        session = derive_session(self._z, self._th, self.role, self.peer_identity)
        self._wipe()
        self._state = "done"
        return session


def run_handshake(gateway: Party, node: Party, relay=None) -> tuple[Session, Session]:
    """Run the three messages in-process. `relay(step, message)` models the
    on-path attacker and may return a modified message."""
    relay = relay or (lambda step, message: message)
    msg1 = relay(1, gateway.start())
    msg2 = relay(2, node.respond(msg1))
    msg3, gateway_session = gateway.finish(msg2)
    node_session = node.accept(relay(3, msg3))
    return gateway_session, node_session


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------

def make_parties(params, gw_key, node_key, gw_id=b"gateway-01", node_id=b"node-01",
                 gw_expects=None, node_expects=None,
                 gw_trusts=None, node_trusts=None) -> tuple[Party, Party]:
    gateway = Party(ROLE_GATEWAY, gw_id, gw_key, gw_expects or node_id,
                    gw_trusts or node_key.public_key(), params)
    node = Party(ROLE_NODE, node_id, node_key, node_expects or gw_id,
                 node_trusts or gw_key.public_key(), params)
    return gateway, node


def flip_field(message: bytes, count: int, index: int) -> bytes:
    """Relay helper: flip one bit in field `index` of a TLV message."""
    fields = decode_fields(message, count)
    changed = bytearray(fields[index])
    changed[-1] ^= 0x01
    fields[index] = bytes(changed)
    return encode_fields(fields)


def main() -> None:
    params = load_group()
    print("Generating two 3072-bit RSA signing keys...")
    gw_key, node_key = generate_signing_key(), generate_signing_key()

    print("\n=== Valid handshake ===")
    gs, ns = run_handshake(*make_parties(params, gw_key, node_key))
    assert gs.session_id == ns.session_id
    assert (gs.k_g2n_enc, gs.k_g2n_mac, gs.k_n2g_enc, gs.k_n2g_mac) == \
           (ns.k_g2n_enc, ns.k_g2n_mac, ns.k_n2g_enc, ns.k_n2g_mac)
    assert len({gs.k_g2n_enc, gs.k_g2n_mac, gs.k_n2g_enc, gs.k_n2g_mac}) == 4
    print(f"  session_id        : {gs.session_id.hex()}")
    print(f"  transcript hash   : {gs.transcript_hash.hex()}")
    print(f"  K_g2n_enc         : {gs.k_g2n_enc.hex()}")
    print(f"  K_g2n_mac         : {gs.k_g2n_mac.hex()}")
    print(f"  K_n2g_enc         : {gs.k_n2g_enc.hex()}")
    print(f"  K_n2g_mac         : {gs.k_n2g_mac.hex()}")
    print("  both sides agree; the four keys are distinct")

    gs2, _ = run_handshake(*make_parties(params, gw_key, node_key))
    assert gs2.session_id != gs.session_id and gs2.k_g2n_enc != gs.k_g2n_enc
    print(f"  second session id : {gs2.session_id.hex()} (fresh keys per session)")

    print("\n=== Rejections ===")

    def expect_reject(name, attempt):
        try:
            attempt()
        except HandshakeError as exc:
            print(f"  {name:<34} REJECTED: {exc}")
        else:
            raise AssertionError(f"{name}: handshake was accepted")

    def with_relay(relay, **kwargs):
        return lambda: run_handshake(
            *make_parties(params, gw_key, node_key, **kwargs), relay=relay)

    other_key = generate_signing_key()
    expect_reject("incorrect RSA public key",
                  with_relay(None, gw_trusts=other_key.public_key()))
    expect_reject("invalid signature (msg2)",
                  with_relay(lambda s, m: flip_field(m, 5, 4) if s == 2 else m))
    expect_reject("changed nonce (msg1)",
                  with_relay(lambda s, m: flip_field(m, 4, 2) if s == 1 else m))
    expect_reject("changed DH public value (msg2)",
                  with_relay(lambda s, m: flip_field(m, 5, 3) if s == 2 else m))
    expect_reject("unexpected peer identity",
                  with_relay(None, gw_expects=b"node-02"))
    expect_reject("malformed length prefix",
                  with_relay(lambda s, m: m[:3] + b"\xff" + m[4:] if s == 1 else m))

    def reflect_msg1():
        gateway, _ = make_parties(params, gw_key, node_key)
        gateway.finish(gateway.start())  # gateway's own msg1 sent back to it
    expect_reject("reflected msg1 to gateway", reflect_msg1)

    def reflect_signature():
        gateway, node = make_parties(params, gw_key, node_key)
        msg2 = node.respond(gateway.start())
        node_sig = decode_fields(msg2, 5)[4]
        node.accept(encode_fields([TAG_HS3, node_sig]))  # node's own signature
    expect_reject("reflected signature to node", reflect_signature)

    def bad_transcript():
        good = build_transcript(b"gateway-01", b"node-01", b"\x01" * DH_LEN,
                                b"\x02" * DH_LEN, b"\x03" * 16, b"\x04" * 16)
        transcript_hash(good[:3] + b"\x0e" + good[4:])  # label length 13 -> 14
    expect_reject("transcript with wrong field length", bad_transcript)


if __name__ == "__main__":
    main()
