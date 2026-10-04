#!/usr/bin/env python3
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 1

DIR_G2N = 0x01  # gateway -> node
DIR_N2G = 0x02  # node -> gateway

MSG_DATA = 0x01

HEADER_FMT = ">BBQBI"  # version, direction, sequence, message_type, ct_length
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 15
IV_LEN = 16
TAG_LEN = 32
SESSION_ID_LEN = 8
KEY_LEN = 32
MAX_SEQUENCE = 2**64 - 1
MAX_CIPHERTEXT = 2**32 - 1


class RecordError(Exception):
    """Base class. No plaintext is ever returned after any of these."""


class FormatError(RecordError):
    """Record is truncated or its fields are inconsistent."""


class DirectionError(RecordError):
    """Record was sent in the other direction (reflection)."""


class MacError(RecordError):
    """HMAC tag did not verify: header, IV or ciphertext was modified."""


class SequenceError(RecordError):
    """Not the exact next sequence number: replay, reorder or gap."""


@dataclass
class ChannelState:
    """Keys and counter for ONE direction. A party holds two of these: one
    it sends on and one it receives on."""
    k_enc: bytes
    k_mac: bytes
    session_id: bytes
    direction: int
    sequence: int = 0  # next to send, or next expected

    def __post_init__(self):
        if len(self.k_enc) != KEY_LEN or len(self.k_mac) != KEY_LEN:
            raise ValueError("keys must be 32 bytes")
        if len(self.session_id) != SESSION_ID_LEN:
            raise ValueError("session_id must be 8 bytes")
        if self.direction not in (DIR_G2N, DIR_N2G):
            raise ValueError("unknown direction")


def states_from_session(session) -> tuple[ChannelState, ChannelState]:
    """Build (send_state, recv_state) for one party from a handshake.Session."""
    g2n = ChannelState(session.k_g2n_enc, session.k_g2n_mac,
                       session.session_id, DIR_G2N)
    n2g = ChannelState(session.k_n2g_enc, session.k_n2g_mac,
                       session.session_id, DIR_N2G)
    return (g2n, n2g) if session.role == b"gateway" else (n2g, g2n)


def _tag(k_mac: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _aes_ctr(k_enc: bytes, iv: bytes, data: bytes) -> bytes:
    # CTR encryption and decryption are the same operation.
    ctx = Cipher(algorithms.AES(k_enc), modes.CTR(iv)).encryptor()
    return ctx.update(data) + ctx.finalize()


def seal(state: ChannelState, plaintext: bytes, message_type: int = MSG_DATA) -> bytes:
    """Encrypt then MAC one record and advance the send counter."""
    if state.sequence > MAX_SEQUENCE:
        raise RecordError("sequence space exhausted: start a new session")
    if len(plaintext) > MAX_CIPHERTEXT:
        raise RecordError("plaintext too long for one record")
    if not 0 <= message_type <= 0xFF:
        raise ValueError("message_type must fit in one byte")

    sequence = state.sequence
    header = struct.pack(HEADER_FMT, VERSION, state.direction, sequence,
                         message_type, len(plaintext))
    # The sequence number is never reused under one key, so neither is the IV.
    iv = state.session_id + sequence.to_bytes(8, "big")
    ciphertext = _aes_ctr(state.k_enc, iv, plaintext)
    tag = _tag(state.k_mac, header + iv + ciphertext)

    state.sequence = sequence + 1
    return header + iv + ciphertext + tag


def open_record(state: ChannelState, record: bytes) -> tuple[int, bytes]:
    """Verify then decrypt one record. Returns (message_type, plaintext).

    Raises a RecordError subclass on any failure. In that case nothing is
    decrypted, nothing is returned and the receive counter does not move.
    """
    if len(record) < HEADER_LEN + IV_LEN + TAG_LEN:
        raise FormatError("record too short")

    header = record[:HEADER_LEN]
    iv = record[HEADER_LEN:HEADER_LEN + IV_LEN]
    ciphertext = record[HEADER_LEN + IV_LEN:-TAG_LEN]
    tag = record[-TAG_LEN:]
    version, direction, sequence, message_type, ct_length = \
        struct.unpack(HEADER_FMT, header)

    # Cheap checks on public header fields. These only pick the error name;
    # a wrong-direction record would also fail the MAC under this key.
    if version != VERSION:
        raise FormatError(f"unsupported version {version}")
    if direction != state.direction:
        raise DirectionError("record is for the opposite direction")

    # Verify the MAC BEFORE decrypting. HMAC.verify compares in constant time.
    h = hmac.HMAC(state.k_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    try:
        h.verify(tag)
    except InvalidSignature:
        raise MacError("HMAC verification failed") from None

    # Everything below is authenticated.
    if ct_length != len(ciphertext):
        raise FormatError("ciphertext length does not match header")
    if iv != state.session_id + sequence.to_bytes(8, "big"):
        raise FormatError("IV does not match session id and sequence")
    if sequence != state.sequence:
        kind = "replayed" if sequence < state.sequence else "out-of-order"
        raise SequenceError(
            f"{kind} record: got sequence {sequence}, expected {state.sequence}")

    plaintext = _aes_ctr(state.k_enc, iv, ciphertext)
    state.sequence += 1
    return message_type, plaintext


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------

def _flip(record: bytes, index: int) -> bytes:
    out = bytearray(record)
    out[index] ^= 0x01
    return bytes(out)


def main() -> None:
    # Stand-in for a handshake Session; with Task 2 use states_from_session().
    sid = os.urandom(8)
    g2n_enc, g2n_mac, n2g_enc, n2g_mac = (os.urandom(32) for _ in range(4))
    gw_send, gw_recv = (ChannelState(g2n_enc, g2n_mac, sid, DIR_G2N),
                        ChannelState(n2g_enc, n2g_mac, sid, DIR_N2G))
    node_send, node_recv = (ChannelState(n2g_enc, n2g_mac, sid, DIR_N2G),
                            ChannelState(g2n_enc, g2n_mac, sid, DIR_G2N))

    print("=== Valid records in both directions ===")
    command = b'{"action":"READ","path":"notes.txt"}'
    rec0 = seal(gw_send, command)
    print(f"  record (seq 0): {rec0.hex()}")
    print(f"  node opened   : {open_record(node_recv, rec0)[1].decode()}")
    reply = seal(node_send, b'{"status":"ok"}')
    print(f"  gateway opened: {open_record(gw_recv, reply)[1].decode()}")

    print("\n=== Rejections ===")

    def expect(name, error, record, state):
        before = state.sequence
        try:
            open_record(state, record)
        except error as exc:
            assert state.sequence == before
            print(f"  {name:<28} {type(exc).__name__}: {exc}")
        else:
            raise AssertionError(f"{name}: record was accepted")

    rec1 = seal(gw_send, command)
    expect("modified ciphertext", MacError, _flip(rec1, HEADER_LEN + IV_LEN + 11), node_recv)
    expect("modified header (type)", MacError, _flip(rec1, 10), node_recv)
    expect("modified header (sequence)", MacError, _flip(rec1, 9), node_recv)
    expect("modified IV", MacError, _flip(rec1, HEADER_LEN), node_recv)
    expect("modified tag", MacError, _flip(rec1, len(rec1) - 1), node_recv)
    expect("truncated record", FormatError, rec1[:20], node_recv)
    expect("replayed record (seq 0)", SequenceError, rec0, node_recv)
    expect("reflected to gateway", DirectionError, rec1, gw_recv)
    rec2 = seal(gw_send, command)
    expect("skipped record (seq 2)", SequenceError, rec2, node_recv)

    print("\n=== Channel still works after the rejected records ===")
    print(f"  node opened seq 1: {open_record(node_recv, rec1)[1].decode()}")
    print(f"  node opened seq 2: {open_record(node_recv, rec2)[1].decode()}")


if __name__ == "__main__":
    main()
