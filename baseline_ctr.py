#!/usr/bin/env python3
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMAND = b'{"action":"READ","path":"notes.txt"}'


# --------------------------------------------------------------------------
# Endpoints (these hold the key)
# --------------------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Sender: AES-256-CTR with a fresh random IV. No MAC."""
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return iv, enc.update(plaintext) + enc.finalize()


def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


class Receiver:
    """Decrypts whatever arrives and acts on it. It has no way to tell
    whether a record was modified or has been seen before."""

    def __init__(self, key: bytes):
        self.key = key
        self.processed = []  # log of every command acted on

    def receive(self, iv: bytes, ciphertext: bytes) -> dict:
        plaintext = decrypt(self.key, iv, ciphertext)
        command = json.loads(plaintext)
        self.processed.append(command)
        print(f"  [receiver] decrypted : {plaintext.decode()}")
        print(f"  [receiver] processing: action={command['action']} "
              f"path={command['path']}  (total processed: {len(self.processed)})")
        return command


# --------------------------------------------------------------------------
# On-path attacker (does NOT hold the key)
# --------------------------------------------------------------------------

def relay_tamper(ciphertext: bytes, offset: int, known: bytes, wanted: bytes) -> bytes:
    """Rewrite `known` to `wanted` at `offset` using only the ciphertext.

    CTR gives C = P xor KS, so XORing the ciphertext with (known xor wanted)
    yields C' = wanted xor KS. The key and keystream are never needed; the
    relay only has to know (or guess) the plaintext at that position.
    """
    assert len(known) == len(wanted), "replacement must be equal length"
    delta = bytes(a ^ b for a, b in zip(known, wanted))
    out = bytearray(ciphertext)
    for i, d in enumerate(delta):
        out[offset + i] ^= d
    return bytes(out)


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    key = os.urandom(32)  # known only to sender and receiver
    receiver = Receiver(key)

    print("=== 1. Sender encrypts ===")
    iv, ct = encrypt(key, COMMAND)
    print(f"  plaintext : {COMMAND.decode()}")
    print(f"  iv        : {iv.hex()}")
    print(f"  ciphertext: {ct.hex()}")

    print("\n=== 2. Relay modifies the ciphertext without the key ===")
    known, wanted = b"READ", b"WIPE"
    offset = COMMAND.index(known)  # public message format -> offset 11
    ct_mod = relay_tamper(ct, offset, known, wanted)
    print(f"  target    : bytes {offset}..{offset + len(known) - 1} "
          f"({known.decode()} -> {wanted.decode()})")
    print(f"  modified  : {ct_mod.hex()}")
    modified_cmd = receiver.receive(iv, ct_mod)
    assert modified_cmd["action"] == wanted.decode()

    print("\n=== 3. XOR relation: C xor C' == P xor P' ===")
    p_mod = COMMAND.replace(known, wanted)
    c_delta = xor(ct, ct_mod)
    p_delta = xor(COMMAND, p_mod)
    print("  idx  P     P'    P^P'  C     C'    C^C'")
    for i in range(offset, offset + len(known)):
        print(f"  {i:<4} {COMMAND[i]:02x}({chr(COMMAND[i])}) "
              f"{p_mod[i]:02x}({chr(p_mod[i])}) {p_delta[i]:02x}    "
              f"{ct[i]:02x}    {ct_mod[i]:02x}    {c_delta[i]:02x}")
    print(f"  P xor P' (full): {p_delta.hex()}")
    print(f"  C xor C' (full): {c_delta.hex()}")
    print(f"  equal: {c_delta == p_delta}; "
          f"bytes outside the target unchanged: "
          f"{all(d == 0 for i, d in enumerate(c_delta) if not offset <= i < offset + len(known))}")
    assert c_delta == p_delta

    print("\n=== 4. Replay: the same original ciphertext delivered twice ===")
    before = len(receiver.processed)
    print("  delivery 1:")
    receiver.receive(iv, ct)
    print("  delivery 2 (identical iv + ciphertext, replayed by the relay):")
    receiver.receive(iv, ct)
    replays = len(receiver.processed) - before
    print(f"  receiver processed the same record {replays} times")
    assert replays == 2

    print("\n=== Summary ===")
    print("  Tampered command accepted : yes (no integrity check)")
    print("  Replayed command accepted : yes (no sequence number or freshness check)")


if __name__ == "__main__":
    main()
