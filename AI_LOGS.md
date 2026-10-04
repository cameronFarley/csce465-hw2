Can you explain how I can do task 1? Do not do it completely for me, but give me direction with code bits.

Task 1 has three parts: encrypt without a MAC, tamper in transit without the key, then replay. Here's how to approach each.

The core idea

CTR turns AES into a stream cipher: ciphertext = plaintext XOR keystream. So flipping a bit in the ciphertext flips exactly the same bit in the decrypted plaintext, and nothing else. If the attacker knows (or guesses) the plaintext at some position, they can rewrite it to anything of the same length:

C' = C XOR (P_old XOR P_new)
→ decrypts to P_new

That relation is what the assignment wants you to show.

1. Sender and receiver

Set up a key, a nonce, and encrypt/decrypt helpers with the cryptography library:

python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = os.urandom(32)
IV  = os.urandom(16)
MSG = b'{"action":"READ","path":"notes.txt"}'

def encrypt(key, iv, plaintext):
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return enc.update(plaintext) + enc.finalize()

Decryption is the same shape with .decryptor(). Then write a receiver(iv, ciphertext) that decrypts, parses the JSON, and "processes" the command (printing something like EXECUTING: READ notes.txt is enough). Keep a counter or log of processed commands, since you'll need it for the replay part.

2. The relay (attacker)

The key design constraint: your relay function must not take the key as an argument. It only sees iv and ciphertext. That is what makes the demonstration honest.

Steps for you to implement:

Find the offset of READ in the known plaintext format (MSG.index(b"READ")). The attacker knows the message format, not the key.
Pick an equal-length replacement. READ is 4 bytes, so you need a 4-byte verb, and it has to keep the JSON valid.
Compute the delta and apply it only at that offset:
python
delta = bytes(a ^ b for a, b in zip(old, new))
# XOR delta into ciphertext[offset : offset+len(old)], leave the rest untouched

Use a bytearray copy of the ciphertext so you can modify it in place.

3. Showing the XOR relation

Print the bytes in hex so the grader can verify it by eye. For the four affected positions, show:

original ciphertext bytes
modified ciphertext bytes
their XOR
old XOR new in plaintext

The last two lines should be identical. An assert on that equality makes the point stronger than a printout alone. Also worth showing: every byte outside that range is unchanged, and the receiver accepts the modified message without complaint.

4. Replay

This is the easy part. Call receiver(iv, ciphertext) twice with the exact same bytes and show your counter going to 2. Nothing in the message or the receiver's state distinguishes a fresh message from an old one.

For the report

The three questions map onto what you built:

Design: sender, key-less relay, receiver with a processing log.
What happened: the command changed and was accepted; the same ciphertext was processed twice.
Root cause: think about two separate gaps here. One is about what CTR's malleability means with no integrity check. The other is about what the receiver would need to track to tell a replay from a new message. Tasks 3's requirements list is a good hint for both, since each item there fixes something you just broke.

One thing to watch: run this inside the course VM with the venv active, and remember AI_USAGE.md needs an entry and the log for this conversation.

Want me to look over your relay function once you've written it?

Can you do this explanation for Task 2-4?

Same approach as Task 1: structure and the tricky API calls, with the logic left for you.

Task 2: Authenticated DH handshake

Building blocks (all from cryptography.hazmat.primitives):

python
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, hmac, serialization

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH)
sig = rsa_key.sign(data, PSS, hashes.SHA256())
# peer_pub.verify(sig, data, PSS, hashes.SHA256()) raises InvalidSignature

params = serialization.load_pem_parameters(open("ffdhe3072.pem", "rb").read())
eph = params.generate_private_key()
y_bytes = eph.public_key().public_numbers().y.to_bytes(384, "big")

To turn a received 384-byte value back into a key for eph.exchange(...), build dh.DHPublicNumbers(int.from_bytes(y_bytes, "big"), params.parameter_numbers()).public_key(). Make sure Z is 384 bytes, and left-pad it if it's ever shorter.

Message flow (plain function calls or a Party class with methods):

Gateway → node: identity, DH public value, nonce
Node → gateway: identity, DH public value, nonce, signature
Gateway → node: signature

Each side builds the transcript from its own view of what was sent and received. If an attacker changes a nonce or public value in transit, the two transcripts differ and the signature check fails, so you don't need separate checks for most of the rejection cases.

Transcript encoding. Eight fields in the order the PDF gives:

python
def encode(fields):
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)

Also write a decode that walks the bytes and raises if a declared length runs past the end, if bytes are left over, or if the field count isn't 8. That covers the "malformed transcript" requirement.

Signing and identity. Each party signs role + SHA256(transcript) with a distinct role, such as b"gateway" and b"node". Give each party a pinned mapping of expected peer identity to RSA public key, and reject before verifying if the claimed identity isn't the expected one. For reflection, think about what happens when a party gets its own message back: the role is wrong, and you can also explicitly reject a peer nonce or public value equal to your own.

KDF. This is a direct transcription of the spec:

python
def hm(key, data):
    h = hmac.HMAC(key, hashes.SHA256()); h.update(data); return h.finalize()

K_master is a plain SHA-256 over the three concatenated pieces, and each of the others is one hm(K_master, label + TH) call. Return the keys in a small dataclass. A good self-check is that both parties end up with identical dataclasses.

Task 3: Encrypt-then-MAC record layer

Packing. The header is 15 bytes:

python
header = struct.pack(">BBQBI", version, direction, seq, msg_type, len(ct))
iv = session_id + struct.pack(">Q", seq)

State. Sequence numbers need to live somewhere. A small class per endpoint works, holding the send key pair, the receive key pair, send_seq, and recv_seq. The gateway sends with the g2n keys and receives with n2g, and the node does the reverse.

seal(): build the IV from the current send_seq, encrypt, build the header, MAC over header || iv || ciphertext, increment send_seq, and return the concatenation.

open_record(): the order of checks is the part being graded:

Slice the record into header, IV, ciphertext, and tag. Reject if the lengths don't agree with ciphertext_length.
Verify the MAC with the library's h.verify(tag), which is constant-time. Don't compare with ==.
Check the version, that the direction is the one this endpoint expects to receive, that seq == recv_seq, and that the IV equals session_id || seq.
Only then decrypt, increment recv_seq, and return the plaintext.

Define your own exception classes (for example BadMAC, ReplayError, WrongDirection) and raise instead of returning anything on failure. That satisfies "do not release plaintext after any error" and gives Task 4 something specific to assert on.

A flaw in the IV format. The library treats the 16-byte IV as one big counter that increments per block. Record 0's second block therefore uses counter session_id || 1, which is also record 1's first block. Any record longer than 16 bytes shares keystream with the next one. Implement the format as specified, but this is a strong point for your security note's "why CTR requires unique IVs" section.

Task 4: Tests and security note

Use a pytest fixture that runs the handshake and returns two connected endpoints, so each test is short:

python
def test_modified_ciphertext(session):
    gw, node = session
    rec = bytearray(gw.seal(MSG_TYPE, b"hello"))
    rec[HEADER_LEN + 16] ^= 0x01
    with pytest.raises(BadMAC):
        node.open_record(bytes(rec))

The others follow the same pattern:

Header: flip a byte inside the first 15 bytes and expect BadMAC.
Replay: open the same record twice and expect ReplayError the second time.
Reflection: feed a gateway-sealed record back into the gateway's own open_record.
Handshake: give one party the wrong pinned RSA key, or flip a signature byte, or hand a party its own message back. Expect your handshake exception.
Valid path: messages in both directions, more than one each, so the sequence numbers advance.

In the failure tests, also assert that recv_seq didn't change. That shows the failure was safe as well as detected.

Security note. The policy says the writing must be yours, so here are questions to answer for each bullet:

Attacker model: what can an on-path attacker do, and what is out of scope (compromised endpoints, stolen long-term keys, traffic analysis)?
Unique IVs: what does XORing two ciphertexts with the same keystream give you?
Verify-before-decrypt: what would the receiver leak or act on if it decrypted first? Task 1 is your example.
Independent keys: what goes wrong when one key serves two different algorithms?
AES-GCM: it does the same job in one primitive with one key. What does it do worse on nonce reuse?
Dangerous authorized calls: tie this to the "central lesson" paragraph. The MAC proves who sent a command, not whether it is safe.