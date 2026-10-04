import pytest
import handshake as hs
import secure_record as sr

COMMAND = b'{"action":"READ","path":"notes.txt"}'
CT_START = sr.HEADER_LEN + sr.IV_LEN  # offset of the ciphertext in a record


def flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def assert_rejected(state, record, error, match):
    """open_record must raise `error` and leave the receive counter alone."""
    before = state.sequence
    with pytest.raises(error, match=match):
        sr.open_record(state, record)
    assert state.sequence == before


# --------------------------------------------------------------------------
# 1. Valid handshake and bidirectional messages
# --------------------------------------------------------------------------

def test_valid_handshake_agrees_on_keys(parties):
    gw, node = hs.run_handshake(*parties())
    assert gw.session_id == node.session_id and len(gw.session_id) == 8
    assert gw.transcript_hash == node.transcript_hash
    keys = [gw.k_g2n_enc, gw.k_g2n_mac, gw.k_n2g_enc, gw.k_n2g_mac]
    assert keys == [node.k_g2n_enc, node.k_g2n_mac, node.k_n2g_enc, node.k_n2g_mac]
    assert all(len(k) == 32 for k in keys)
    assert len(set(keys)) == 4  # key separation
    assert gw.peer_identity == b"node-01" and node.peer_identity == b"gateway-01"


def test_each_session_gets_fresh_keys(parties):
    first, _ = hs.run_handshake(*parties())
    second, _ = hs.run_handshake(*parties())
    assert first.session_id != second.session_id
    assert first.k_g2n_enc != second.k_g2n_enc


def test_bidirectional_messages(channel):
    for i in range(3):  # sequence numbers 0, 1, 2 in each direction
        to_node = COMMAND + str(i).encode()
        record = sr.seal(channel["gw_send"], to_node)
        assert COMMAND not in record  # actually encrypted
        assert sr.open_record(channel["node_recv"], record) == (sr.MSG_DATA, to_node)

        to_gw = b'{"status":"ok","n":%d}' % i
        record = sr.seal(channel["node_send"], to_gw)
        assert sr.open_record(channel["gw_recv"], record) == (sr.MSG_DATA, to_gw)
    assert channel["gw_send"].sequence == channel["node_recv"].sequence == 3
    assert channel["node_send"].sequence == channel["gw_recv"].sequence == 3


def test_sequence_starts_at_zero_and_iv_is_never_reused(channel):
    records = [sr.seal(channel["gw_send"], COMMAND) for _ in range(5)]
    ivs = [r[sr.HEADER_LEN:CT_START] for r in records]
    sid = channel["gw_send"].session_id
    assert ivs == [sid + n.to_bytes(8, "big") for n in range(5)]
    assert len(set(ivs)) == 5


# --------------------------------------------------------------------------
# 2. Modified ciphertext
# --------------------------------------------------------------------------

def test_modified_ciphertext_rejected(channel):
    """The Task 1 attack (READ -> WIPE by XOR) now fails the MAC."""
    record = bytearray(sr.seal(channel["gw_send"], COMMAND))
    offset = CT_START + COMMAND.index(b"READ")
    for i, (a, b) in enumerate(zip(b"READ", b"WIPE")):
        record[offset + i] ^= a ^ b
    assert_rejected(channel["node_recv"], bytes(record),
                    sr.MacError, "HMAC verification failed")


def test_modified_tag_rejected(channel):
    record = sr.seal(channel["gw_send"], COMMAND)
    assert_rejected(channel["node_recv"], flip(record, len(record) - 1),
                    sr.MacError, "HMAC verification failed")


def test_valid_record_still_opens_after_rejection(channel):
    record = sr.seal(channel["gw_send"], COMMAND)
    assert_rejected(channel["node_recv"], flip(record, CT_START),
                    sr.MacError, "HMAC verification failed")
    assert sr.open_record(channel["node_recv"], record) == (sr.MSG_DATA, COMMAND)


# --------------------------------------------------------------------------
# 3. Modified authenticated header
# --------------------------------------------------------------------------

@pytest.mark.parametrize("index,field", [
    (9, "sequence"), (10, "message_type"), (14, "ciphertext_length"),
    (sr.HEADER_LEN + 15, "iv"),
])
def test_modified_header_rejected(channel, index, field):
    record = sr.seal(channel["gw_send"], COMMAND)
    assert_rejected(channel["node_recv"], flip(record, index),
                    sr.MacError, "HMAC verification failed")


def test_modified_version_rejected(channel):
    record = sr.seal(channel["gw_send"], COMMAND)
    assert_rejected(channel["node_recv"], flip(record, 0),
                    sr.FormatError, "unsupported version")


def test_truncated_record_rejected(channel):
    record = sr.seal(channel["gw_send"], COMMAND)
    assert_rejected(channel["node_recv"], record[:sr.HEADER_LEN + 4],
                    sr.FormatError, "record too short")
    assert_rejected(channel["node_recv"], record[:-1],
                    sr.MacError, "HMAC verification failed")


# --------------------------------------------------------------------------
# 4. Replayed record
# --------------------------------------------------------------------------

def test_replayed_record_rejected(channel):
    record = sr.seal(channel["gw_send"], COMMAND)
    assert sr.open_record(channel["node_recv"], record) == (sr.MSG_DATA, COMMAND)
    assert_rejected(channel["node_recv"], record,
                    sr.SequenceError, "replayed record: got sequence 0, expected 1")


def test_out_of_order_record_rejected(channel):
    sr.seal(channel["gw_send"], b"first")
    second = sr.seal(channel["gw_send"], b"second")
    assert_rejected(channel["node_recv"], second,
                    sr.SequenceError, "out-of-order record: got sequence 1, expected 0")


def test_record_from_another_session_rejected(channel, parties):
    """Replay across sessions fails: the keys are fresh per session."""
    other_gw, _ = hs.run_handshake(*parties())
    other_send, _ = sr.states_from_session(other_gw)
    old_record = sr.seal(other_send, COMMAND)
    assert_rejected(channel["node_recv"], old_record,
                    sr.MacError, "HMAC verification failed")


# --------------------------------------------------------------------------
# 5. Record reflected into the opposite direction
# --------------------------------------------------------------------------

def test_reflected_record_rejected(channel):
    record = sr.seal(channel["gw_send"], COMMAND)  # gateway -> node
    assert_rejected(channel["gw_recv"], record,     # sent back to the gateway
                    sr.DirectionError, "opposite direction")


def test_reflected_record_with_rewritten_direction_rejected(channel):
    """Even if the attacker fixes the direction byte, the per-direction MAC
    key makes the tag invalid."""
    record = bytearray(sr.seal(channel["gw_send"], COMMAND))
    record[1] = sr.DIR_N2G
    assert_rejected(channel["gw_recv"], bytes(record),
                    sr.MacError, "HMAC verification failed")


# --------------------------------------------------------------------------
# 6. Handshake attacks
# --------------------------------------------------------------------------

def test_incorrect_rsa_public_key_rejected(parties, rsa_keys):
    """Gateway holds the wrong public key for the node."""
    gateway, node = parties(gw_trusts=rsa_keys["attacker"].public_key())
    msg2 = node.respond(gateway.start())
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS signature for role node"):
        gateway.finish(msg2)


def test_attacker_signed_msg2_rejected(parties, rsa_keys):
    """Man in the middle re-signs the transcript with its own RSA key."""
    gateway, node = parties()
    msg1 = gateway.start()
    fields = hs.decode_fields(node.respond(msg1), 5)
    g = hs.decode_fields(msg1, 4)
    th = hs.transcript_hash(hs.build_transcript(
        g[1], fields[1], g[3], fields[3], g[2], fields[2]))
    fields[4] = hs.sign_transcript(rsa_keys["attacker"], hs.ROLE_NODE, th)
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS signature for role node"):
        gateway.finish(hs.encode_fields(fields))


def test_invalid_transcript_signature_rejected(parties):
    def relay(step, message):  # corrupt the gateway's signature in msg3
        return hs.flip_field(message, 2, 1) if step == 3 else message
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS signature for role gateway"):
        hs.run_handshake(*parties(), relay=relay)


@pytest.mark.parametrize("step,count,index,what", [
    (1, 4, 2, "gateway nonce"), (1, 4, 3, "gateway DH value"),
    (2, 5, 2, "node nonce"), (2, 5, 3, "node DH value"),
])
def test_changed_nonce_or_public_value_rejected(parties, step, count, index, what):
    def relay(s, message):
        return hs.flip_field(message, count, index) if s == step else message
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS signature for role node"):
        hs.run_handshake(*parties(), relay=relay)


def test_reflected_handshake_message_rejected(parties):
    """Gateway's own msg1 is sent straight back to it as if it were msg2."""
    gateway, _ = parties()
    msg1 = gateway.start()
    with pytest.raises(hs.HandshakeError, match="expected 5 fields, got 4"):
        gateway.finish(msg1)


def test_reflected_values_in_msg2_rejected(parties):
    """Gateway's own nonce and DH value come back in a well-formed msg2."""
    gateway, _ = parties()
    _, _, nonce_g, dh_g = hs.decode_fields(gateway.start(), 4)
    forged = hs.encode_fields([hs.TAG_HS2, b"node-01", nonce_g, dh_g, b"\x00" * 384])
    with pytest.raises(hs.HandshakeError, match="reflected handshake message"):
        gateway.finish(forged)


def test_reflected_signature_rejected(parties):
    """Node's own signature is sent back to it as the gateway's msg3."""
    gateway, node = parties()
    node_sig = hs.decode_fields(node.respond(gateway.start()), 5)[4]
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS signature for role gateway"):
        node.accept(hs.encode_fields([hs.TAG_HS3, node_sig]))


def test_unexpected_peer_identity_rejected(parties):
    gateway, node = parties(gw_expects=b"node-02")
    msg2 = node.respond(gateway.start())
    with pytest.raises(hs.HandshakeError, match="unexpected peer identity"):
        gateway.finish(msg2)


def test_malformed_transcript_rejected_before_hashing():
    good = hs.build_transcript(b"gateway-01", b"node-01", b"\x01" * hs.DH_LEN,
                               b"\x02" * hs.DH_LEN, b"\x03" * 16, b"\x04" * 16)
    assert len(hs.transcript_hash(good)) == 32
    with pytest.raises(hs.HandshakeError, match="malformed encoding"):
        hs.transcript_hash(good[:3] + b"\x0e" + good[4:])  # label length 13 -> 14
    with pytest.raises(hs.HandshakeError, match="malformed encoding"):
        hs.transcript_hash(good + b"\x00")  # trailing byte
    short_nonce = hs.build_transcript(b"gateway-01", b"node-01", b"\x01" * hs.DH_LEN,
                                      b"\x02" * hs.DH_LEN, b"\x03" * 15, b"\x04" * 16)
    with pytest.raises(hs.HandshakeError, match="nonce is not 16 bytes"):
        hs.transcript_hash(short_nonce)


def test_failed_party_cannot_continue(parties):
    """After a rejection the party is dead: no session can be coaxed out."""
    gateway, node = parties(gw_expects=b"node-02")
    msg2 = node.respond(gateway.start())
    with pytest.raises(hs.HandshakeError):
        gateway.finish(msg2)
    with pytest.raises(hs.HandshakeError, match="state failed"):
        gateway.finish(msg2)
