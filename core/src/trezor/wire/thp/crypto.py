from micropython import const
from trezorcrypto import aesgcm, curve25519, hmac

from trezor.crypto.hashlib import sha256

DUMMY_TAG = b"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xB0\xB1\xB2\xB3\xB4\xB5"
PUBKEY_LENGTH = const(32)


# TODO implement


def encrypt(
    # key: bytes,
    # nonce: bytes,
    buffer: bytearray,
    init_offset: int = 0,
    payload_length: int = 0,
) -> bytes:
    """
    Returns a 16-byte long encryption tag, the encryption is performed on the buffer provided (in place).
    """

    #  return AES-GCM-ENCRYPT(key=key_response, IV=0^96, ad=empty_string, plaintext=buffer).
    return DUMMY_TAG


def decrypt(
    key: bytes,
    nonce: bytes,
    buffer: bytearray,
    init_offset: int = 0,
    payload_length: int = 0,
) -> None:
    """
    Decryption in place.
    """
    pass


def is_tag_valid(key: bytes, nonce: bytes, payload: bytes, noise_tag: bytes) -> bool:
    return True


PROTOCOL_NAME = bytes("Noise_XX_25519_AESGCM_SHA256", "ascii")
IV_1 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
IV_2 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

trezor_static_privkey: bytes = b""  # TODO
trezor_static_pubkey: bytes = b""  # TODO


def _handle_th1_crypto(device_properties: bytes, host_ephemeral_pubkey: bytes):

    # 1
    trezor_ephemeral_privkey = curve25519.generate_secret()
    trezor_ephemeral_pubkey = curve25519.publickey(trezor_ephemeral_privkey)
    # 2
    h = _hash_two(PROTOCOL_NAME, device_properties)
    # 3
    h = _hash_two(h, host_ephemeral_pubkey)
    # 4
    h = _hash_two(h, trezor_ephemeral_pubkey)
    # 5 - TODO rename `point`
    point = curve25519.multiply(trezor_ephemeral_privkey, host_ephemeral_pubkey)
    ck, k = _hkdf(PROTOCOL_NAME, point)
    # 6
    mask = _hash_two(trezor_static_pubkey, trezor_ephemeral_pubkey)
    # 7
    trezor_masked_static_pubkey = curve25519.multiply(mask, trezor_static_pubkey)
    # 8
    aes_ctx = aesgcm(key=k, iv=IV_1)
    encrypted_trezor_static_pubkey = aes_ctx.encrypt(trezor_masked_static_pubkey)
    aes_ctx.auth(h)
    tag_to_encrypted_key = aes_ctx.finish()
    encrypted_trezor_static_pubkey = (
        encrypted_trezor_static_pubkey + tag_to_encrypted_key
    )
    # 9
    h = _hash_two(h, encrypted_trezor_static_pubkey)
    # 10 - TODO rename `point`
    point = curve25519.multiply(trezor_static_privkey, host_ephemeral_pubkey)
    ck, k = _hkdf(ck, curve25519.multiply(mask, point))
    # 11
    aes_ctx = aesgcm(key=k, iv=IV_1)
    aes_ctx.auth(h)
    tag = aes_ctx.finish()
    # 12
    h = _hash_two(h, tag)
    # 13 -ish
    return (trezor_ephemeral_pubkey, encrypted_trezor_static_pubkey, tag)


def _handle_thp2_crypto(
    encrypted_host_static_pubkey: bytes,
    encrypted_payload,
    k,
    h,
    ck,
    trezor_ephemeral_privkey,
):
    # 1 - TODO WHAT TO DO WITH ad=h???????????????????
    aes_ctx = aesgcm(k, IV_2)
    host_static_pubkey = aes_ctx.decrypt(encrypted_host_static_pubkey[:16])
    aes_ctx.auth(h)
    tag = aes_ctx.finish()
    assert tag == encrypted_host_static_pubkey[-16:]
    # 2
    h = _hash_two(h, encrypted_host_static_pubkey)
    # 3
    ck, k = _hkdf(ck, curve25519.multiply(trezor_ephemeral_privkey, host_static_pubkey))
    # 4 - TODO WHAT TO DO WITH ad=h???????????????????
    payload_binary = aesgcm(k, IV_1).decrypt(encrypted_payload)

    # 5 and #6 somewhere else
    # 7
    h = _hash_two(h, payload_binary)
    # 8 somewhere else
    # 9
    # key_request, key_response = _hkdf(ck, b"")
    # TODO set nonces: nonce_request=0, nonce_response =1

    # 10 somewhere else


def _hkdf(chaining_key, input: bytes):
    temp_key = hmac(hmac.SHA256, chaining_key, input).digest()
    output_1 = hmac(hmac.SHA256, temp_key, b"\x01").digest()
    ctx_output_2 = hmac(hmac.SHA256, temp_key, output_1)
    ctx_output_2.update(b"\x02")
    output_2 = ctx_output_2.digest()
    return (output_1, output_2)


def _hash_two(part_1, part_2) -> bytes:
    ctx = sha256(part_1)
    ctx.update(part_2)
    return ctx.digest()
