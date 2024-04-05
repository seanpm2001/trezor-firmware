from micropython import const  # pyright: ignore[reportMissingModuleSource]

DUMMY_TAG = b"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xB0\xB1\xB2\xB3\xB4\xB5"
PUBKEY_LENGTH = const(32)


# TODO implement


def encrypt(
    key: bytes,
    nonce: bytes,
    buffer: bytearray,
    init_offset: int = 0,
    payload_length: int = 0,
) -> bytes:
    """
    Returns a 16-byte long encryption tag, the encryption itself is performed on the buffer provided.
    """
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
