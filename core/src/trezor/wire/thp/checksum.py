from micropython import const

from trezor import utils
from trezor.crypto import crc

CHECKSUM_LENGTH = const(4)


def compute(data: bytes | utils.BufferType) -> bytes:
    return crc.crc32(data).to_bytes(CHECKSUM_LENGTH, "big")


def is_valid(checksum: bytes | utils.BufferType, data: bytes) -> bool:
    data_checksum = compute(data)
    return checksum == data_checksum
