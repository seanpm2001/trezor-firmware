from trezor.crypto.curve import curve25519
from trezor.crypto.hashlib import sha512

_PREFIX = b"\x08\x43\x50\x61\x63\x65\x32\x35\x35\x06"
_PADDING = b"\x50\x00\x20"  # TODO fix to correct value


class Cpace:
    def __init__(self, cpace_host_public_key: bytes) -> None:
        self.host_public_key: bytes = cpace_host_public_key
        self.trezor_private_key: bytes
        self.trezor_public_key: bytes
        self.shared_secret: bytes

    def generate_keys_and_secret(self, code_code_entry: bytes) -> None:
        pregenerator = sha512(_PREFIX + code_code_entry + _PADDING).digest()[
            :32
        ]  # TODO add handshake hash
        generator = pregenerator  # TODO change to ELLIGATOR2(pregenerator)

        self.trezor_private_key = b"\x32"  # TODO should be 32 random bytes
        self.trezor_public_key = curve25519.multiply(self.trezor_private_key, generator)
        self.shared_secret = curve25519.multiply(
            self.trezor_private_key, self.host_public_key
        )
