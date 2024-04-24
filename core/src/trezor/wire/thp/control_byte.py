from trezor.wire.thp.thp_messages import (
    ACK_MESSAGE,
    CONTINUATION_PACKET,
    ENCRYPTED_TRANSPORT,
    HANDSHAKE_COMP_REQ,
    HANDSHAKE_INIT_REQ,
)
from trezor.wire.thp.thp_session import ThpError


def add_sync_bit_to_ctrl_byte(ctrl_byte, sync_bit):
    if sync_bit == 0:
        return ctrl_byte & 0xEF
    if sync_bit == 1:
        return ctrl_byte | 0x10
    raise ThpError("Unexpected synchronization bit")


def is_ack(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == ACK_MESSAGE


def is_continuation(ctrl_byte: int) -> bool:
    return ctrl_byte & 0x80 == CONTINUATION_PACKET


def is_encrypted_transport(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == ENCRYPTED_TRANSPORT


def is_handshake_init_req(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == HANDSHAKE_INIT_REQ


def is_handshake_comp_req(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == HANDSHAKE_COMP_REQ
