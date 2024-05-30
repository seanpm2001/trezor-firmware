import ustruct  # pyright:ignore[reportMissingModuleSource]

from storage.cache_thp import BROADCAST_CHANNEL_ID
from trezor import protobuf

from .. import message_handler
from ..protocol_common import Message

CODEC_V1 = 0x3F
CONTINUATION_PACKET = 0x80
HANDSHAKE_INIT_REQ = 0x00
HANDSHAKE_INIT_RES = 0x01
HANDSHAKE_COMP_REQ = 0x02
HANDSHAKE_COMP_RES = 0x03
ENCRYPTED_TRANSPORT = 0x04

CONTINUATION_PACKET_MASK = 0x80
ACK_MASK = 0xF7
DATA_MASK = 0xE7

ACK_MESSAGE = 0x20
ERROR = 0x42
CHANNEL_ALLOCATION_REQ = 0x40
_CHANNEL_ALLOCATION_RES = 0x41

TREZOR_STATE_UNPAIRED = b"\x00"
TREZOR_STATE_PAIRED = b"\x01"

if __debug__:
    from trezor import log


class PacketHeader:
    format_str_init = ">BHH"
    format_str_cont = ">BH"

    def __init__(self, ctrl_byte: int, cid: int, length: int) -> None:
        self.ctrl_byte = ctrl_byte
        self.cid = cid
        self.length = length

    def to_bytes(self) -> bytes:
        return ustruct.pack(self.format_str_init, self.ctrl_byte, self.cid, self.length)

    def pack_to_init_buffer(self, buffer, buffer_offset=0) -> None:
        ustruct.pack_into(
            self.format_str_init,
            buffer,
            buffer_offset,
            self.ctrl_byte,
            self.cid,
            self.length,
        )

    def pack_to_cont_buffer(self, buffer, buffer_offset=0) -> None:
        ustruct.pack_into(
            self.format_str_cont, buffer, buffer_offset, CONTINUATION_PACKET, self.cid
        )

    @classmethod
    def get_error_header(cls, cid, length):
        return cls(ERROR, cid, length)

    @classmethod
    def get_channel_allocation_response_header(cls, length):
        return cls(_CHANNEL_ALLOCATION_RES, BROADCAST_CHANNEL_ID, length)


_ENCODED_PROTOBUF_DEVICE_PROPERTIES = (
    b"\x0a\x04\x54\x33\x57\x31\x10\x05\x18\x00\x20\x01\x28\x01\x28\x02"
)

_ERROR_UNALLOCATED_CHANNEL = (
    b"\x55\x4e\x41\x4c\x4c\x4f\x43\x41\x54\x45\x44\x5f\x53\x45\x53\x53\x49\x4f\x4e"
)


def get_device_properties() -> Message:
    return Message(_ENCODED_PROTOBUF_DEVICE_PROPERTIES)


def get_channel_allocation_response(nonce: bytes, new_cid: bytes) -> bytes:
    props_msg = get_device_properties()
    return nonce + new_cid + props_msg.to_bytes()


def get_error_unallocated_channel() -> bytes:
    return _ERROR_UNALLOCATED_CHANNEL


def get_handshake_init_response() -> bytes:
    # TODO implement - 32 bytes ephemeral key, 48 bytes encrypted and masked public key, 16 bytes ciphertext of empty string (i.e. noise tag)
    return b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45\x46\x47\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15"


def get_handshake_completion_response(paired: bool) -> bytes:
    if paired:
        return (
            TREZOR_STATE_PAIRED
            + b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15"
        )
    return (
        TREZOR_STATE_UNPAIRED
        + b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15"
    )


def decode_message(
    buffer: bytes, msg_type: int, message_name: str | None = None
) -> protobuf.MessageType:
    if __debug__:
        log.debug(__name__, "decode message")
    if message_name is not None:
        expected_type = protobuf.type_for_name(message_name)
    else:
        expected_type = protobuf.type_for_wire(msg_type)
    x = message_handler.wrap_protobuf_load(buffer, expected_type)
    return x
