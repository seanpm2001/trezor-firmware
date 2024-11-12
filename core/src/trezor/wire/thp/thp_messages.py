import ustruct
from micropython import const
from typing import TYPE_CHECKING

from storage.cache_thp import BROADCAST_CHANNEL_ID
from trezor import protobuf, utils
from trezor.enums import ThpPairingMethod
from trezor.messages import ThpDeviceProperties

from .. import message_handler

CODEC_V1 = const(0x3F)
CONTINUATION_PACKET = const(0x80)
HANDSHAKE_INIT_REQ = const(0x00)
HANDSHAKE_INIT_RES = const(0x01)
HANDSHAKE_COMP_REQ = const(0x02)
HANDSHAKE_COMP_RES = const(0x03)
ENCRYPTED_TRANSPORT = const(0x04)

CONTINUATION_PACKET_MASK = const(0x80)
ACK_MASK = const(0xF7)
DATA_MASK = const(0xE7)

ACK_MESSAGE = const(0x20)
_ERROR = const(0x42)
CHANNEL_ALLOCATION_REQ = const(0x40)
_CHANNEL_ALLOCATION_RES = const(0x41)

TREZOR_STATE_UNPAIRED = b"\x00"
TREZOR_STATE_PAIRED = b"\x01"

if __debug__:
    from trezor import log

if TYPE_CHECKING:
    from trezor.wire import WireInterface


class PacketHeader:
    format_str_init = ">BHH"
    format_str_cont = ">BH"

    def __init__(self, ctrl_byte: int, cid: int, length: int) -> None:
        self.ctrl_byte = ctrl_byte
        self.cid = cid
        self.length = length

    def to_bytes(self) -> bytes:
        return ustruct.pack(self.format_str_init, self.ctrl_byte, self.cid, self.length)

    def pack_to_init_buffer(self, buffer: bytearray, buffer_offset: int = 0) -> None:
        ustruct.pack_into(
            self.format_str_init,
            buffer,
            buffer_offset,
            self.ctrl_byte,
            self.cid,
            self.length,
        )

    def pack_to_cont_buffer(self, buffer: bytearray, buffer_offset: int = 0) -> None:
        ustruct.pack_into(
            self.format_str_cont, buffer, buffer_offset, CONTINUATION_PACKET, self.cid
        )

    @classmethod
    def get_error_header(cls, cid: int, length: int):
        return cls(_ERROR, cid, length)

    @classmethod
    def get_channel_allocation_response_header(cls, length: int):
        return cls(_CHANNEL_ALLOCATION_RES, BROADCAST_CHANNEL_ID, length)


_DEFAULT_ENABLED_PAIRING_METHODS = [
    ThpPairingMethod.CodeEntry,
    ThpPairingMethod.QrCode,
    ThpPairingMethod.NFC_Unidirectional,
]


def get_enabled_pairing_methods(
    iface: WireInterface | None = None,
) -> list[ThpPairingMethod]:
    import usb

    l = _DEFAULT_ENABLED_PAIRING_METHODS.copy()
    if iface is not None and iface is usb.iface_wire:
        l.append(ThpPairingMethod.NoMethod)
    return l


def _get_device_properties(iface: WireInterface) -> ThpDeviceProperties:
    # TODO define model variants
    return ThpDeviceProperties(
        pairing_methods=get_enabled_pairing_methods(iface),
        internal_model=utils.INTERNAL_MODEL,
        model_variant=0,
        bootloader_mode=False,
        protocol_version=2,
    )


def get_encoded_device_properties(iface: WireInterface) -> bytes:
    props = _get_device_properties(iface)
    length = protobuf.encoded_length(props)
    encoded_properties = bytearray(length)
    protobuf.encode(encoded_properties, props)
    return encoded_properties


def get_channel_allocation_response(
    nonce: bytes, new_cid: bytes, iface: WireInterface
) -> bytes:
    props_msg = get_encoded_device_properties(iface)
    return nonce + new_cid + props_msg


def get_codec_v1_error_message() -> bytes:
    # Codec_v1 magic constant "?##" + Failure message type + msg_size
    # + msg_data (code = "Failure_InvalidProtocol") + padding to 64 B
    ERROR_MSG = b"\x3f\x23\x23\x00\x03\x00\x00\x00\x14\x08\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return ERROR_MSG


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
