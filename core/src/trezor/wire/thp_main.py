import ustruct
from micropython import const
from typing import TYPE_CHECKING

from storage.cache_thp import BROADCAST_CHANNEL_ID
from trezor import io, log, loop, utils
from trezor.wire.thp import writer

from .thp import (
    ChannelState,
    ThpError,
    ThpErrorType,
    channel_manager,
    checksum,
    thp_messages,
)
from .thp.channel import Channel
from .thp.checksum import CHECKSUM_LENGTH
from .thp.thp_messages import CHANNEL_ALLOCATION_REQ, CODEC_V1, PacketHeader
from .thp.writer import (
    INIT_HEADER_LENGTH,
    MAX_PAYLOAD_LEN,
    PACKET_LENGTH,
    write_payload_to_wire_and_add_checksum,
)

if TYPE_CHECKING:
    from trezorio import WireInterface

_CID_REQ_PAYLOAD_LENGTH = const(12)
_READ_BUFFER: bytearray
_WRITE_BUFFER: bytearray
_CHANNELS: dict[int, Channel] = {}


def set_read_buffer(buffer: bytearray):
    global _READ_BUFFER
    _READ_BUFFER = buffer


def set_write_buffer(buffer: bytearray):
    global _WRITE_BUFFER
    _WRITE_BUFFER = buffer


def get_raw_read_buffer() -> bytearray:
    global _READ_BUFFER
    return _READ_BUFFER


def get_raw_write_buffer() -> bytearray:
    global _WRITE_BUFFER
    return _WRITE_BUFFER


async def thp_main_loop(iface: WireInterface):
    global _CHANNELS
    global _READ_BUFFER
    _CHANNELS = channel_manager.load_cached_channels(_READ_BUFFER)

    read = loop.wait(iface.iface_num() | io.POLL_READ)

    while True:
        try:
            if __debug__ and utils.ALLOW_DEBUG_MESSAGES:
                log.debug(__name__, "thp_main_loop")
            packet = await read
            ctrl_byte, cid = ustruct.unpack(">BH", packet)

            if ctrl_byte == CODEC_V1:
                await _handle_codec_v1(iface, packet)
                continue

            if cid == BROADCAST_CHANNEL_ID:
                await _handle_broadcast(iface, ctrl_byte, packet)
                continue

            if cid in _CHANNELS:
                await _handle_allocated(iface, cid, packet)
            else:
                await _handle_unallocated(iface, cid)

        except ThpError as e:
            if __debug__:
                log.exception(__name__, e)


async def _handle_codec_v1(iface: WireInterface, packet):
    # If the received packet is not initial codec_v1 packet, do not send error message
    if not packet[1:3] == b"##":
        return
    if __debug__:
        log.debug(__name__, "Received codec_v1 message, returning error")
    error_message = thp_messages.get_codec_v1_error_message()
    await writer.write_packet_to_wire(iface, error_message)


async def _handle_broadcast(
    iface: WireInterface, ctrl_byte: int, packet: utils.BufferType
) -> None:
    global _READ_BUFFER
    if ctrl_byte != CHANNEL_ALLOCATION_REQ:
        raise ThpError("Unexpected ctrl_byte in a broadcast channel packet")
    if __debug__:
        log.debug(__name__, "Received valid message on the broadcast channel")

    length, nonce = ustruct.unpack(">H8s", packet[3:])
    payload = _get_buffer_for_payload(length, packet[5:], _CID_REQ_PAYLOAD_LENGTH)
    if not checksum.is_valid(
        payload[-4:],
        packet[: _CID_REQ_PAYLOAD_LENGTH + INIT_HEADER_LENGTH - CHECKSUM_LENGTH],
    ):
        raise ThpError("Checksum is not valid")

    new_channel: Channel = channel_manager.create_new_channel(iface, _READ_BUFFER)
    cid = int.from_bytes(new_channel.channel_id, "big")
    _CHANNELS[cid] = new_channel

    response_data = thp_messages.get_channel_allocation_response(
        nonce, new_channel.channel_id, iface
    )
    response_header = PacketHeader.get_channel_allocation_response_header(
        len(response_data) + CHECKSUM_LENGTH,
    )
    if __debug__:
        log.debug(__name__, "New channel allocated with id %d", cid)

    await write_payload_to_wire_and_add_checksum(iface, response_header, response_data)


async def _handle_allocated(
    iface: WireInterface, cid: int, packet: utils.BufferType
) -> None:
    channel = _CHANNELS[cid]
    if channel is None:
        await _handle_unallocated(iface, cid)
        raise ThpError("Invalid state of a channel")
    if channel.iface is not iface:
        # TODO send error message to wire
        raise ThpError("Channel has different WireInterface")

    if channel.get_channel_state() != ChannelState.UNALLOCATED:
        x = channel.receive_packet(packet)
        if x is not None:
            await x


async def _handle_unallocated(iface, cid) -> None:
    data = (ThpErrorType.UNALLOCATED_CHANNEL).to_bytes(1, "big")
    header = PacketHeader.get_error_header(cid, len(data) + CHECKSUM_LENGTH)
    await write_payload_to_wire_and_add_checksum(iface, header, data)


def _get_buffer_for_payload(
    payload_length: int, existing_buffer: utils.BufferType, max_length=MAX_PAYLOAD_LEN
) -> utils.BufferType:
    if payload_length > max_length:
        raise ThpError("Message too large")
    if payload_length > len(existing_buffer):
        return _try_allocate_new_buffer(payload_length)
    return _reuse_existing_buffer(payload_length, existing_buffer)


def _try_allocate_new_buffer(payload_length: int) -> utils.BufferType:
    try:
        payload: utils.BufferType = bytearray(payload_length)
    except MemoryError:
        payload = bytearray(PACKET_LENGTH)
        raise ThpError("Message too large")
    return payload


def _reuse_existing_buffer(
    payload_length: int, existing_buffer: utils.BufferType
) -> utils.BufferType:
    return memoryview(existing_buffer)[:payload_length]
