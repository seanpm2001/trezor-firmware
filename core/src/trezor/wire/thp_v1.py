import ustruct  # pyright: ignore[reportMissingModuleSource]
from micropython import const  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from storage.cache_thp import BROADCAST_CHANNEL_ID
from trezor import io, log, loop, utils

from .protocol_common import MessageWithId
from .thp import ChannelState, checksum, thp_messages
from .thp.channel import MAX_PAYLOAD_LEN, REPORT_LENGTH, Channel, load_cached_channels
from .thp.checksum import CHECKSUM_LENGTH
from .thp.thp_messages import CHANNEL_ALLOCATION_REQ, CODEC_V1, InitHeader
from .thp.thp_session import ThpError
from .thp.writer import write_payload_to_wire

if TYPE_CHECKING:
    from trezorio import WireInterface  # pyright: ignore[reportMissingImports]

_MAX_CID_REQ_PAYLOAD_LENGTH = const(12)  # TODO set to reasonable value


_BUFFER: bytearray
_BUFFER_LOCK = None

CHANNELS: dict[int, Channel] = {}


def set_buffer(buffer):
    global _BUFFER
    _BUFFER = buffer


async def thp_main_loop(iface: WireInterface, is_debug_session=False):
    global CHANNELS
    global _BUFFER
    CHANNELS = load_cached_channels(_BUFFER)

    read = loop.wait(iface.iface_num() | io.POLL_READ)

    while True:
        try:
            if __debug__:
                log.debug(__name__, "thp_main_loop")
            packet = await read
            ctrl_byte, cid = ustruct.unpack(">BH", packet)

            if ctrl_byte == CODEC_V1:
                pass
                # TODO add handling of (unsupported) codec_v1 packets
                # possibly ignore continuation packets, i.e. if the
                # following bytes are not "##"", do not respond

            if cid == BROADCAST_CHANNEL_ID:
                await _handle_broadcast(iface, ctrl_byte, packet)
                continue

            if cid in CHANNELS:
                channel = CHANNELS[cid]
                if channel is None:
                    # TODO send error message to wire
                    raise ThpError("Invalid state of a channel")
                if channel.iface is not iface:
                    # TODO send error message to wire
                    raise ThpError("Channel has different WireInterface")

                if channel.get_channel_state() != ChannelState.UNALLOCATED:
                    await channel.receive_packet(packet)
                    continue
            await _handle_unallocated(iface, cid)

        except ThpError as e:
            if __debug__:
                log.exception(__name__, e)

        # TODO add cleaning sequence if no workflow/channel is active (or some condition like that)


async def _handle_broadcast(
    iface: WireInterface, ctrl_byte, packet
) -> MessageWithId | None:
    global _BUFFER
    if ctrl_byte != CHANNEL_ALLOCATION_REQ:
        raise ThpError("Unexpected ctrl_byte in broadcast channel packet")
    if __debug__:
        log.debug(__name__, "Received valid message on broadcast channel ")

    length, nonce = ustruct.unpack(">H8s", packet[3:])
    header = InitHeader(ctrl_byte, BROADCAST_CHANNEL_ID, length)
    payload = _get_buffer_for_payload(length, packet[5:], _MAX_CID_REQ_PAYLOAD_LENGTH)

    if not checksum.is_valid(payload[-4:], header.to_bytes() + payload[:-4]):
        raise ThpError("Checksum is not valid")

    new_channel: Channel = Channel.create_new_channel(iface, _BUFFER)
    cid = int.from_bytes(new_channel.channel_id, "big")
    CHANNELS[cid] = new_channel

    response_data = thp_messages.get_channel_allocation_response(
        nonce, new_channel.channel_id
    )
    response_header = InitHeader.get_channel_allocation_response_header(
        len(response_data) + CHECKSUM_LENGTH,
    )
    chksum = checksum.compute(response_header.to_bytes() + response_data)
    if __debug__:
        log.debug(__name__, "New channel allocated with id %d", cid)

    await write_payload_to_wire(iface, response_header, response_data + chksum)


async def _handle_unallocated(iface, cid) -> MessageWithId | None:
    data = thp_messages.get_error_unallocated_channel()
    header = InitHeader.get_error_header(cid, len(data) + CHECKSUM_LENGTH)
    chksum = checksum.compute(header.to_bytes() + data)
    await write_payload_to_wire(iface, header, data + chksum)


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
        payload = bytearray(REPORT_LENGTH)
        raise ThpError("Message too large")
    return payload


def _reuse_existing_buffer(
    payload_length: int, existing_buffer: utils.BufferType
) -> utils.BufferType:
    return memoryview(existing_buffer)[:payload_length]


async def deprecated_read_message(
    iface: WireInterface, buffer: utils.BufferType
) -> MessageWithId:
    return MessageWithId(-1, b"\x00")


async def deprecated_write_message(
    iface: WireInterface, message: MessageWithId, is_retransmission: bool = False
) -> None:
    pass
