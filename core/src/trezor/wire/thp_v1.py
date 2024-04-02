import ustruct  # pyright: ignore[reportMissingModuleSource]
from micropython import const  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from storage.cache_thp import BROADCAST_CHANNEL_ID
from trezor import io, log, loop, utils

from .protocol_common import MessageWithId
from .thp import ChannelState, checksum, thp_messages
from .thp.channel import (
    CONT_DATA_OFFSET,
    INIT_DATA_OFFSET,
    MAX_PAYLOAD_LEN,
    REPORT_LENGTH,
    Channel,
    load_cached_channels,
)
from .thp.checksum import CHECKSUM_LENGTH
from .thp.thp_messages import CODEC_V1, InitHeader
from .thp.thp_session import ThpError

if TYPE_CHECKING:
    from trezorio import WireInterface  # pyright: ignore[reportMissingImports]

_MAX_CID_REQ_PAYLOAD_LENGTH = const(12)  # TODO set to reasonable value
_CHANNEL_ALLOCATION_REQ = 0x40


_BUFFER: bytearray
_BUFFER_LOCK = None

_CHANNEL_CONTEXTS: dict[int, Channel] = {}


def set_buffer(buffer):
    global _BUFFER
    _BUFFER = buffer


async def thp_main_loop(iface: WireInterface, is_debug_session=False):
    global _CHANNEL_CONTEXTS
    global _BUFFER
    _CHANNEL_CONTEXTS = load_cached_channels(_BUFFER)

    read = loop.wait(iface.iface_num() | io.POLL_READ)

    while True:
        print("main loop")
        packet = await read
        ctrl_byte, cid = ustruct.unpack(">BH", packet)

        if ctrl_byte == CODEC_V1:
            pass
            # TODO add handling of (unsupported) codec_v1 packets
            # possibly ignore continuation packets, i.e. if the
            # following bytes are not "##"", do not respond

        if cid == BROADCAST_CHANNEL_ID:
            # TODO handle exceptions, try-catch?
            await _handle_broadcast(iface, ctrl_byte, packet)
            continue

        if cid in _CHANNEL_CONTEXTS:
            channel = _CHANNEL_CONTEXTS[cid]
            if channel is None:
                raise ThpError("Invalid state of a channel")
            if channel.iface is not iface:
                raise ThpError("Channel has different WireInterface")

            if channel.get_channel_state() != ChannelState.UNALLOCATED:
                print("packet type in loop:", type(packet))
                await channel.receive_packet(packet)
                continue

        await _handle_unallocated(iface, cid)
        # TODO add cleaning sequence if no workflow/channel is active (or some condition like that)


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


async def write_to_wire(
    iface: WireInterface, header: InitHeader, payload: bytes
) -> None:
    loop_write = loop.wait(iface.iface_num() | io.POLL_WRITE)

    payload_length = len(payload)

    # prepare the report buffer with header data
    report = bytearray(REPORT_LENGTH)
    header.pack_to_buffer(report)

    # write initial report
    nwritten = utils.memcpy(report, INIT_DATA_OFFSET, payload, 0)
    await _write_report(loop_write, iface, report)

    # if we have more data to write, use continuation reports for it
    if nwritten < payload_length:
        header.pack_to_cont_buffer(report)

    while nwritten < payload_length:
        nwritten += utils.memcpy(report, CONT_DATA_OFFSET, payload, nwritten)
        await _write_report(loop_write, iface, report)


async def _write_report(write, iface: WireInterface, report: bytearray) -> None:
    while True:
        await write
        n = iface.write(report)
        if n == len(report):
            return


async def _handle_broadcast(
    iface: WireInterface, ctrl_byte, packet
) -> MessageWithId | None:
    global _BUFFER
    if ctrl_byte != _CHANNEL_ALLOCATION_REQ:
        raise ThpError("Unexpected ctrl_byte in broadcast channel packet")
    if __debug__:
        log.debug(__name__, "Received valid message on broadcast channel ")

    length, nonce = ustruct.unpack(">H8s", packet[3:])
    header = InitHeader(ctrl_byte, BROADCAST_CHANNEL_ID, length)
    payload = _get_buffer_for_payload(length, packet[5:], _MAX_CID_REQ_PAYLOAD_LENGTH)

    if not checksum.is_valid(payload[-4:], header.to_bytes() + payload[:-4]):
        raise ThpError("Checksum is not valid")

    new_context: Channel = Channel.create_new_channel(iface, _BUFFER)
    cid = int.from_bytes(new_context.channel_id, "big")
    _CHANNEL_CONTEXTS[cid] = new_context

    response_data = thp_messages.get_channel_allocation_response(
        nonce, new_context.channel_id
    )
    response_header = InitHeader.get_channel_allocation_response_header(
        len(response_data) + CHECKSUM_LENGTH,
    )
    chksum = checksum.compute(response_header.to_bytes() + response_data)
    if __debug__:
        log.debug(__name__, "New channel allocated with id %d", cid)

    await write_to_wire(iface, response_header, response_data + chksum)


async def _handle_unallocated(iface, cid) -> MessageWithId | None:
    data = thp_messages.get_error_unallocated_channel()
    header = InitHeader.get_error_header(cid, len(data) + CHECKSUM_LENGTH)
    chksum = checksum.compute(header.to_bytes() + data)
    await write_to_wire(iface, header, data + chksum)


async def deprecated_read_message(
    iface: WireInterface, buffer: utils.BufferType
) -> MessageWithId:
    return MessageWithId(-1, b"\x00")


async def deprecated_write_message(
    iface: WireInterface, message: MessageWithId, is_retransmission: bool = False
) -> None:
    pass
