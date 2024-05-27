import ustruct  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING

from storage import cache_thp
from storage.cache_thp import KEY_LENGTH, SESSION_ID_LENGTH, TAG_LENGTH
from trezor import log, loop, protobuf, utils
from trezor.enums import FailureType
from trezor.messages import GetFeatures, ThpCreateNewSession

from .. import message_handler
from ..errors import DataError
from ..protocol_common import MessageWithType
from . import ChannelState, SessionState, ThpError
from . import alternating_bit_protocol as ABP
from . import checksum, control_byte, is_channel_state_pairing, thp_messages
from .checksum import CHECKSUM_LENGTH
from .credential_manager import validate_credential
from .crypto import PUBKEY_LENGTH
from .thp_messages import (
    ACK_MESSAGE,
    HANDSHAKE_COMP_RES,
    HANDSHAKE_INIT_RES,
    InitHeader,
)
from .writer import INIT_DATA_OFFSET, MESSAGE_TYPE_LENGTH, write_payload_to_wire

if TYPE_CHECKING:
    from trezor.messages import ThpHandshakeCompletionReqNoisePayload

    from .channel import Channel

if __debug__:
    from trezor.messages import LoadDevice

    from . import state_to_str


async def handle_received_message(
    ctx: Channel, message_buffer: utils.BufferType
) -> None:
    """Handle a message received from the channel."""

    if __debug__:
        log.debug(__name__, "handle_received_message")
    ctrl_byte, _, payload_length = ustruct.unpack(">BHH", message_buffer)
    message_length = payload_length + INIT_DATA_OFFSET

    _check_checksum(message_length, message_buffer)

    # Synchronization process
    seq_bit = (ctrl_byte & 0x10) >> 4
    ack_bit = (ctrl_byte & 0x08) >> 3
    if __debug__:
        log.debug(
            __name__,
            "handle_completed_message - seq bit of message: %d, ack bit of message: %d",
            seq_bit,
            ack_bit,
        )

    # 1: Handle ACKs
    if control_byte.is_ack(ctrl_byte):
        await _handle_ack(ctx, ack_bit)
        return

    if _should_have_ctrl_byte_encrypted_transport(
        ctx
    ) and not control_byte.is_encrypted_transport(ctrl_byte):
        raise ThpError("Message is not encrypted. Ignoring")

    # 2: Handle message with unexpected sequential bit
    if seq_bit != ABP.get_expected_receive_seq_bit(ctx.channel_cache):
        if __debug__:
            log.debug(__name__, "Received message with an unexpected sequential bit")
        await _send_ack(ctx, ack_bit=seq_bit)
        raise ThpError("Received message with an unexpected sequential bit")

    # 3: Send ACK in response
    await _send_ack(ctx, ack_bit=seq_bit)

    ABP.set_expected_receive_seq_bit(ctx.channel_cache, 1 - seq_bit)

    await _handle_message_to_app_or_channel(
        ctx, payload_length, message_length, ctrl_byte
    )
    if __debug__:
        log.debug(__name__, "handle_received_message - end")


async def _send_ack(ctx: Channel, ack_bit: int) -> None:
    ctrl_byte = control_byte.add_ack_bit_to_ctrl_byte(ACK_MESSAGE, ack_bit)
    header = InitHeader(ctrl_byte, ctx.get_channel_id_int(), CHECKSUM_LENGTH)
    chksum = checksum.compute(header.to_bytes())
    if __debug__:
        log.debug(
            __name__,
            "Writing ACK message to a channel with id: %d, ack_bit: %d",
            ctx.get_channel_id_int(),
            ack_bit,
        )
    await write_payload_to_wire(ctx.iface, header, chksum)


def _check_checksum(message_length: int, message_buffer: utils.BufferType):
    if __debug__:
        log.debug(__name__, "check_checksum")
    if not checksum.is_valid(
        checksum=message_buffer[message_length - CHECKSUM_LENGTH : message_length],
        data=message_buffer[: message_length - CHECKSUM_LENGTH],
    ):
        if __debug__:
            log.debug(__name__, "Invalid checksum, ignoring message.")
        raise ThpError("Invalid checksum, ignoring message.")


# TEST THIS


async def _handle_ack(ctx: Channel, ack_bit: int):
    if not ABP.is_ack_valid(ctx.channel_cache, ack_bit):
        return
    # ACK is expected and it has correct sync bit
    if __debug__:
        log.debug(__name__, "Received ACK message with correct ack bit")
    if ctx.transmission_loop is not None:
        ctx.transmission_loop.stop_immediately()
        if __debug__:
            log.debug(__name__, "Stopped transmission loop")

    ABP.set_sending_allowed(ctx.channel_cache, True)

    if ctx.write_task_spawn is not None:
        if __debug__:
            log.debug(__name__, 'Control to "write_encrypted_payload_loop" task')
        await ctx.write_task_spawn
        # Note that no the write_task_spawn could result in loop.clear(),
        # which will result in terminations of this function - any code after
        # this await might not be executed


async def _handle_message_to_app_or_channel(
    ctx: Channel,
    payload_length: int,
    message_length: int,
    ctrl_byte: int,
) -> None:
    state = ctx.get_channel_state()
    if __debug__:
        log.debug(__name__, "state: %s", state_to_str(state))

    if state is ChannelState.ENCRYPTED_TRANSPORT:
        await _handle_state_ENCRYPTED_TRANSPORT(ctx, message_length)
        return

    if state is ChannelState.TH1:
        await _handle_state_TH1(ctx, payload_length, message_length, ctrl_byte)
        return

    if state is ChannelState.TH2:
        await _handle_state_TH2(ctx, message_length, ctrl_byte)
        return

    if is_channel_state_pairing(state):
        await _handle_pairing(ctx, message_length)
        return

    raise ThpError("Unimplemented channel state")


async def _handle_state_TH1(
    ctx: Channel,
    payload_length: int,
    message_length: int,
    ctrl_byte: int,
) -> None:
    if __debug__:
        log.debug(__name__, "handle_state_TH1")
    if not control_byte.is_handshake_init_req(ctrl_byte):
        raise ThpError("Message received is not a handshake init request!")
    if not payload_length == PUBKEY_LENGTH + CHECKSUM_LENGTH:
        raise ThpError("Message received is not a valid handshake init request!")
    host_ephemeral_key = bytearray(
        ctx.buffer[INIT_DATA_OFFSET : message_length - CHECKSUM_LENGTH]
    )
    cache_thp.set_channel_host_ephemeral_key(ctx.channel_cache, host_ephemeral_key)

    # send handshake init response message
    await ctx.write_handshake_message(
        HANDSHAKE_INIT_RES, thp_messages.get_handshake_init_response()
    )
    ctx.set_channel_state(ChannelState.TH2)
    return


async def _handle_state_TH2(ctx: Channel, message_length: int, ctrl_byte: int) -> None:
    if __debug__:
        log.debug(__name__, "handle_state_TH2")
    if not control_byte.is_handshake_comp_req(ctrl_byte):
        raise ThpError("Message received is not a handshake completion request!")
    host_encrypted_static_pubkey = ctx.buffer[
        INIT_DATA_OFFSET : INIT_DATA_OFFSET + KEY_LENGTH + TAG_LENGTH
    ]
    handshake_completion_request_noise_payload = ctx.buffer[
        INIT_DATA_OFFSET + KEY_LENGTH + TAG_LENGTH : message_length - CHECKSUM_LENGTH
    ]

    noise_payload = thp_messages.decode_message(
        ctx.buffer[
            INIT_DATA_OFFSET
            + KEY_LENGTH
            + TAG_LENGTH : message_length
            - CHECKSUM_LENGTH
            - TAG_LENGTH
        ],
        0,
        "ThpHandshakeCompletionReqNoisePayload",
    )
    if TYPE_CHECKING:
        assert ThpHandshakeCompletionReqNoisePayload.is_type_of(noise_payload)
    for i in noise_payload.pairing_methods:
        ctx.selected_pairing_methods.append(i)
    if __debug__:
        log.debug(
            __name__,
            "host static pubkey: %s, noise payload: %s",
            utils.get_bytes_as_str(host_encrypted_static_pubkey),
            utils.get_bytes_as_str(handshake_completion_request_noise_payload),
        )
    host_static_pubkey = host_encrypted_static_pubkey  # TODO add decoding

    paired: bool = False

    if noise_payload.host_pairing_credential is not None:
        try:  # TODO change try-except for something better
            paired = validate_credential(
                noise_payload.host_pairing_credential,
                host_static_pubkey,
            )
        except DataError as e:
            if __debug__:
                log.exception(__name__, e)
            pass

    # send hanshake completion response
    await ctx.write_handshake_message(
        HANDSHAKE_COMP_RES,
        thp_messages.get_handshake_completion_response(paired),
    )
    if paired:
        ctx.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
    else:
        ctx.set_channel_state(ChannelState.TP1)


async def _handle_state_ENCRYPTED_TRANSPORT(ctx: Channel, message_length: int) -> None:
    if __debug__:
        log.debug(__name__, "handle_state_ENCRYPTED_TRANSPORT")

    ctx.decrypt_buffer(message_length)
    session_id, message_type = ustruct.unpack(">BH", ctx.buffer[INIT_DATA_OFFSET:])
    if session_id not in ctx.sessions:
        await ctx.write_error(FailureType.ThpUnallocatedSession, "Unallocated session")
        raise ThpError("Unalloacted session")

    session_state = ctx.sessions[session_id].get_session_state()
    if session_state is SessionState.UNALLOCATED:
        await ctx.write_error(FailureType.ThpUnallocatedSession, "Unallocated session")
        raise ThpError("Unalloacted session")
    ctx.sessions[session_id].incoming_message.publish(
        MessageWithType(
            message_type,
            ctx.buffer[
                INIT_DATA_OFFSET
                + MESSAGE_TYPE_LENGTH
                + SESSION_ID_LENGTH : message_length
                - CHECKSUM_LENGTH
                - TAG_LENGTH
            ],
        )
    )


async def _handle_pairing(ctx: Channel, message_length: int) -> None:
    from .pairing_context import PairingContext

    if ctx.connection_context is None:
        ctx.connection_context = PairingContext(ctx)
        loop.schedule(ctx.connection_context.handle())

    ctx.decrypt_buffer(message_length)
    message_type = ustruct.unpack(
        ">H", ctx.buffer[INIT_DATA_OFFSET + SESSION_ID_LENGTH :]
    )[0]

    ctx.connection_context.incoming_message.publish(
        MessageWithType(
            message_type,
            ctx.buffer[
                INIT_DATA_OFFSET
                + MESSAGE_TYPE_LENGTH
                + SESSION_ID_LENGTH : message_length
                - CHECKSUM_LENGTH
                - TAG_LENGTH
            ],
        )
    )


def _should_have_ctrl_byte_encrypted_transport(ctx: Channel) -> bool:
    if ctx.get_channel_state() in [
        ChannelState.UNALLOCATED,
        ChannelState.TH1,
        ChannelState.TH2,
    ]:
        return False
    return True


async def _handle_channel_message(
    ctx: Channel, message_length: int, message_type: int
) -> None:
    buf = ctx.buffer[
        INIT_DATA_OFFSET + 3 : message_length - CHECKSUM_LENGTH - TAG_LENGTH
    ]

    expected_type = protobuf.type_for_wire(message_type)
    message = message_handler.wrap_protobuf_load(buf, expected_type)

    if not _is_channel_message(message):
        raise ThpError(
            "The received message cannot be handled by channel itself. It must be sent to allocated session."
        )
    # TODO handle other messages than CreateNewSession
    from trezor.wire.thp.handler_provider import get_handler_for_channel_message

    handler = get_handler_for_channel_message(message)
    task = handler(ctx, message)
    response_message = await task
    # TODO handle
    await ctx.write(response_message)
    if __debug__:
        log.debug(__name__, "_handle_channel_message - end")


def _is_channel_message(message) -> bool:
    channel_messages = [ThpCreateNewSession, GetFeatures]
    if __debug__:
        channel_messages.append(LoadDevice)

    for channel_message in channel_messages:
        if channel_message.is_type_of(message):
            return True
    return False
