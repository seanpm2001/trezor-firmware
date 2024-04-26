import ustruct  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING

from storage import cache_thp
from storage.cache_thp import KEY_LENGTH, SESSION_ID_LENGTH, TAG_LENGTH
from trezor import log, loop, protobuf, utils
from trezor.enums import FailureType
from trezor.messages import ThpCreateNewSession
from trezor.wire import message_handler
from trezor.wire.protocol_common import MessageWithType
from trezor.wire.thp import ack_handler, thp_messages
from trezor.wire.thp.checksum import CHECKSUM_LENGTH
from trezor.wire.thp.crypto import PUBKEY_LENGTH
from trezor.wire.thp.thp_messages import (
    ACK_MESSAGE,
    HANDSHAKE_COMP_RES,
    HANDSHAKE_INIT_RES,
    InitHeader,
)

from . import (
    ChannelState,
    SessionState,
    checksum,
    control_byte,
    is_channel_state_pairing,
)
from . import thp_session as THP
from .thp_session import ThpError
from .writer import INIT_DATA_OFFSET, MESSAGE_TYPE_LENGTH, write_payload_to_wire

if TYPE_CHECKING:
    from trezor.messages import ThpHandshakeCompletionReqNoisePayload

    from . import ChannelContext

if __debug__:
    from . import state_to_str


async def handle_received_message(
    ctx: ChannelContext, message_buffer: utils.BufferType
) -> None:
    """Handle a message received from the channel."""

    if __debug__:
        log.debug(__name__, "handle_received_message")
    ctrl_byte, _, payload_length = ustruct.unpack(">BHH", message_buffer)
    message_length = payload_length + INIT_DATA_OFFSET

    _check_checksum(message_length, message_buffer)

    # Synchronization process
    sync_bit = (ctrl_byte & 0x10) >> 4
    if __debug__:
        log.debug(
            __name__,
            "handle_completed_message - sync bit of message: %d",
            sync_bit,
        )

    # 1: Handle ACKs
    if control_byte.is_ack(ctrl_byte):
        await _handle_ack(ctx, sync_bit)
        return

    if _should_have_ctrl_byte_encrypted_transport(
        ctx
    ) and not control_byte.is_encrypted_transport(ctrl_byte):
        raise ThpError("Message is not encrypted. Ignoring")

    # 2: Handle message with unexpected synchronization bit
    if sync_bit != THP.sync_get_receive_expected_bit(ctx.channel_cache):
        if __debug__:
            log.debug(
                __name__, "Received message with an unexpected synchronization bit"
            )
        await _send_ack(ctx, sync_bit)
        raise ThpError("Received message with an unexpected synchronization bit")

    # 3: Send ACK in response
    await _send_ack(ctx, sync_bit)

    THP.sync_set_receive_expected_bit(ctx.channel_cache, 1 - sync_bit)

    await _handle_message_to_app_or_channel(
        ctx, payload_length, message_length, ctrl_byte, sync_bit
    )
    if __debug__:
        log.debug(__name__, "handle_received_message - end")


async def _send_ack(ctx: ChannelContext, ack_bit: int) -> None:
    ctrl_byte = control_byte.add_sync_bit_to_ctrl_byte(ACK_MESSAGE, ack_bit)
    header = InitHeader(ctrl_byte, ctx.get_channel_id_int(), CHECKSUM_LENGTH)
    chksum = checksum.compute(header.to_bytes())
    if __debug__:
        log.debug(
            __name__,
            "Writing ACK message to a channel with id: %d, sync bit: %d",
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


async def _handle_ack(ctx: ChannelContext, sync_bit: int):
    if not ack_handler.is_ack_valid(ctx.channel_cache, sync_bit):
        return
    # ACK is expected and it has correct sync bit
    if __debug__:
        log.debug(__name__, "Received ACK message with correct sync bit")
    if ctx.waiting_for_ack_timeout is not None:
        ctx.waiting_for_ack_timeout.close()
        if __debug__:
            log.debug(__name__, 'Closed "waiting for ack" task')

    THP.sync_set_can_send_message(ctx.channel_cache, True)

    if ctx.write_task_spawn is not None:
        if __debug__:
            log.debug(__name__, 'Control to "write_encrypted_payload_loop" task')
        await ctx.write_task_spawn
        # Note that no the write_task_spawn could result in loop.clear(),
        # which will result in terminations of this function - any code after
        # this await might not be executed


async def _handle_message_to_app_or_channel(
    ctx: ChannelContext,
    payload_length: int,
    message_length: int,
    ctrl_byte: int,
    sync_bit: int,
) -> None:
    state = ctx.get_channel_state()
    if __debug__:
        log.debug(__name__, "state: %s", state_to_str(state))

    if state is ChannelState.ENCRYPTED_TRANSPORT:
        await _handle_state_ENCRYPTED_TRANSPORT(ctx, message_length)
        return

    if state is ChannelState.TH1:
        await _handle_state_TH1(
            ctx, payload_length, message_length, ctrl_byte, sync_bit
        )
        return

    if state is ChannelState.TH2:
        await _handle_state_TH2(ctx, message_length, ctrl_byte, sync_bit)
        return

    if is_channel_state_pairing(state):
        await _handle_pairing(ctx, message_length)
        return

    raise ThpError("Unimplemented channel state")


async def _handle_state_TH1(
    ctx: ChannelContext,
    payload_length: int,
    message_length: int,
    ctrl_byte: int,
    sync_bit: int,
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


async def _handle_state_TH2(
    ctx: ChannelContext, message_length: int, ctrl_byte: int, sync_bit: int
) -> None:
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

    # TODO add credential recognition
    paired: bool = True  # TODO should be output from credential check

    # send hanshake completion response
    await ctx.write_handshake_message(
        HANDSHAKE_COMP_RES,
        thp_messages.get_handshake_completion_response(paired),
    )
    if paired:
        ctx.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
    else:
        ctx.set_channel_state(ChannelState.TP1)


async def _handle_state_ENCRYPTED_TRANSPORT(
    ctx: ChannelContext, message_length: int
) -> None:
    if __debug__:
        log.debug(__name__, "handle_state_ENCRYPTED_TRANSPORT")

    ctx.decrypt_buffer(message_length)
    session_id, message_type = ustruct.unpack(">BH", ctx.buffer[INIT_DATA_OFFSET:])
    if session_id == 0:
        await _handle_channel_message(ctx, message_length, message_type)
        return
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


async def _handle_pairing(ctx: ChannelContext, message_length: int) -> None:

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
    # 1. Check that message is expected with respect to the current state
    # 2. Handle the message
    pass


def _should_have_ctrl_byte_encrypted_transport(ctx: ChannelContext) -> bool:
    if ctx.get_channel_state() in [
        ChannelState.UNALLOCATED,
        ChannelState.TH1,
        ChannelState.TH2,
    ]:
        return False
    return True


async def _handle_channel_message(
    ctx: ChannelContext, message_length: int, message_type: int
) -> None:
    buf = ctx.buffer[
        INIT_DATA_OFFSET + 3 : message_length - CHECKSUM_LENGTH - TAG_LENGTH
    ]

    expected_type = protobuf.type_for_wire(message_type)
    message = message_handler.wrap_protobuf_load(buf, expected_type)

    if not ThpCreateNewSession.is_type_of(message):
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
