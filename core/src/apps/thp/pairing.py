from trezor import log, protobuf
from trezor.enums import MessageType, ThpPairingMethod
from trezor.messages import (
    ThpCodeEntryChallenge,
    ThpCodeEntryCommitment,
    ThpCodeEntryCpaceHost,
    ThpCodeEntryCpaceTrezor,
    ThpCodeEntrySecret,
    ThpCodeEntryTag,
    ThpCredentialRequest,
    ThpCredentialResponse,
    ThpEndRequest,
    ThpEndResponse,
    ThpNfcUnideirectionalSecret,
    ThpNfcUnidirectionalTag,
    ThpPairingPreparationsFinished,
    ThpQrCodeSecret,
    ThpQrCodeTag,
    ThpStartPairingRequest,
)
from trezor.wire import context
from trezor.wire.errors import UnexpectedMessage
from trezor.wire.thp import ChannelState
from trezor.wire.thp.pairing_context import PairingContext
from trezor.wire.thp.thp_session import ThpError

# TODO implement the following handlers


async def handle_pairing_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpStartPairingRequest.is_type_of(message)

    if __debug__:
        log.debug(__name__, "handle_pairing_request")
    _check_state(ctx, ChannelState.TP1)

    if _is_method_included(ctx, ThpPairingMethod.PairingMethod_CodeEntry):
        ctx.channel.set_channel_state(ChannelState.TP2)
        await context.call(ThpCodeEntryCommitment(), ThpCodeEntryChallenge)

    ctx.channel.set_channel_state(ChannelState.TP3)
    await context.call_any(
        ThpPairingPreparationsFinished(),
        MessageType.ThpQrCodeTag,
        MessageType.ThpNfcUnidirectionalTag,
    )


async def handle_code_entry_challenge(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpCodeEntryChallenge.is_type_of(message)

    _check_state(ctx, ChannelState.TP2)
    ctx.channel.set_channel_state(ChannelState.TP3)
    await context.call_any(
        ThpPairingPreparationsFinished(),
        MessageType.ThpCodeEntryCpaceHost,
        MessageType.ThpQrCodeTag,
        MessageType.ThpNfcUnidirectionalTag,
    )


async def handle_code_entry_cpace(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpCodeEntryCpaceHost.is_type_of(message)

    _check_state(ctx, ChannelState.TP3)
    _check_method_is_allowed(ctx, ThpPairingMethod.PairingMethod_CodeEntry)
    ctx.channel.set_channel_state(ChannelState.TP4)
    await context.call(ThpCodeEntryCpaceTrezor(), ThpCodeEntryTag)


async def handle_code_entry_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpCodeEntryTag.is_type_of(message)

    _check_state(ctx, ChannelState.TP4)
    ctx.channel.set_channel_state(ChannelState.TC1)
    await context.call_any(
        ThpCodeEntrySecret(),
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )


async def handle_qr_code_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpQrCodeTag.is_type_of(message)

    _check_state(ctx, ChannelState.TP3)
    _check_method_is_allowed(ctx, ThpPairingMethod.PairingMethod_QrCode)
    ctx.channel.set_channel_state(ChannelState.TC1)
    await context.call_any(
        ThpQrCodeSecret(),
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )


async def handle_nfc_unidirectional_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpNfcUnidirectionalTag.is_type_of(message)

    _check_state(ctx, ChannelState.TP3)
    _check_method_is_allowed(ctx, ThpPairingMethod.PairingMethod_NFC_Unidirectional)
    ctx.channel.set_channel_state(ChannelState.TC1)
    await context.call_any(
        ThpNfcUnideirectionalSecret(),
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )


async def handle_credential_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> None:
    assert ThpCredentialRequest.is_type_of(message)

    _check_state(ctx, ChannelState.TC1)
    await context.call_any(
        ThpCredentialResponse(),
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )


async def handle_end_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpEndRequest.is_type_of(message)

    _check_state(ctx, ChannelState.TC1)
    ctx.channel.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
    return ThpEndResponse()


def _check_state(ctx: PairingContext, expected_state: ChannelState) -> None:
    if expected_state is not ctx.channel.get_channel_state():
        raise UnexpectedMessage("Unexpected message")


def _check_method_is_allowed(ctx: PairingContext, method: ThpPairingMethod) -> None:
    if not _is_method_included(ctx, method):
        raise ThpError("Unexpected pairing method")


def _is_method_included(ctx: PairingContext, method: ThpPairingMethod) -> bool:
    return method in ctx.channel.selected_pairing_methods
