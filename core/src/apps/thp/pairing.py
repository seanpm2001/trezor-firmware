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
from trezor.wire.errors import UnexpectedMessage
from trezor.wire.thp import ChannelState
from trezor.wire.thp.pairing_context import PairingContext
from trezor.wire.thp.thp_session import ThpError

# TODO implement the following handlers


async def handle_pairing_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpStartPairingRequest.is_type_of(message)

    if __debug__:
        log.debug(__name__, "handle_pairing_request")

    _check_state(ctx, ChannelState.TP1)

    if _is_method_included(ctx, ThpPairingMethod.PairingMethod_CodeEntry):
        ctx.channel.set_channel_state(ChannelState.TP2)

        response = await ctx.call(ThpCodeEntryCommitment(), ThpCodeEntryChallenge)
        return await _handle_code_entry_challenge(ctx, response)

    ctx.channel.set_channel_state(ChannelState.TP3)
    response = await ctx.call_any(
        ThpPairingPreparationsFinished(),
        MessageType.ThpQrCodeTag,
        MessageType.ThpNfcUnidirectionalTag,
    )
    if ThpQrCodeTag.is_type_of(response):
        return await _handle_qr_code_tag(ctx, response)
    if ThpNfcUnidirectionalTag.is_type_of(response):
        return await _handle_nfc_unidirectional_tag(ctx, response)
    raise Exception(
        "TODO Change this exception message and type. This exception should result in channel destruction."
    )


async def _handle_code_entry_challenge(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpCodeEntryChallenge.is_type_of(message)

    _check_state(ctx, ChannelState.TP2)
    ctx.channel.set_channel_state(ChannelState.TP3)
    response = await ctx.call_any(
        ThpPairingPreparationsFinished(),
        MessageType.ThpCodeEntryCpaceHost,
        MessageType.ThpQrCodeTag,
        MessageType.ThpNfcUnidirectionalTag,
    )
    if ThpCodeEntryCpaceHost.is_type_of(response):
        return await _handle_code_entry_cpace(ctx, response)
    if ThpQrCodeTag.is_type_of(response):
        return await _handle_qr_code_tag(ctx, response)
    if ThpNfcUnidirectionalTag.is_type_of(response):
        return await _handle_nfc_unidirectional_tag(ctx, response)
    raise Exception(
        "TODO Change this exception message and type. This exception should result in channel destruction."
    )


async def _handle_code_entry_cpace(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpCodeEntryCpaceHost.is_type_of(message)

    _check_state(ctx, ChannelState.TP3)
    _check_method_is_allowed(ctx, ThpPairingMethod.PairingMethod_CodeEntry)
    ctx.channel.set_channel_state(ChannelState.TP4)
    response = await ctx.call(ThpCodeEntryCpaceTrezor(), ThpCodeEntryTag)
    return await _handle_code_entry_tag(ctx, response)


async def _handle_code_entry_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpCodeEntryTag.is_type_of(message)
    return await _handle_tag_message(
        ctx,
        expected_state=ChannelState.TP4,
        used_method=ThpPairingMethod.PairingMethod_CodeEntry,
        msg=ThpCodeEntrySecret(),
    )


async def _handle_qr_code_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpQrCodeTag.is_type_of(message)
    return await _handle_tag_message(
        ctx,
        expected_state=ChannelState.TP3,
        used_method=ThpPairingMethod.PairingMethod_QrCode,
        msg=ThpQrCodeSecret(),
    )


async def _handle_nfc_unidirectional_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpNfcUnidirectionalTag.is_type_of(message)
    return await _handle_tag_message(
        ctx,
        expected_state=ChannelState.TP3,
        used_method=ThpPairingMethod.PairingMethod_NFC_Unidirectional,
        msg=ThpNfcUnideirectionalSecret(),
    )


async def _handle_credential_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpCredentialRequest.is_type_of(message)

    _check_state(ctx, ChannelState.TC1)
    response = await ctx.call_any(
        ThpCredentialResponse(),
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )
    return await _handle_credential_request_or_end_request(ctx, response)


async def _handle_end_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    assert ThpEndRequest.is_type_of(message)

    _check_state(ctx, ChannelState.TC1)
    ctx.channel.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
    return ThpEndResponse()


async def _handle_tag_message(
    ctx: PairingContext,
    expected_state: ChannelState,
    used_method: ThpPairingMethod,
    msg: protobuf.MessageType,
) -> ThpEndResponse:
    _check_state(ctx, expected_state)
    _check_method_is_allowed(ctx, used_method)
    ctx.channel.set_channel_state(ChannelState.TC1)
    response = await ctx.call_any(
        msg,
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )
    return await _handle_credential_request_or_end_request(ctx, response)


def _check_state(ctx: PairingContext, expected_state: ChannelState) -> None:
    if expected_state is not ctx.channel.get_channel_state():
        raise UnexpectedMessage("Unexpected message")


def _check_method_is_allowed(ctx: PairingContext, method: ThpPairingMethod) -> None:
    if not _is_method_included(ctx, method):
        raise ThpError("Unexpected pairing method")


def _is_method_included(ctx: PairingContext, method: ThpPairingMethod) -> bool:
    return method in ctx.channel.selected_pairing_methods


async def _handle_credential_request_or_end_request(
    ctx: PairingContext, response: protobuf.MessageType | None
) -> ThpEndResponse:
    if ThpCredentialRequest.is_type_of(response):
        return await _handle_credential_request(ctx, response)
    if ThpEndRequest.is_type_of(response):
        return await _handle_end_request(ctx, response)
    raise UnexpectedMessage(
        "Received message is not credential request or end request."
    )
