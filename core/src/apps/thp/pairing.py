from typing import TYPE_CHECKING

from trezor import protobuf
from trezor.crypto.hashlib import sha256
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
    ThpNfcUnidirectionalSecret,
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

if __debug__:
    from trezor import log

if TYPE_CHECKING:
    from typing import Any, Callable, Concatenate, ParamSpec, Tuple

    P = ParamSpec("P")
    FuncWithContext = Callable[Concatenate[PairingContext, P], Any]


# Helpers - decorators


def check_state_and_log(
    *allowed_states: ChannelState,
) -> Callable[[FuncWithContext], FuncWithContext]:
    def decorator(f: FuncWithContext) -> FuncWithContext:
        def inner(context: PairingContext, *args: P.args, **kwargs: P.kwargs) -> object:
            _check_state(context, *allowed_states)
            if __debug__:
                try:
                    log.debug(__name__, "started %s", f.__name__)
                except AttributeError:
                    log.debug(
                        __name__,
                        "started a function that cannot be named, because it raises AttributeError, eg. closure",
                    )
            return f(context, *args, **kwargs)

        return inner

    return decorator


def check_method_is_allowed(
    pairing_method: ThpPairingMethod,
) -> Callable[[FuncWithContext], FuncWithContext]:
    def decorator(f: FuncWithContext) -> FuncWithContext:
        def inner(context: PairingContext, *args: P.args, **kwargs: P.kwargs) -> object:
            _check_method_is_allowed(context, pairing_method)
            return f(context, *args, **kwargs)

        return inner

    return decorator


# Pairing handlers


@check_state_and_log(ChannelState.TP1)
async def handle_pairing_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:

    if not ThpStartPairingRequest.is_type_of(message):
        raise UnexpectedMessage("Unexpected message")

    await _prepare_pairing(ctx)
    ctx.display_data.show()

    ctx.channel_ctx.set_channel_state(ChannelState.TP3)
    response = await ctx.call_any(
        ThpPairingPreparationsFinished(), *_get_possible_pairing_methods(ctx)
    )
    # TODO disable NFC (if enabled)
    response = await _handle_different_pairing_methods(ctx, response)

    while ThpCredentialRequest.is_type_of(response):
        response = await _handle_credential_request(ctx, response)

    return await _handle_end_request(ctx, response)


async def _prepare_pairing(ctx: PairingContext) -> None:

    if _is_method_included(ctx, ThpPairingMethod.PairingMethod_CodeEntry):
        await _handle_code_entry_is_included(ctx)

    if _is_method_included(ctx, ThpPairingMethod.PairingMethod_QrCode):
        _handle_qr_code_is_included(ctx)

    if _is_method_included(ctx, ThpPairingMethod.PairingMethod_NFC_Unidirectional):
        _handle_nfc_unidirectional_is_included(ctx)


@check_state_and_log(ChannelState.TP1)
async def _handle_code_entry_is_included(ctx: PairingContext) -> None:
    commitment = sha256(ctx.secret).digest()

    challenge_message = await ctx.call(  # noqa: F841
        ThpCodeEntryCommitment(commitment=commitment), ThpCodeEntryChallenge
    )
    ctx.channel_ctx.set_channel_state(ChannelState.TP2)

    _check_code_entry_challenge_message_is_valid(challenge_message)

    if TYPE_CHECKING:
        assert isinstance(challenge_message, ThpCodeEntryChallenge)

    # response.challenge is not None as it is checked within _check_code_entry_challenge_message
    code_code_entry_hash = sha256(
        challenge_message.challenge
        or b"" + ctx.secret + bytes("PairingMethod_CodeEntry", "utf-8")
    ).digest()  # TODO add handshake hash
    ctx.display_data.code_code_entry = (
        int.from_bytes(code_code_entry_hash, "big") % 1000000
    )
    print("code_code_entry", ctx.display_data.code_code_entry)
    ctx.display_data.display_code_entry = True


@check_state_and_log(ChannelState.TP1, ChannelState.TP2)
def _handle_qr_code_is_included(ctx: PairingContext) -> None:
    ctx.display_data.code_qr_code = sha256(
        ctx.secret + bytes("PairingMethod_QrCode", "utf-8")
    ).digest()[
        :16
    ]  # TODO add handshake hash
    ctx.display_data.display_qr_code = True


@check_state_and_log(ChannelState.TP1, ChannelState.TP2)
def _handle_nfc_unidirectional_is_included(ctx: PairingContext) -> None:
    ctx.display_data.code_nfc_unidirectional = sha256(
        ctx.secret + bytes("PairingMethod_NfcUnidirectional", "utf-8")
    ).digest()[
        :16
    ]  # TODO add handshake hash
    ctx.display_data.display_nfc_unidirectional = True


@check_state_and_log(ChannelState.TP3)
async def _handle_different_pairing_methods(
    ctx: PairingContext, response: protobuf.MessageType
) -> protobuf.MessageType:  # TODO change
    if ThpCodeEntryCpaceHost.is_type_of(response):
        return await _handle_code_entry_cpace(ctx, response)
    if ThpQrCodeTag.is_type_of(response):
        return await _handle_qr_code_tag(ctx, response)
    if ThpNfcUnidirectionalTag.is_type_of(response):
        return await _handle_nfc_unidirectional_tag(ctx, response)
    raise UnexpectedMessage("Unexpected message")


@check_state_and_log(ChannelState.TP3)
@check_method_is_allowed(ThpPairingMethod.PairingMethod_CodeEntry)
async def _handle_code_entry_cpace(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    from trezor.wire.thp.cpace import Cpace

    # TODO check that ThpCodeEntryCpaceHost message is valid

    if TYPE_CHECKING:
        assert isinstance(message, ThpCodeEntryCpaceHost)
    if message.cpace_host_public_key is None:
        raise ThpError("Message ThpCodeEntryCpaceHost has no public key")

    ctx.cpace = Cpace(message.cpace_host_public_key)
    assert ctx.display_data.code_code_entry is not None
    ctx.cpace.generate_keys_and_secret(
        ctx.display_data.code_code_entry.to_bytes(6, "big")
    )

    ctx.channel_ctx.set_channel_state(ChannelState.TP4)
    response = await ctx.call(
        ThpCodeEntryCpaceTrezor(cpace_trezor_public_key=ctx.cpace.trezor_public_key),
        ThpCodeEntryTag,
    )
    return await _handle_code_entry_tag(ctx, response)


@check_state_and_log(ChannelState.TP4)
@check_method_is_allowed(ThpPairingMethod.PairingMethod_CodeEntry)
async def _handle_code_entry_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:

    if TYPE_CHECKING:
        assert isinstance(message, ThpCodeEntryTag)

    expected_tag = sha256(ctx.cpace.shared_secret).digest()
    if expected_tag != message.tag:
        raise ThpError("Unexpected Entry Code Tag")

    return await _handle_secret_reveal(
        ctx,
        msg=ThpCodeEntrySecret(secret=ctx.secret),
    )


@check_state_and_log(ChannelState.TP3)
@check_method_is_allowed(ThpPairingMethod.PairingMethod_QrCode)
async def _handle_qr_code_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    if TYPE_CHECKING:
        assert isinstance(message, ThpQrCodeTag)
    expected_tag = sha256(ctx.display_data.code_qr_code).digest()
    if expected_tag != message.tag:

        raise ThpError("Unexpected QR Code Tag")

    return await _handle_secret_reveal(
        ctx,
        msg=ThpQrCodeSecret(secret=ctx.secret),
    )


@check_state_and_log(ChannelState.TP3)
@check_method_is_allowed(ThpPairingMethod.PairingMethod_NFC_Unidirectional)
async def _handle_nfc_unidirectional_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    if TYPE_CHECKING:
        assert isinstance(message, ThpNfcUnidirectionalTag)

    expected_tag = sha256(ctx.display_data.code_nfc_unidirectional).digest()
    if expected_tag != message.tag:
        raise ThpError("Unexpected NFC Unidirectional Tag")

    return await _handle_secret_reveal(
        ctx,
        msg=ThpNfcUnidirectionalSecret(secret=ctx.secret),
    )


@check_state_and_log(ChannelState.TP3, ChannelState.TP4)
async def _handle_secret_reveal(
    ctx: PairingContext,
    msg: protobuf.MessageType,
) -> protobuf.MessageType:
    ctx.channel_ctx.set_channel_state(ChannelState.TC1)
    return await ctx.call_any(
        msg,
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )


@check_state_and_log(ChannelState.TC1)
async def _handle_credential_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:

    return await ctx.call_any(
        ThpCredentialResponse(),  # TODO provide public key and credential
        MessageType.ThpCredentialRequest,
        MessageType.ThpEndRequest,
    )


@check_state_and_log(ChannelState.TC1)
async def _handle_end_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    if not ThpEndRequest.is_type_of(message):
        raise UnexpectedMessage("Unexcpected message")

    ctx.channel_ctx.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
    return ThpEndResponse()


#
# Helpers - checkers


def _check_code_entry_challenge_message_is_valid(
    message: protobuf.MessageType,
):
    if not ThpCodeEntryChallenge.is_type_of(message):
        raise UnexpectedMessage("Unexpected message")
    if message.challenge is None:
        raise Exception("Invalid message")  # TODO change failure type


def _check_state(ctx: PairingContext, *allowed_states: ChannelState) -> None:
    if ctx.channel_ctx.get_channel_state() not in allowed_states:
        raise UnexpectedMessage("Unexpected message")


def _check_method_is_allowed(ctx: PairingContext, method: ThpPairingMethod) -> None:
    if not _is_method_included(ctx, method):
        raise ThpError("Unexpected pairing method")


def _is_method_included(ctx: PairingContext, method: ThpPairingMethod) -> bool:
    return method in ctx.channel_ctx.selected_pairing_methods


#
# Helpers - getters


def _get_possible_pairing_methods(ctx: PairingContext) -> Tuple[int, ...]:
    return tuple(
        _get_message_type_for_method(method)
        for method in ctx.channel_ctx.selected_pairing_methods
    )


def _get_message_type_for_method(method: int) -> int:
    if method is ThpPairingMethod.PairingMethod_CodeEntry:
        return MessageType.ThpCodeEntryCpaceHost
    if method is ThpPairingMethod.PairingMethod_NFC_Unidirectional:
        return MessageType.ThpNfcUnidirectionalTag
    if method is ThpPairingMethod.PairingMethod_QrCode:
        return MessageType.ThpQrCodeTag
    raise ValueError("Unexpected pairing method - no message type available")
