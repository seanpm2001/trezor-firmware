from typing import TYPE_CHECKING
from ubinascii import hexlify

from trezor import loop, protobuf
from trezor.crypto.hashlib import sha256
from trezor.enums import ThpMessageType, ThpPairingMethod
from trezor.messages import (
    Cancel,
    ThpCodeEntryChallenge,
    ThpCodeEntryCommitment,
    ThpCodeEntryCpaceHost,
    ThpCodeEntryCpaceTrezor,
    ThpCodeEntrySecret,
    ThpCodeEntryTag,
    ThpCredentialMetadata,
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
from trezor.wire.errors import ActionCancelled, SilentError, UnexpectedMessage
from trezor.wire.thp import ChannelState, ThpError, crypto
from trezor.wire.thp.pairing_context import PairingContext

from .credential_manager import issue_credential

if __debug__:
    from trezor import log

if TYPE_CHECKING:
    from typing import Any, Callable, Concatenate, Container, ParamSpec, Tuple

    P = ParamSpec("P")
    FuncWithContext = Callable[Concatenate[PairingContext, P], Any]

#
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


#
# Pairing handlers


@check_state_and_log(ChannelState.TP1)
async def handle_pairing_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:

    if not ThpStartPairingRequest.is_type_of(message):
        raise UnexpectedMessage("Unexpected message")

    ctx.host_name = message.host_name or ""

    skip_pairing = _is_method_included(ctx, ThpPairingMethod.NoMethod)
    if skip_pairing:
        return await _end_pairing(ctx)

    await _prepare_pairing(ctx)
    await ctx.write(ThpPairingPreparationsFinished())
    ctx.channel_ctx.set_channel_state(ChannelState.TP3)
    response = await show_display_data(
        ctx, _get_possible_pairing_methods_and_cancel(ctx)
    )
    if __debug__:
        from trezor.messages import DebugLinkGetState

        while DebugLinkGetState.is_type_of(response):
            from apps.debug import dispatch_DebugLinkGetState

            dl_state = await dispatch_DebugLinkGetState(response)
            assert dl_state is not None
            await ctx.write(dl_state)
            response = await show_display_data(
                ctx, _get_possible_pairing_methods_and_cancel(ctx)
            )
    if Cancel.is_type_of(response):
        ctx.channel_ctx.clear()
        raise SilentError("Action was cancelled by the Host")
    # TODO disable NFC (if enabled)
    response = await _handle_different_pairing_methods(ctx, response)

    while ThpCredentialRequest.is_type_of(response):
        response = await _handle_credential_request(ctx, response)

    return await _handle_end_request(ctx, response)


async def _prepare_pairing(ctx: PairingContext) -> None:

    if _is_method_included(ctx, ThpPairingMethod.CodeEntry):
        await _handle_code_entry_is_included(ctx)

    if _is_method_included(ctx, ThpPairingMethod.QrCode):
        _handle_qr_code_is_included(ctx)

    if _is_method_included(ctx, ThpPairingMethod.NFC_Unidirectional):
        _handle_nfc_unidirectional_is_included(ctx)


async def show_display_data(ctx: PairingContext, expected_types: Container[int] = ()):
    from trezorui2 import CANCELLED

    read_task = ctx.read(expected_types)
    cancel_task = ctx.display_data.get_display_layout()
    race = loop.race(read_task, cancel_task.get_result())
    result = await race

    if result is CANCELLED:
        raise ActionCancelled

    return result


@check_state_and_log(ChannelState.TP1)
async def _handle_code_entry_is_included(ctx: PairingContext) -> None:
    commitment = sha256(ctx.secret).digest()

    challenge_message = await ctx.call(  # noqa: F841
        ThpCodeEntryCommitment(commitment=commitment), ThpCodeEntryChallenge
    )
    ctx.channel_ctx.set_channel_state(ChannelState.TP2)

    if not ThpCodeEntryChallenge.is_type_of(challenge_message):
        raise UnexpectedMessage("Unexpected message")

    if challenge_message.challenge is None:
        raise Exception("Invalid message")
    sha_ctx = sha256(ctx.channel_ctx.get_handshake_hash())
    sha_ctx.update(ctx.secret)
    sha_ctx.update(challenge_message.challenge)
    sha_ctx.update(bytes("PairingMethod_CodeEntry", "utf-8"))
    code_code_entry_hash = sha_ctx.digest()
    ctx.display_data.code_code_entry = (
        int.from_bytes(code_code_entry_hash, "big") % 1000000
    )


@check_state_and_log(ChannelState.TP1, ChannelState.TP2)
def _handle_qr_code_is_included(ctx: PairingContext) -> None:
    sha_ctx = sha256(ctx.channel_ctx.get_handshake_hash())
    sha_ctx.update(ctx.secret)
    sha_ctx.update(bytes("PairingMethod_QrCode", "utf-8"))
    ctx.display_data.code_qr_code = sha_ctx.digest()[:16]


@check_state_and_log(ChannelState.TP1, ChannelState.TP2)
def _handle_nfc_unidirectional_is_included(ctx: PairingContext) -> None:
    sha_ctx = sha256(ctx.channel_ctx.get_handshake_hash())
    sha_ctx.update(ctx.secret)
    sha_ctx.update(bytes("PairingMethod_NfcUnidirectional", "utf-8"))
    ctx.display_data.code_nfc_unidirectional = sha_ctx.digest()[:16]


@check_state_and_log(ChannelState.TP3)
async def _handle_different_pairing_methods(
    ctx: PairingContext, response: protobuf.MessageType
) -> protobuf.MessageType:
    if ThpCodeEntryCpaceHost.is_type_of(response):
        return await _handle_code_entry_cpace(ctx, response)
    if ThpQrCodeTag.is_type_of(response):
        return await _handle_qr_code_tag(ctx, response)
    if ThpNfcUnidirectionalTag.is_type_of(response):
        return await _handle_nfc_unidirectional_tag(ctx, response)
    raise UnexpectedMessage("Unexpected message")


@check_state_and_log(ChannelState.TP3)
@check_method_is_allowed(ThpPairingMethod.CodeEntry)
async def _handle_code_entry_cpace(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    from trezor.wire.thp.cpace import Cpace

    # TODO check that ThpCodeEntryCpaceHost message is valid

    if TYPE_CHECKING:
        assert isinstance(message, ThpCodeEntryCpaceHost)
    if message.cpace_host_public_key is None:
        raise ThpError("Message ThpCodeEntryCpaceHost has no public key")

    ctx.cpace = Cpace(
        message.cpace_host_public_key,
        ctx.channel_ctx.get_handshake_hash(),
    )
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
@check_method_is_allowed(ThpPairingMethod.CodeEntry)
async def _handle_code_entry_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:

    if TYPE_CHECKING:
        assert isinstance(message, ThpCodeEntryTag)

    expected_tag = sha256(ctx.cpace.shared_secret).digest()
    if expected_tag != message.tag:
        print(
            "expected code entry tag:", hexlify(expected_tag).decode()
        )  # TODO remove after testing
        print(
            "expected code entry shared secret:",
            hexlify(ctx.cpace.shared_secret).decode(),
        )  # TODO remove after testing
        raise ThpError("Unexpected Code Entry Tag")

    return await _handle_secret_reveal(
        ctx,
        msg=ThpCodeEntrySecret(secret=ctx.secret),
    )


@check_state_and_log(ChannelState.TP3)
@check_method_is_allowed(ThpPairingMethod.QrCode)
async def _handle_qr_code_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    if TYPE_CHECKING:
        assert isinstance(message, ThpQrCodeTag)
    assert ctx.display_data.code_qr_code is not None
    expected_tag = sha256(ctx.display_data.code_qr_code).digest()
    if expected_tag != message.tag:
        print(
            "expected qr code tag:", hexlify(expected_tag).decode()
        )  # TODO remove after testing
        print(
            "expected code qr code tag:",
            hexlify(ctx.display_data.code_qr_code).decode(),
        )  # TODO remove after testing
        print(
            "expected secret:", hexlify(ctx.secret).decode()
        )  # TODO remove after testing
        raise ThpError("Unexpected QR Code Tag")

    return await _handle_secret_reveal(
        ctx,
        msg=ThpQrCodeSecret(secret=ctx.secret),
    )


@check_state_and_log(ChannelState.TP3)
@check_method_is_allowed(ThpPairingMethod.NFC_Unidirectional)
async def _handle_nfc_unidirectional_tag(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    if TYPE_CHECKING:
        assert isinstance(message, ThpNfcUnidirectionalTag)

    expected_tag = sha256(ctx.display_data.code_nfc_unidirectional).digest()
    if expected_tag != message.tag:
        print(
            "expected nfc tag:", hexlify(expected_tag).decode()
        )  # TODO remove after testing
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
        ThpMessageType.ThpCredentialRequest,
        ThpMessageType.ThpEndRequest,
    )


@check_state_and_log(ChannelState.TC1)
async def _handle_credential_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> protobuf.MessageType:
    ctx.secret

    if not ThpCredentialRequest.is_type_of(message):
        raise UnexpectedMessage("Unexpected message")
    if message.host_static_pubkey is None:
        raise Exception("Invalid message")  # TODO change failure type

    trezor_static_pubkey = crypto.get_trezor_static_pubkey()
    credential_metadata = ThpCredentialMetadata(host_name=ctx.host_name)
    credential = issue_credential(message.host_static_pubkey, credential_metadata)

    return await ctx.call_any(
        ThpCredentialResponse(
            trezor_static_pubkey=trezor_static_pubkey, credential=credential
        ),
        ThpMessageType.ThpCredentialRequest,
        ThpMessageType.ThpEndRequest,
    )


@check_state_and_log(ChannelState.TC1)
async def _handle_end_request(
    ctx: PairingContext, message: protobuf.MessageType
) -> ThpEndResponse:
    if not ThpEndRequest.is_type_of(message):
        raise UnexpectedMessage("Unexpected message")
    return await _end_pairing(ctx)


async def _end_pairing(ctx: PairingContext) -> ThpEndResponse:
    ctx.channel_ctx.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
    return ThpEndResponse()


#
# Helpers - checkers


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


def _get_possible_pairing_methods_and_cancel(ctx: PairingContext) -> Tuple[int, ...]:
    r = _get_possible_pairing_methods(ctx)
    mtype = Cancel.MESSAGE_WIRE_TYPE
    return r + ((mtype,) if mtype is not None else ())


def _get_possible_pairing_methods(ctx: PairingContext) -> Tuple[int, ...]:
    r = tuple(
        _get_message_type_for_method(method)
        for method in ctx.channel_ctx.selected_pairing_methods
    )
    if __debug__:
        from trezor.messages import DebugLinkGetState

        mtype = DebugLinkGetState.MESSAGE_WIRE_TYPE
        return r + ((mtype,) if mtype is not None else ())
    return r


def _get_message_type_for_method(method: int) -> int:
    if method is ThpPairingMethod.CodeEntry:
        return ThpMessageType.ThpCodeEntryCpaceHost
    if method is ThpPairingMethod.NFC_Unidirectional:
        return ThpMessageType.ThpNfcUnidirectionalTag
    if method is ThpPairingMethod.QrCode:
        return ThpMessageType.ThpQrCodeTag
    raise ValueError("Unexpected pairing method - no message type available")
