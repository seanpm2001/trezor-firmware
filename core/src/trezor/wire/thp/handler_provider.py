from typing import TYPE_CHECKING

from trezor import protobuf
from trezor.enums import MessageType
from trezor.wire.thp.thp_session import ThpError

from apps.thp import create_session

if TYPE_CHECKING:
    from typing import Any, Callable, Coroutine

    pass

from apps.thp.pairing import (
    handle_code_entry_challenge,
    handle_code_entry_cpace,
    handle_code_entry_tag,
    handle_credential_request,
    handle_end_request,
    handle_nfc_unidirectional_tag,
    handle_pairing_request,
    handle_qr_code_tag,
)


def get_handler_for_handshake(
    msg: protobuf.MessageType,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    return create_session.create_new_session


def get_handler_for_pairing(
    messageType: int,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    if TYPE_CHECKING:
        assert isinstance(messageType, MessageType)
    handler = handlers.get(messageType)
    if handler is None:
        raise ThpError("Pairing handler for this message is not available!")
    return handler


handlers = {
    MessageType.ThpStartPairingRequest: handle_pairing_request,
    MessageType.ThpCodeEntryChallenge: handle_code_entry_challenge,
    MessageType.ThpCodeEntryCpaceHost: handle_code_entry_cpace,
    MessageType.ThpCodeEntryTag: handle_code_entry_tag,
    MessageType.ThpQrCodeTag: handle_qr_code_tag,
    MessageType.ThpNfcUnidirectionalTag: handle_nfc_unidirectional_tag,
    MessageType.ThpCredentialRequest: handle_credential_request,
    MessageType.ThpEndRequest: handle_end_request,
}
