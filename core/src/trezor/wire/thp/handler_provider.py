from typing import TYPE_CHECKING

from trezor import protobuf

from apps.thp import create_session

if TYPE_CHECKING:
    from typing import Any, Callable, Coroutine

    pass

from apps.thp.pairing import handle_pairing_request


def get_handler_for_handshake(
    msg: protobuf.MessageType,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    return create_session.create_new_session


def get_handler_for_pairing(
    messageType: int,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType | None]]:
    return handle_pairing_request
