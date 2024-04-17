from typing import TYPE_CHECKING

from trezor import protobuf

from apps.thp import create_session

if TYPE_CHECKING:
    from typing import Any, Callable, Coroutine

    pass


def get_handler_for_channel_message(
    msg: protobuf.MessageType,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    return create_session.create_new_session
