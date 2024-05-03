from typing import TYPE_CHECKING

from trezor import protobuf
from trezor.enums import MessageType
from trezor.wire.errors import UnexpectedMessage

from apps.thp import create_session

if TYPE_CHECKING:
    from typing import Any, Callable, Coroutine

    from trezor.messages import LoadDevice

    from . import ChannelContext

    pass


def get_handler_for_channel_message(
    msg: protobuf.MessageType,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    if msg.MESSAGE_WIRE_TYPE is MessageType.ThpCreateNewSession:
        return create_session.create_new_session
    if __debug__:
        if msg.MESSAGE_WIRE_TYPE is MessageType.LoadDevice:
            from apps.debug.load_device import load_device

            def wrapper(
                channel: ChannelContext, msg: LoadDevice
            ) -> Coroutine[Any, Any, protobuf.MessageType]:
                return load_device(msg)

            return wrapper
    raise UnexpectedMessage("There is no handler available for this message")
