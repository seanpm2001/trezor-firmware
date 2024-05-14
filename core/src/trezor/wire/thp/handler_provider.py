from typing import TYPE_CHECKING

from trezor import protobuf
from trezor.enums import MessageType
from trezor.wire.errors import UnexpectedMessage

from apps.base import get_features
from apps.thp import create_session

if TYPE_CHECKING:
    from trezorio import WireInterface
    from typing import Any, Callable, Coroutine

    from trezor.messages import Features, GetFeatures, LoadDevice

    from .. import Handler
    from .session_context import ManagementSessionContext


def get_handler_for_channel_message(
    msg: protobuf.MessageType,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    if msg.MESSAGE_WIRE_TYPE is MessageType.ThpCreateNewSession:
        return create_session.create_new_session
    if msg.MESSAGE_WIRE_TYPE is MessageType.GetFeatures:
        return handle_GetFeatures
    if __debug__:
        if msg.MESSAGE_WIRE_TYPE is MessageType.LoadDevice:
            from apps.debug.load_device import load_device

            def wrapper(
                channel: ManagementSessionContext, msg: LoadDevice
            ) -> Coroutine[Any, Any, protobuf.MessageType]:
                return load_device(msg)

            return wrapper
    raise UnexpectedMessage("There is no handler available for this message")


async def handle_GetFeatures(
    ctx: ManagementSessionContext, msg: GetFeatures
) -> Features:
    return get_features()


def get_handler_finder_for_message(ctx: ManagementSessionContext):
    def finder(iface: WireInterface, msg_type: int) -> Handler | None:
        def handler_wrap(msg: protobuf.MessageType):
            handler = get_handler_for_channel_message(msg)
            return handler(ctx, msg)

        return handler_wrap

    return finder
