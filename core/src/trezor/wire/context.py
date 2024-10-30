"""Context pseudo-global.

Each workflow handler runs in a "context" which is tied to a particular communication
session. When the handler needs to communicate with the host, it needs access to that
context.

To avoid the need to pass a context object around, the context is stored in a
pseudo-global manner: any workflow handler can request access to the context via this
module, and the appropriate context object will be used for it.

Some workflows don't need a context to exist. This is supported by the `maybe_call`
function, which will silently ignore the call if no context is available. Useful mainly
for ButtonRequests. Of course, `context.wait()` transparently works in such situations.
"""

from typing import TYPE_CHECKING

from storage import cache, cache_codec
from storage.cache_common import SESSIONLESS_FLAG, InvalidSessionError
from trezor import log, loop, protobuf
from trezor.wire import codec_v1

from .protocol_common import Context, Message

if TYPE_CHECKING:
    from trezorio import WireInterface
    from typing import (
        Any,
        Awaitable,
        Callable,
        Container,
        Coroutine,
        Generator,
        TypeVar,
        overload,
    )

    from storage.cache_common import DataCache

    Msg = TypeVar("Msg", bound=protobuf.MessageType)
    HandlerTask = Coroutine[Any, Any, protobuf.MessageType]
    Handler = Callable[["Context", Msg], HandlerTask]

    LoadedMessageType = TypeVar("LoadedMessageType", bound=protobuf.MessageType)

    T = TypeVar("T")


class UnexpectedMessageException(Exception):
    """A message was received that is not part of the current workflow.

    Utility exception to inform the session handler that the current workflow
    should be aborted and a new one started as if `msg` was the first message.
    """

    def __init__(self, msg: Message) -> None:
        super().__init__()
        self.msg = msg


class CodecContext(Context):
    """Wire context.

    Represents USB communication inside a particular session (channel) on a particular interface
    (i.e., wire, debug, single BT connection, etc.)
    """

    def __init__(
        self,
        iface: WireInterface,
        buffer: bytearray,
    ) -> None:
        self.iface = iface
        self.buffer = buffer
        super().__init__(iface, codec_v1.SESSION_ID.to_bytes(2, "big"))

    def read_from_wire(self) -> Awaitable[Message]:
        """Read a whole message from the wire without parsing it."""
        return codec_v1.read_message(self.iface, self.buffer)

    if TYPE_CHECKING:

        @overload
        async def read(
            self, expected_types: Container[int]
        ) -> protobuf.MessageType: ...

        @overload
        async def read(
            self, expected_types: Container[int], expected_type: type[LoadedMessageType]
        ) -> LoadedMessageType: ...

    reading: bool = False

    async def read(
        self,
        expected_types: Container[int],
        expected_type: type[protobuf.MessageType] | None = None,
    ) -> protobuf.MessageType:
        """Read a message from the wire.

        The read message must be of one of the types specified in `expected_types`.
        If only a single type is expected, it can be passed as `expected_type`,
        to save on having to decode the type code into a protobuf class.
        """
        if __debug__:
            log.debug(
                __name__,
                "%s: expect: %s",
                self.iface.iface_num(),
                expected_type.MESSAGE_NAME if expected_type else expected_types,
            )

        # Load the full message into a buffer, parse out type and data payload
        msg = await self.read_from_wire()

        # If we got a message with unexpected type, raise the message via
        # `UnexpectedMessageError` and let the session handler deal with it.
        if msg.type not in expected_types:
            raise UnexpectedMessageException(msg)

        if expected_type is None:
            expected_type = protobuf.type_for_wire(msg.type)

        if __debug__:
            log.debug(
                __name__,
                "%s: read: %s",
                self.iface.iface_num(),
                expected_type.MESSAGE_NAME,
            )

        # look up the protobuf class and parse the message
        from . import message_handler  # noqa: F401
        from .message_handler import wrap_protobuf_load

        return wrap_protobuf_load(msg.data, expected_type)

    async def write(self, msg: protobuf.MessageType) -> None:
        """Write a message to the wire."""
        if __debug__:
            log.debug(
                __name__,
                "%s: write: %s",
                self.iface.iface_num(),
                msg.MESSAGE_NAME,
            )

        # cannot write message without wire type
        assert msg.MESSAGE_WIRE_TYPE is not None

        msg_size = protobuf.encoded_length(msg)

        if msg_size <= len(self.buffer):
            # reuse preallocated
            buffer = self.buffer
        else:
            # message is too big, we need to allocate a new buffer
            buffer = bytearray(msg_size)

        msg_size = protobuf.encode(buffer, msg)
        await codec_v1.write_message(
            self.iface,
            msg.MESSAGE_WIRE_TYPE,
            memoryview(buffer)[:msg_size],
        )

    def release(self) -> None:
        cache_codec.end_current_session()

    # ACCESS TO CACHE
    @property
    def cache(self) -> DataCache:
        c = cache_codec.get_active_session()
        if c is None:
            raise InvalidSessionError()
        return c


CURRENT_CONTEXT: Context | None = None


async def call(
    msg: protobuf.MessageType,
    expected_type: type[LoadedMessageType],
) -> LoadedMessageType:
    """Send a message to the host and wait for a response of a particular type.

    Raises if there is no context for this workflow."""
    if CURRENT_CONTEXT is None:
        raise RuntimeError("No wire context")

    return await CURRENT_CONTEXT.call(msg, expected_type)


async def call_any(
    msg: protobuf.MessageType, *expected_wire_types: int
) -> protobuf.MessageType:
    """Send a message to the host and wait for a response.

    The response can be of any of the types specified in `expected_wire_types`.

    Raises if there is no context for this workflow."""
    if CURRENT_CONTEXT is None:
        raise RuntimeError("No wire context")

    await CURRENT_CONTEXT.write(msg)
    del msg
    return await CURRENT_CONTEXT.read(expected_wire_types)


async def maybe_call(
    msg: protobuf.MessageType, expected_type: type[LoadedMessageType]
) -> None:
    """Send a message to the host and read but ignore the response.

    If there is a context, the function still checks that the response is of the
    requested type. If there is no context, the call is ignored.
    """
    if CURRENT_CONTEXT is None:
        return

    await call(msg, expected_type)


def get_context() -> Context:
    """Get the current session context.

    Can be needed in case the caller needs raw read and raw write capabilities, which
    are not provided by the module functions.

    Result of this function should not be stored -- the context is technically allowed
    to change inbetween any `await` statements.
    """
    if CURRENT_CONTEXT is None:
        raise RuntimeError("No wire context")
    return CURRENT_CONTEXT


def with_context(ctx: Context, workflow: loop.Task) -> Generator:
    """Run a workflow in a particular context.

    Stores the context in a closure and installs it into the global variable every time
    the closure is resumed, thus making sure that all calls to `wire.context.*` will
    work as expected.
    """
    global CURRENT_CONTEXT
    send_val = None
    send_exc = None

    while True:
        CURRENT_CONTEXT = ctx
        try:
            if send_exc is not None:
                res = workflow.throw(send_exc)
            else:
                res = workflow.send(send_val)
        except StopIteration as st:
            return st.value
        finally:
            CURRENT_CONTEXT = None

        try:
            send_val = yield res
        except BaseException as e:
            send_exc = e
        else:
            send_exc = None


# ACCESS TO CACHE

if TYPE_CHECKING:
    T = TypeVar("T")

    @overload
    def cache_get(key: int) -> bytes | None:  # noqa: F811
        ...

    @overload
    def cache_get(key: int, default: T) -> bytes | T:  # noqa: F811
        ...


def cache_get(key: int, default: T | None = None) -> bytes | T | None:  # noqa: F811
    cache = _get_cache_for_key(key)
    return cache.get(key, default)


def cache_get_bool(key: int) -> bool:  # noqa: F811
    cache = _get_cache_for_key(key)
    return cache.get_bool(key)


def cache_get_int(key: int, default: T | None = None) -> int | T | None:  # noqa: F811
    cache = _get_cache_for_key(key)
    return cache.get_int(key, default)


def cache_is_set(key: int) -> bool:
    cache = _get_cache_for_key(key)
    return cache.is_set(key)


def cache_set(key: int, value: bytes) -> None:
    cache = _get_cache_for_key(key)
    cache.set(key, value)


def cache_set_bool(key: int, value: bool) -> None:
    cache = _get_cache_for_key(key)
    cache.set_bool(key, value)


def cache_set_int(key: int, value: int) -> None:
    cache = _get_cache_for_key(key)
    cache.set_int(key, value)


def cache_delete(key: int) -> None:
    cache = _get_cache_for_key(key)
    cache.delete(key)


def _get_cache_for_key(key) -> DataCache:
    if key & SESSIONLESS_FLAG:
        return cache.get_sessionless_cache()
    if CURRENT_CONTEXT:
        return CURRENT_CONTEXT.cache
    raise Exception("No wire context")
