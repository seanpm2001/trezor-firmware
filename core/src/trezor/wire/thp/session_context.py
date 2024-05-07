from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from storage.cache_thp import SessionThpCache
from trezor import log, loop, protobuf, utils
from trezor.wire import message_handler, protocol_common
from trezor.wire.message_handler import AVOID_RESTARTING_FOR, failure

from ..protocol_common import Context, MessageWithType
from . import SessionState

if TYPE_CHECKING:
    from typing import (  # pyright: ignore[reportShadowedImports]
        Any,
        Awaitable,
        Container,
        TypeVar,
        overload,
    )

    from storage.cache_common import DataCache

    from . import ChannelContext

    pass

_EXIT_LOOP = True
_REPEAT_LOOP = False


class UnexpectedMessageWithType(Exception):
    """A message was received that is not part of the current workflow.

    Utility exception to inform the session handler that the current workflow
    should be aborted and a new one started as if `msg` was the first message.
    """

    def __init__(self, msg: MessageWithType) -> None:
        super().__init__()
        self.msg = msg


class SessionContext(Context):
    def __init__(
        self, channel_ctx: ChannelContext, session_cache: SessionThpCache
    ) -> None:
        if channel_ctx.channel_id != session_cache.channel_id:
            raise Exception(
                "The session has different channel id than the provided channel context!"
            )
        super().__init__(channel_ctx.iface, channel_ctx.channel_id)
        self.channel_ctx = channel_ctx
        self.session_cache = session_cache
        self.session_id = int.from_bytes(session_cache.session_id, "big")
        self.incoming_message = loop.chan()

    async def handle(self, is_debug_session: bool = False) -> None:
        if __debug__:
            self._handle_debug(is_debug_session)

        take = self.incoming_message.take()
        next_message: MessageWithType | None = None

        # Take a mark of modules that are imported at this point, so we can
        # roll back and un-import any others.
        # TODO modules = utils.unimport_begin()
        while True:
            try:
                if await self._handle_message(take, next_message, is_debug_session):
                    return
            except Exception as exc:
                # Log and try again.
                if __debug__:
                    log.exception(__name__, exc)

    def _handle_debug(self, is_debug_session: bool) -> None:
        log.debug(__name__, "handle - start (session_id: %d)", self.session_id)
        if is_debug_session:
            import apps.debug

            apps.debug.DEBUG_CONTEXT = self

    async def _handle_message(
        self,
        take: Awaitable[Any],
        next_message: MessageWithType | None,
        is_debug_session: bool,
    ) -> bool:

        try:
            message = await self._get_message(take, next_message)
        except protocol_common.WireError as e:
            if __debug__:
                log.exception(__name__, e)
            await self.write(failure(e))
            return _REPEAT_LOOP

        try:
            next_message = await message_handler.handle_single_message(
                self, message, use_workflow=not is_debug_session
            )
        except Exception as exc:
            # Log and ignore. The session handler can only exit explicitly in the
            # following finally block.
            if __debug__:
                log.exception(__name__, exc)
        finally:
            if not __debug__ or not is_debug_session:
                # Unload modules imported by the workflow.  Should not raise.
                # This is not done for the debug session because the snapshot taken
                # in a debug session would clear modules which are in use by the
                # workflow running on wire.
                # TODO utils.unimport_end(modules)

                if next_message is None and message.type not in AVOID_RESTARTING_FOR:
                    # Shut down the loop if there is no next message waiting.
                    return _EXIT_LOOP  # pylint: disable=lost-exception
            return _REPEAT_LOOP  # pylint: disable=lost-exception

    async def _get_message(
        self, take: Awaitable[Any], next_message: MessageWithType | None
    ) -> MessageWithType:
        if next_message is None:
            # If the previous run did not keep an unprocessed message for us,
            # wait for a new one.
            message: MessageWithType = await take
        else:
            # Process the message from previous run.
            message = next_message
            next_message = None
        return message

    async def read(
        self,
        expected_types: Container[int],
        expected_type: type[protobuf.MessageType] | None = None,
    ) -> protobuf.MessageType:
        if __debug__:
            exp_type: str = str(expected_type)
            if expected_type is not None:
                exp_type = expected_type.MESSAGE_NAME
            log.debug(
                __name__,
                "Read - with expected types %s and expected type %s",
                str(expected_types),
                exp_type,
            )
        message: MessageWithType = await self.incoming_message.take()
        if message.type not in expected_types:
            raise UnexpectedMessageWithType(message)

        if expected_type is None:
            expected_type = protobuf.type_for_wire(message.type)

        return message_handler.wrap_protobuf_load(message.data, expected_type)

    async def write(self, msg: protobuf.MessageType) -> None:
        return await self.channel_ctx.write(msg, self.session_id)

    # ACCESS TO SESSION DATA

    def get_session_state(self) -> SessionState:
        state = int.from_bytes(self.session_cache.state, "big")
        return SessionState(state)

    def set_session_state(self, state: SessionState) -> None:
        self.session_cache.state = bytearray(state.to_bytes(1, "big"))

    # ACCESS TO CACHE
    @property
    def cache(self) -> DataCache:
        return self.session_cache

    if TYPE_CHECKING:
        T = TypeVar("T")

        @overload
        def cache_get(self, key: int) -> bytes | None:  # noqa: F811
            ...

        @overload
        def cache_get(self, key: int, default: T) -> bytes | T:  # noqa: F811
            ...

    def cache_get(
        self, key: int, default: T | None = None
    ) -> bytes | T | None:  # noqa: F811
        utils.ensure(key < len(self.session_cache.fields))
        if self.session_cache.data[key][0] != 1:
            return default
        return bytes(self.session_cache.data[key][1:])

    def cache_is_set(self, key: int) -> bool:
        return self.session_cache.is_set(key)

    def cache_set(self, key: int, value: bytes) -> None:
        utils.ensure(key < len(self.session_cache.fields))
        utils.ensure(len(value) <= self.session_cache.fields[key])
        self.session_cache.data[key][0] = 1
        self.session_cache.data[key][1:] = value
