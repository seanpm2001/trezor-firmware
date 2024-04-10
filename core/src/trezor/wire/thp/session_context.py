from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from storage import cache_thp
from storage.cache_thp import SessionThpCache
from trezor import log, loop, protobuf
from trezor.wire import message_handler, protocol_common
from trezor.wire.message_handler import AVOID_RESTARTING_FOR, failure

from ..protocol_common import Context, MessageWithType
from . import SessionState
from . import channel

if TYPE_CHECKING:
    from typing import Container  # pyright: ignore[reportShadowedImports]

    pass


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
        self, channel: channel.Channel, session_cache: SessionThpCache
    ) -> None:
        if channel.channel_id != session_cache.channel_id:
            raise Exception(
                "The session has different channel id than the provided channel context!"
            )
        super().__init__(channel.iface, channel.channel_id)
        self.channel = channel
        self.session_cache = session_cache
        self.session_id = int.from_bytes(session_cache.session_id, "big")
        self.incoming_message = loop.chan()

    @classmethod
    def create_new_session(cls, channel_context: channel.Channel) -> "SessionContext":
        session_cache = cache_thp.get_new_session(channel_context.channel_cache)
        return cls(channel_context, session_cache)

    async def handle(self, is_debug_session: bool = False) -> None:
        if __debug__:
            log.debug(__name__, "handle - start")
            if is_debug_session:
                import apps.debug

                apps.debug.DEBUG_CONTEXT = self

        take = self.incoming_message.take()
        next_message: MessageWithType | None = None

        # Take a mark of modules that are imported at this point, so we can
        # roll back and un-import any others.
        # TODO modules = utils.unimport_begin()
        while True:
            try:
                if next_message is None:
                    # If the previous run did not keep an unprocessed message for us,
                    # wait for a new one.
                    try:
                        message: MessageWithType = await take
                    except protocol_common.WireError as e:
                        if __debug__:
                            log.exception(__name__, e)
                        await self.write(failure(e))
                        continue
                else:
                    # Process the message from previous run.
                    message = next_message
                    next_message = None

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

                        if (
                            next_message is None
                            and message.type not in AVOID_RESTARTING_FOR
                        ):
                            # Shut down the loop if there is no next message waiting.
                            # Let the session be restarted from `main`.
                            loop.clear()
                            return  # pylint: disable=lost-exception

            except Exception as exc:
                # Log and try again. The session handler can only exit explicitly via
                # loop.clear() above.
                if __debug__:
                    log.exception(__name__, exc)

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
        return await self.channel.write(msg, self.session_id)

    # ACCESS TO SESSION DATA

    def get_session_state(self) -> SessionState:
        state = int.from_bytes(self.session_cache.state, "big")
        return SessionState(state)

    def set_session_state(self, state: SessionState) -> None:
        self.session_cache.state = bytearray(state.to_bytes(1, "big"))


def load_cached_sessions(channel: channel.Channel) -> dict[int, SessionContext]:  # TODO
    if __debug__:
        log.debug(__name__, "load_cached_sessions")
    sessions: dict[int, SessionContext] = {}
    cached_sessions = cache_thp.get_all_allocated_sessions()
    if __debug__:
        log.debug(
            __name__,
            "load_cached_sessions - loaded a total of %d sessions from cache",
            len(cached_sessions),
        )
    for session in cached_sessions:
        if session.channel_id == channel.channel_id:
            sid = int.from_bytes(session.session_id, "big")
            sessions[sid] = SessionContext(channel, session)
            loop.schedule(sessions[sid].handle())
    return sessions
