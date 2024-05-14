from typing import TYPE_CHECKING

from storage import cache_thp
from trezor import loop

from .session_context import (
    GenericSessionContext,
    ManagementSessionContext,
    SessionContext,
)

if __debug__:
    from trezor import log

if TYPE_CHECKING:
    from . import ChannelContext


def create_new_session(channel_ctx: ChannelContext) -> SessionContext:
    session_cache = cache_thp.get_new_session(channel_ctx.channel_cache)
    return SessionContext(channel_ctx, session_cache)


def create_new_management_session(
    channel_ctx: ChannelContext,
) -> ManagementSessionContext:
    return ManagementSessionContext(channel_ctx)


def load_cached_sessions(
    channel_ctx: ChannelContext,
) -> dict[int, GenericSessionContext]:
    if __debug__:
        log.debug(__name__, "load_cached_sessions")
    sessions: dict[int, GenericSessionContext] = {}
    cached_sessions = cache_thp.get_all_allocated_sessions()
    if __debug__:
        log.debug(
            __name__,
            "load_cached_sessions - loaded a total of %d sessions from cache",
            len(cached_sessions),
        )
    for session in cached_sessions:
        if session.channel_id == channel_ctx.channel_id:
            sid = int.from_bytes(session.session_id, "big")
            sessions[sid] = SessionContext(channel_ctx, session)
            loop.schedule(sessions[sid].handle())
    return sessions
