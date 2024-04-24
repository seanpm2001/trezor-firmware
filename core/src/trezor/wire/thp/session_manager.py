from storage import cache_thp
from trezor import log, loop
from trezor.wire.thp import ChannelContext
from trezor.wire.thp.session_context import SessionContext


def create_new_session(channel_ctx: ChannelContext) -> SessionContext:
    session_cache = cache_thp.get_new_session(channel_ctx.channel_cache)
    return SessionContext(channel_ctx, session_cache)


def load_cached_sessions(channel_ctx: ChannelContext) -> dict[int, SessionContext]:
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
        if session.channel_id == channel_ctx.channel_id:
            sid = int.from_bytes(session.session_id, "big")
            sessions[sid] = SessionContext(channel_ctx, session)
            loop.schedule(sessions[sid].handle())
    return sessions
