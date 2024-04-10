from trezor import log, loop
from trezor.messages import ThpCreateNewSession, ThpNewSession
from trezor.wire.thp import SessionState, channel
from trezor.wire.thp.session_context import SessionContext


async def create_new_session(
    channel: channel.Channel, message: ThpCreateNewSession
) -> ThpNewSession:

    session = SessionContext.create_new_session(channel)
    session.set_session_state(SessionState.ALLOCATED)
    channel.sessions[session.session_id] = session
    loop.schedule(session.handle())
    new_session_id: int = session.session_id

    if __debug__:
        log.debug(
            __name__,
            "create_new_session - new session created. Passphrase: %s, Session id: %d",
            message.passphrase,
            session.session_id,
        )
        print(channel.sessions)

    return ThpNewSession(new_session_id=new_session_id)
