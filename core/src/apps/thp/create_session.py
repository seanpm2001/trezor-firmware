from typing import TYPE_CHECKING

from trezor import log, loop
from trezor.messages import ThpCreateNewSession, ThpNewSession
from trezor.wire.thp import SessionState

if TYPE_CHECKING:
    from trezor.wire.thp import ChannelContext


async def create_new_session(
    channel: ChannelContext, message: ThpCreateNewSession
) -> ThpNewSession:
    # from apps.common.seed import get_seed TODO
    from trezor.wire.thp.session_manager import create_new_session

    from apps.common.seed import derive_and_store_roots

    session = create_new_session(channel)
    await derive_and_store_roots(session, message)

    session.set_session_state(SessionState.ALLOCATED)
    channel.sessions[session.session_id] = session
    loop.schedule(session.handle())
    new_session_id: int = session.session_id
    # await get_seed() TODO

    if __debug__:
        log.debug(
            __name__,
            "create_new_session - new session created. Passphrase: %s, Session id: %d",
            message.passphrase if message.passphrase is not None else "",
            session.session_id,
        )
        print(channel.sessions)

    return ThpNewSession(new_session_id=new_session_id)
