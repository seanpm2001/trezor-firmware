from typing import TYPE_CHECKING

from trezor import log, loop
from trezor.enums import FailureType
from trezor.messages import Failure, ThpCreateNewSession, ThpNewSession
from trezor.wire.errors import ActionCancelled, DataError
from trezor.wire.thp import SessionState

if TYPE_CHECKING:
    from trezor.wire.thp import ChannelContext


async def create_new_session(
    channel: ChannelContext, message: ThpCreateNewSession
) -> ThpNewSession | Failure:
    from trezor.wire.thp.session_manager import create_new_session

    from apps.common.seed import derive_and_store_roots

    session = create_new_session(channel)
    try:
        await derive_and_store_roots(session, message)
    except DataError as e:
        return Failure(code=FailureType.DataError, message=e.message)
    except ActionCancelled as e:
        return Failure(code=FailureType.ActionCancelled, message=e.message)
    # TODO handle other errors

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
