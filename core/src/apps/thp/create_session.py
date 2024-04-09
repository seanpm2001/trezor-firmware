from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from trezor.wire.thp.channel import Channel

if TYPE_CHECKING:
    from trezor.messages import ThpCreateNewSession, ThpNewSession


async def create_new_session(
    channel: Channel, message: ThpCreateNewSession
) -> ThpNewSession:
    new_session_id: int = channel.create_new_session(message.passphrase)
    return ThpNewSession(new_session_id=new_session_id)
