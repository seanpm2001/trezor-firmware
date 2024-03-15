from trezor import protobuf

from ..context import Context
from .channel_context import ChannelContext


class SessionContext(Context):
    def __init__(self, channel_context: ChannelContext, session_id: int) -> None:
        super().__init__(channel_context.iface, channel_context.channel_id)
        self.channel_context = channel_context
        self.session_id = session_id

    async def write(self, msg: protobuf.MessageType) -> None:
        return await self.channel_context.write(msg, self.session_id)
