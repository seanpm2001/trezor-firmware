import ustruct
from micropython import const
from typing import TYPE_CHECKING

from storage.cache_thp import SessionThpCache
from trezor import loop, protobuf, utils

from ..protocol_common import Context
from . import thp_session
from .thp_messages import CONTINUATION_PACKET, ENCRYPTED_TRANSPORT

# from .thp_session import SessionState, ThpError

if TYPE_CHECKING:
    from trezorio import WireInterface

_INIT_DATA_OFFSET = const(5)
_CONT_DATA_OFFSET = const(3)


class ChannelContext(Context):
    def __init__(
        self, iface: WireInterface, channel_id: int, session_data: SessionThpCache
    ) -> None:
        super().__init__(iface, channel_id)
        self.session_data = session_data
        self.buffer: utils.BufferType
        self.waiting_for_ack_timeout: loop.Task | None
        self.is_cont_packet_expected: bool = False
        self.expected_payload_length: int = 0
        self.bytes_read = 0

    # ACCESS TO SESSION_DATA

    def get_management_session_state(self):
        return thp_session.get_state(self.session_data)

    # CALLED BY THP_MAIN_LOOP

    async def receive_packet(self, packet: utils.BufferType):
        ctrl_byte = packet[0]
        if _is_ctrl_byte_continuation(ctrl_byte):
            await self._handle_cont_packet(packet)
        else:
            await self._handle_init_packet(packet)

    async def _handle_init_packet(self, packet):
        ctrl_byte, _, payload_length = ustruct.unpack(">BHH", packet)
        packet_payload = packet[5:]

        if _is_ctrl_byte_encrypted_transport(ctrl_byte):
            packet_payload = self._decode(packet_payload)

        # session_id = packet_payload[0]  # TODO handle handshake differently
        self.expected_payload_length = payload_length
        self.bytes_read = 0

        await self._buffer_packet_data(self.buffer, packet, _INIT_DATA_OFFSET)
        # TODO Set/Provide different buffer for management session

        if self.expected_payload_length == self.bytes_read:
            self._finish_message()
        else:
            self.is_cont_packet_expected = True

    async def _handle_cont_packet(self, packet):
        if not self.is_cont_packet_expected:
            return  # Continuation packet is not expected, ignoring
        await self._buffer_packet_data(self.buffer, packet, _CONT_DATA_OFFSET)

    def _decode(self, payload) -> bytes:
        return payload  # TODO add decryption process

    async def _buffer_packet_data(
        self, payload_buffer, packet: utils.BufferType, offset
    ):
        self.bytes_read += utils.memcpy(payload_buffer, self.bytes_read, packet, offset)

    def _finish_message(self):
        # TODO Provide loaded message to SessionContext or handle it with this ChannelContext
        self.bytes_read = 0
        self.expected_payload_length = 0
        self.is_cont_packet_expected = False

    # CALLED BY WORKFLOW / SESSION CONTEXT

    async def write(self, msg: protobuf.MessageType, session_id: int = 0) -> None:
        pass
        # TODO protocol.write(self.iface, self.channel_id, session_id, msg)

    def create_new_session(
        self,
        passphrase="",
    ) -> None:  # TODO change it to output session data
        pass
        # TODO check, wheter a session with this passphrase already exists
        # if not, create a new session with this passphrase
        # if yes, what TODO TODO ???


def _is_ctrl_byte_continuation(ctrl_byte: int) -> bool:
    return ctrl_byte & 0x80 == CONTINUATION_PACKET


def _is_ctrl_byte_encrypted_transport(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == ENCRYPTED_TRANSPORT
