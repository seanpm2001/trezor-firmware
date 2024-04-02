import ustruct  # pyright: ignore[reportMissingModuleSource]
from micropython import const  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING  # pyright:ignore[reportShadowedImports]
from ubinascii import hexlify

import usb
from storage import cache_thp
from storage.cache_thp import KEY_LENGTH, SESSION_ID_LENGTH, TAG_LENGTH, ChannelCache
from trezor import io, log, loop, protobuf, utils
from trezor.messages import ThpCreateNewSession
from trezor.wire import message_handler
from trezor.wire.thp import thp_messages

from ..protocol_common import Context, MessageWithType
from . import ChannelState, SessionState, checksum
from . import thp_session as THP
from .checksum import CHECKSUM_LENGTH
from .thp_messages import (
    ACK_MESSAGE,
    CONTINUATION_PACKET,
    ENCRYPTED_TRANSPORT,
    HANDSHAKE_INIT,
    InitHeader,
)
from .thp_session import ThpError

if TYPE_CHECKING:
    from trezorio import WireInterface  # pyright:ignore[reportMissingImports]


_WIRE_INTERFACE_USB = b"\x01"
_MOCK_INTERFACE_HID = b"\x00"

_PUBKEY_LENGTH = const(32)

INIT_DATA_OFFSET = const(5)
CONT_DATA_OFFSET = const(3)

MESSAGE_TYPE_LENGTH = const(2)

REPORT_LENGTH = const(64)
MAX_PAYLOAD_LEN = const(60000)

_ACK_MESSAGE = 0x20


class Channel(Context):
    def __init__(self, channel_cache: ChannelCache) -> None:
        iface = _decode_iface(channel_cache.iface)
        super().__init__(iface, channel_cache.channel_id)
        self.channel_cache = channel_cache
        self.buffer: utils.BufferType
        self.waiting_for_ack_timeout: loop.spawn | None
        self.is_cont_packet_expected: bool = False
        self.expected_payload_length: int = 0
        self.bytes_read = 0
        from trezor.wire.thp.session_context import load_cached_sessions

        self.sessions = load_cached_sessions(self)

    @classmethod
    def create_new_channel(
        cls, iface: WireInterface, buffer: utils.BufferType
    ) -> "Channel":
        channel_cache = cache_thp.get_new_unauthenticated_channel(_encode_iface(iface))
        r = cls(channel_cache)
        r.set_buffer(buffer)
        r.set_channel_state(ChannelState.TH1)
        return r

    # ACCESS TO CHANNEL_DATA

    def get_channel_state(self) -> int:
        state = int.from_bytes(self.channel_cache.state, "big")
        print("get_ch_state", state)
        return state

    def set_channel_state(self, state: ChannelState) -> None:
        print("set_ch_state", int.from_bytes(state.to_bytes(1, "big"), "big"))
        self.channel_cache.state = bytearray(state.to_bytes(1, "big"))

    def set_buffer(self, buffer: utils.BufferType) -> None:
        self.buffer = buffer
        print("set buffer channel", type(self.buffer))

    # CALLED BY THP_MAIN_LOOP

    async def receive_packet(self, packet: utils.BufferType):
        print("receive packet")
        ctrl_byte = packet[0]
        if _is_ctrl_byte_continuation(ctrl_byte):
            await self._handle_cont_packet(packet)
        else:
            await self._handle_init_packet(packet)

        if self.expected_payload_length + INIT_DATA_OFFSET == self.bytes_read:
            self._finish_message()
            await self._handle_completed_message()

    async def _handle_init_packet(self, packet: utils.BufferType):
        print("handle_init_packet")
        ctrl_byte, _, payload_length = ustruct.unpack(">BHH", packet)
        self.expected_payload_length = payload_length
        packet_payload = packet[5:]
        # If the channel does not "own" the buffer lock, decrypt first packet
        # TODO do it only when needed!
        if _is_ctrl_byte_encrypted_transport(ctrl_byte):
            packet_payload = self._decrypt(packet_payload)

        state = self.get_channel_state()

        if state is ChannelState.ENCRYPTED_TRANSPORT:
            session_id = packet_payload[0]
            if session_id == 0:
                pass
                # TODO use small buffer
            else:
                pass
                # TODO use big buffer but only if the channel owns the buffer lock.
                # Otherwise send BUSY message and return
        else:
            pass
            # TODO use small buffer
        try:
            # TODO for now, we create a new big buffer every time. It should be changed
            self.buffer: utils.BufferType = _get_buffer_for_message(
                payload_length, self.buffer
            )
        except Exception as e:
            print(e)
        print("payload len", payload_length)
        print("len", len(self.buffer))
        await self._buffer_packet_data(self.buffer, packet, 0)
        print("end init")

    async def _handle_cont_packet(self, packet: utils.BufferType):
        print("cont")
        if not self.is_cont_packet_expected:
            return  # Continuation packet is not expected, ignoring
        await self._buffer_packet_data(self.buffer, packet, CONT_DATA_OFFSET)

    async def _handle_completed_message(self):
        print("handling completed message")
        print("send snyc bit::", THP.sync_get_send_bit(self.channel_cache))
        ctrl_byte, _, payload_length = ustruct.unpack(">BHH", self.buffer)
        msg_len = payload_length + INIT_DATA_OFFSET

        print("checksum check")
        # printBytes(self.buffer)

        if not checksum.is_valid(
            checksum=self.buffer[msg_len - CHECKSUM_LENGTH : msg_len],
            data=self.buffer[: msg_len - CHECKSUM_LENGTH],
        ):
            # checksum is not valid -> ignore message
            self._todo_clear_buffer()
            return

        # Synchronization process
        sync_bit = (ctrl_byte & 0x10) >> 4
        print("sync bit:", sync_bit)

        # 1: Handle ACKs
        if _is_ctrl_byte_ack(ctrl_byte):
            self._handle_received_ACK(sync_bit)
            self._todo_clear_buffer()
            return

        # 2: Handle message with unexpected synchronization bit
        if sync_bit != THP.sync_get_receive_expected_bit(self.channel_cache):
            if __debug__:
                log.debug(
                    __name__, "Received message with an unexpected synchronization bit"
                )
            await self._sendAck(sync_bit)
            raise ThpError("Received message with an unexpected synchronization bit")

        # 3: Send ACK in response
        if __debug__:
            log.debug(
                __name__,
                "Writing ACK message to a channel with id: %d, sync bit: %d",
                self.channel_id,
                sync_bit,
            )
        await self._sendAck(sync_bit)
        print("___set receive bit to", 1 - sync_bit)
        THP.sync_set_receive_expected_bit(self.channel_cache, 1 - sync_bit)

        state = self.get_channel_state()
        if __debug__:
            log.debug(__name__, _state_to_str(state))

        if state is ChannelState.TH1:
            if not _is_ctrl_byte_handshake_init:
                raise ThpError("Message received is not a handshake init request!")
            if not payload_length == _PUBKEY_LENGTH + CHECKSUM_LENGTH:
                raise ThpError(
                    "Message received is not a valid handshake init request!"
                )
            host_ephemeral_key = bytearray(
                self.buffer[INIT_DATA_OFFSET : msg_len - CHECKSUM_LENGTH]
            )
            cache_thp.set_channel_host_ephemeral_key(
                self.channel_cache, host_ephemeral_key
            )
            # TODO send ack in response
            # TODO send handshake init response message
            loop.schedule(
                self._write_encrypted_payload_loop(
                    thp_messages.get_handshake_init_response()
                )
            )
            self.set_channel_state(ChannelState.TH2)
            return

        if not _is_ctrl_byte_encrypted_transport(ctrl_byte):
            print("Message is not encrypted. Ignoring")
            # TODO ignore message
            self._todo_clear_buffer()
            return

        if state is ChannelState.ENCRYPTED_TRANSPORT:
            self._decrypt_buffer()
            session_id, message_type = ustruct.unpack(
                ">BH", self.buffer[INIT_DATA_OFFSET:]
            )
            if session_id == 0:
                try:
                    buf = self.buffer[INIT_DATA_OFFSET + 3 : msg_len - CHECKSUM_LENGTH]

                    expected_type = protobuf.type_for_wire(message_type)
                    message = message_handler.wrap_protobuf_load(buf, expected_type)
                    print(message)
                    # TODO handle other messages than CreateNewSession
                    assert isinstance(message, ThpCreateNewSession)
                    print("passphrase:", message.passphrase)
                    # await thp_messages.handle_CreateNewSession(message)
                    if message.passphrase is not None:
                        self.create_new_session(message.passphrase)
                    else:
                        self.create_new_session()
                except Exception as e:
                    print("Proč??")
                    print(e)
                return
                # TODO not finished

            if session_id not in self.sessions:
                raise Exception("Unalloacted session")  # TODO send error message

            session_state = self.sessions[session_id].get_session_state()
            if session_state is SessionState.UNALLOCATED:
                raise Exception("Unalloacted session")  # TODO send error message

            self.sessions[session_id].incoming_message.publish(
                MessageWithType(
                    message_type,
                    self.buffer[INIT_DATA_OFFSET + 3 : msg_len - CHECKSUM_LENGTH],
                )
            )

        if state is ChannelState.TH2:
            print("th2 branche")
            host_encrypted_static_pubkey = self.buffer[
                INIT_DATA_OFFSET : INIT_DATA_OFFSET + KEY_LENGTH + TAG_LENGTH
            ]
            handshake_completion_request_noise_payload = self.buffer[
                INIT_DATA_OFFSET + KEY_LENGTH + TAG_LENGTH : msg_len - CHECKSUM_LENGTH
            ]
            print(
                host_encrypted_static_pubkey,
                handshake_completion_request_noise_payload,
            )  # TODO remove
            # TODO send ack in response
            # TODO send hanshake completion response
            loop.schedule(
                self._write_encrypted_payload_loop(
                    thp_messages.get_handshake_init_response()
                )
            )
            self.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
        print("end handle completed message")

    def _decrypt(self, payload) -> bytes:
        return payload  # TODO add decryption process

    def _decrypt_buffer(self) -> None:
        pass
        # TODO decode buffer in place

    async def _buffer_packet_data(
        self, payload_buffer: utils.BufferType, packet: utils.BufferType, offset: int
    ):
        self.bytes_read += utils.memcpy(payload_buffer, self.bytes_read, packet, offset)
        print("bytes, read:", self.bytes_read)

    def _finish_message(self):
        self.bytes_read = 0
        self.expected_payload_length = 0
        self.is_cont_packet_expected = False

    async def _sendAck(self, ack_bit: int) -> None:
        ctrl_byte = self._add_sync_bit_to_ctrl_byte(_ACK_MESSAGE, ack_bit)
        header = InitHeader(
            ctrl_byte, int.from_bytes(self.channel_id, "big"), CHECKSUM_LENGTH
        )
        chksum = checksum.compute(header.to_bytes())
        await self._write_encrypted_payload(header, chksum, CHECKSUM_LENGTH)

    def _add_sync_bit_to_ctrl_byte(self, ctrl_byte, sync_bit):
        if sync_bit == 0:
            return ctrl_byte & 0xEF
        if sync_bit == 1:
            return ctrl_byte | 0x10
        raise ThpError("Unexpected synchronization bit")

    # CALLED BY WORKFLOW / SESSION CONTEXT

    async def write(self, msg: protobuf.MessageType, session_id: int = 0) -> None:
        print("write")

        noise_payload_len = self._encode_into_buffer(msg, session_id)

        # trezor.crypto.noise.encode(key, payload=self.buffer)

        # TODO payload_len should be output from trezor.crypto.noise.encode
        payload_len = noise_payload_len  # + TAG_LENGTH # TODO

        loop.schedule(self._write_encrypted_payload_loop(self.buffer[:payload_len]))

    async def _write_encrypted_payload_loop(self, payload: bytes) -> None:
        print("write loop before while")
        payload_len = len(payload)
        sync_bit = THP.sync_get_send_bit(self.channel_cache)
        ctrl_byte = self._add_sync_bit_to_ctrl_byte(ENCRYPTED_TRANSPORT, sync_bit)
        header = InitHeader(
            ctrl_byte, int.from_bytes(self.channel_id, "big"), payload_len
        )
        # TODO add condition that disallows to write when can_send_message is false
        THP.sync_set_can_send_message(self.channel_cache, False)
        while True:
            print(
                "write encrypted payload loop - start, sync_bit:",
                header.ctrl_byte & 0x10,
                " send_sync_bit:",
                THP.sync_get_send_bit(self.channel_cache),
            )
            await self._write_encrypted_payload(header, payload, payload_len)
            self.waiting_for_ack_timeout = loop.spawn(self._wait_for_ack())
            try:
                await self.waiting_for_ack_timeout
            except loop.TaskClosed:
                THP.sync_set_send_bit_to_opposite(self.channel_cache)
                break

    async def _write_encrypted_payload(
        self, header: InitHeader, payload: bytes, payload_len: int
    ):

        # prepare the report buffer with header data
        report = bytearray(REPORT_LENGTH)
        header.pack_to_buffer(report)

        # write initial report
        nwritten = utils.memcpy(report, INIT_DATA_OFFSET, payload, 0)
        await self._write_report(report)

        # if we have more data to write, use continuation reports for it
        if nwritten < payload_len:
            header.pack_to_cont_buffer(report)
        while nwritten < payload_len:
            nwritten += utils.memcpy(report, CONT_DATA_OFFSET, payload, nwritten)
            await self._write_report(report)

    async def _write_report(self, report: utils.BufferType) -> None:
        while True:
            await loop.wait(self.iface.iface_num() | io.POLL_WRITE)
            n = self.iface.write(report)
            if n == len(report):
                return

    async def _wait_for_ack(self) -> None:
        await loop.sleep(1000)

    def _encode_into_buffer(self, msg: protobuf.MessageType, session_id: int) -> int:

        # cannot write message without wire type
        assert msg.MESSAGE_WIRE_TYPE is not None

        msg_size = protobuf.encoded_length(msg)
        offset = SESSION_ID_LENGTH + MESSAGE_TYPE_LENGTH
        payload_size = offset + msg_size

        if payload_size > len(self.buffer) or not isinstance(self.buffer, bytearray):
            # message is too big or buffer is not bytearray, we need to allocate a new buffer
            self.buffer = bytearray(payload_size)

        buffer = self.buffer
        session_id_bytes = int.to_bytes(session_id, SESSION_ID_LENGTH, "big")
        msg_type_bytes = int.to_bytes(msg.MESSAGE_WIRE_TYPE, MESSAGE_TYPE_LENGTH, "big")

        utils.memcpy(buffer, 0, session_id_bytes, 0)
        utils.memcpy(buffer, SESSION_ID_LENGTH, msg_type_bytes, 0)
        assert isinstance(buffer, bytearray)
        msg_size = protobuf.encode(buffer[offset:], msg)
        return payload_size

    def create_new_session(
        self,
        passphrase="",
    ) -> None:  # TODO change it to output session data
        print("create new session")
        from trezor.wire.thp.session_context import SessionContext

        session = SessionContext.create_new_session(self)
        self.sessions[session.session_id] = session
        loop.schedule(session.handle())
        print("new session created. Session id:", session.session_id)

    def _todo_clear_buffer(self):
        # TODO Buffer clearing not implemented
        pass

    # TODO add debug logging to ACK handling
    def _handle_received_ACK(self, sync_bit: int) -> None:
        if self._ack_is_not_expected():
            print("ack is not expected")
            return
        if self._ack_has_incorrect_sync_bit(sync_bit):
            print("ack has incorrect sync bit")
            return

        if self.waiting_for_ack_timeout is not None:
            self.waiting_for_ack_timeout.close()
            print("closed waiting for ack")

        THP.sync_set_can_send_message(self.channel_cache, True)

    def _ack_is_not_expected(self) -> bool:
        return THP.sync_can_send_message(self.channel_cache)

    def _ack_has_incorrect_sync_bit(self, sync_bit: int) -> bool:
        return THP.sync_get_send_bit(self.channel_cache) != sync_bit


def load_cached_channels(buffer: utils.BufferType) -> dict[int, Channel]:  # TODO
    channels: dict[int, Channel] = {}
    cached_channels = cache_thp.get_all_allocated_channels()
    for c in cached_channels:
        channels[int.from_bytes(c.channel_id, "big")] = Channel(c)
    for c in channels.values():
        c.set_buffer(buffer)
    return channels


def _decode_iface(cached_iface: bytes) -> WireInterface:
    if cached_iface == _WIRE_INTERFACE_USB:
        iface = usb.iface_wire
        if iface is None:
            raise RuntimeError("There is no valid USB WireInterface")
        return iface
    if __debug__ and cached_iface == _MOCK_INTERFACE_HID:
        raise NotImplementedError("Should return MockHID WireInterface")
    # TODO implement bluetooth interface
    raise Exception("Unknown WireInterface")


def _encode_iface(iface: WireInterface) -> bytes:
    if iface is usb.iface_wire:
        return _WIRE_INTERFACE_USB
    # TODO implement bluetooth interface
    if __debug__:
        return _MOCK_INTERFACE_HID
    raise Exception("Unknown WireInterface")


def _get_buffer_for_message(
    payload_length: int, existing_buffer: utils.BufferType, max_length=MAX_PAYLOAD_LEN
) -> utils.BufferType:
    length = payload_length + INIT_DATA_OFFSET
    print("length", length)
    print("existing buffer type", type(existing_buffer))
    if length > max_length:
        raise ThpError("Message too large")

    if length > len(existing_buffer):
        # allocate a new buffer to fit the message
        try:
            payload: utils.BufferType = bytearray(length)
        except MemoryError:
            payload = bytearray(REPORT_LENGTH)
            raise ThpError("Message too large")
        return payload

    # reuse a part of the supplied buffer
    return memoryview(existing_buffer)[:length]


def _is_ctrl_byte_continuation(ctrl_byte: int) -> bool:
    return ctrl_byte & 0x80 == CONTINUATION_PACKET


def _is_ctrl_byte_encrypted_transport(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == ENCRYPTED_TRANSPORT


def _is_ctrl_byte_handshake_init(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == HANDSHAKE_INIT


def _is_ctrl_byte_ack(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == ACK_MESSAGE


def _state_to_str(state: int) -> str:
    if state == ChannelState.ENCRYPTED_TRANSPORT:
        return "state: encrypted transport"
    elif state == ChannelState.TH1:
        return "state: th1"
    elif state == ChannelState.TH2:
        return "state: th2"
    elif state == ChannelState.TP1:
        return "state: tp1"
    elif state == ChannelState.TP2:
        return "state: tp2"
    elif state == ChannelState.TP3:
        return "state: tp3"
    elif state == ChannelState.TP4:
        return "state: tp4"
    elif state == ChannelState.TP5:
        return "state: tp5"
    elif state == ChannelState.UNALLOCATED:
        return "state: unallocated"
    elif state == ChannelState.UNAUTHENTICATED:
        return "state: unauthenticated"
    else:
        return "state: <not implemented>"


def printBytes(a):
    print(hexlify(a).decode("utf-8"))
