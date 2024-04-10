import ustruct  # pyright: ignore[reportMissingModuleSource]
from micropython import const  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING  # pyright:ignore[reportShadowedImports]

import usb
from storage import cache_thp
from storage.cache_thp import KEY_LENGTH, SESSION_ID_LENGTH, TAG_LENGTH, ChannelCache
from trezor import log, loop, protobuf, utils, workflow
from trezor.enums import FailureType, MessageType  # , ThpPairingMethod
from trezor.messages import Failure, ThpDeviceProperties
from trezor.wire import message_handler
from trezor.wire.thp import ack_handler, thp_messages
from trezor.wire.thp.handler_provider import get_handler

from ..protocol_common import Context, MessageWithType
from . import ChannelState, SessionState, checksum, crypto
from . import thp_session as THP
from .checksum import CHECKSUM_LENGTH
from .crypto import PUBKEY_LENGTH
from .thp_messages import (
    ACK_MESSAGE,
    CONTINUATION_PACKET,
    ENCRYPTED_TRANSPORT,
    ERROR,
    HANDSHAKE_COMP_REQ,
    HANDSHAKE_COMP_RES,
    HANDSHAKE_INIT_REQ,
    HANDSHAKE_INIT_RES,
    InitHeader,
)
from .thp_session import ThpError
from .writer import (
    CONT_DATA_OFFSET,
    INIT_DATA_OFFSET,
    REPORT_LENGTH,
    write_payload_to_wire,
)

if TYPE_CHECKING:
    from trezorio import WireInterface  # pyright:ignore[reportMissingImports]


_WIRE_INTERFACE_USB = b"\x01"
_MOCK_INTERFACE_HID = b"\x00"


MESSAGE_TYPE_LENGTH = const(2)

MAX_PAYLOAD_LEN = const(60000)


class Channel(Context):
    def __init__(self, channel_cache: ChannelCache) -> None:
        if __debug__:
            log.debug(__name__, "channel initialization")
        iface = _decode_iface(channel_cache.iface)
        super().__init__(iface, channel_cache.channel_id)
        self.channel_cache = channel_cache
        self.buffer: utils.BufferType
        self.waiting_for_ack_timeout: loop.spawn | None = None
        self.is_cont_packet_expected: bool = False
        self.expected_payload_length: int = 0
        self.bytes_read: int = 0
        self.selected_pairing_methods = []
        from trezor.wire.thp.session_context import load_cached_sessions

        self.connection_context = None

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
        if __debug__:
            log.debug(__name__, "get_channel_state: %s", _state_to_str(state))
        return state

    def get_channel_id_int(self) -> int:
        return int.from_bytes(self.channel_id, "big")

    def set_channel_state(self, state: ChannelState) -> None:
        if __debug__:
            log.debug(__name__, "set_channel_state: %s", _state_to_str(state))
        self.channel_cache.state = bytearray(state.to_bytes(1, "big"))

    def set_buffer(self, buffer: utils.BufferType) -> None:
        self.buffer = buffer
        if __debug__:
            log.debug(__name__, "set_buffer: %s", type(self.buffer))

    # CALLED BY THP_MAIN_LOOP

    async def receive_packet(self, packet: utils.BufferType):
        if __debug__:
            log.debug(__name__, "receive_packet")
        ctrl_byte = packet[0]
        if _is_ctrl_byte_continuation(ctrl_byte):
            await self._handle_cont_packet(packet)
        else:
            await self._handle_init_packet(packet)
        if __debug__:
            log.debug(__name__, "self.buffer: %s", utils.get_bytes_as_str(self.buffer))
        if self.expected_payload_length + INIT_DATA_OFFSET == self.bytes_read:
            self._finish_message()
            await self._handle_completed_message()
        elif self.expected_payload_length + INIT_DATA_OFFSET > self.bytes_read:
            self.is_cont_packet_expected = True
        else:
            raise ThpError(
                "Read more bytes than is the expected length of the message, this should not happen!"
            )

    async def _handle_init_packet(self, packet: utils.BufferType):
        if __debug__:
            log.debug(__name__, "handle_init_packet")
        ctrl_byte, _, payload_length = ustruct.unpack(">BHH", packet)
        self.expected_payload_length = payload_length
        packet_payload = packet[5:]
        # If the channel does not "own" the buffer lock, decrypt first packet
        # TODO do it only when needed!
        if _is_ctrl_byte_encrypted_transport(ctrl_byte):
            packet_payload = self._decrypt_single_packet_payload(packet_payload)

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
            if __debug__:
                log.exception(__name__, e)
        if __debug__:
            log.debug(__name__, "handle_init_packet - payload len: %d", payload_length)
        if __debug__:
            log.debug(__name__, "handle_init_packet - buffer len: %d", len(self.buffer))

        await self._buffer_packet_data(self.buffer, packet, 0)
        if __debug__:
            log.debug(__name__, "handle_init_packet - end")

    async def _handle_cont_packet(self, packet: utils.BufferType):
        if __debug__:
            log.debug(__name__, "handle_cont_packet")
        if not self.is_cont_packet_expected:
            raise ThpError("Continuation packet is not expected, ignoring")
        await self._buffer_packet_data(self.buffer, packet, CONT_DATA_OFFSET)

    async def _handle_completed_message(self) -> None:
        if __debug__:
            log.debug(__name__, "handle_completed_message")
        ctrl_byte, _, payload_length = ustruct.unpack(">BHH", self.buffer)
        message_length = payload_length + INIT_DATA_OFFSET

        self._check_checksum(message_length)

        # Synchronization process
        sync_bit = (ctrl_byte & 0x10) >> 4
        if __debug__:
            log.debug(
                __name__,
                "handle_completed_message - sync bit of message: %d",
                sync_bit,
            )

        # 1: Handle ACKs
        if _is_ctrl_byte_ack(ctrl_byte):
            ack_handler.handle_received_ACK(
                self.channel_cache, sync_bit, self.waiting_for_ack_timeout
            )
            self._todo_clear_buffer()
            return

        if (
            self._should_have_ctrl_byte_encrypted_transport()
            and not _is_ctrl_byte_encrypted_transport(ctrl_byte)
        ):
            self._todo_clear_buffer()
            raise ThpError("Message is not encrypted. Ignoring")

        # 2: Handle message with unexpected synchronization bit
        if sync_bit != THP.sync_get_receive_expected_bit(self.channel_cache):
            if __debug__:
                log.debug(
                    __name__, "Received message with an unexpected synchronization bit"
                )
            await self._send_ack(sync_bit)
            raise ThpError("Received message with an unexpected synchronization bit")

        # 3: Send ACK in response
        await self._send_ack(sync_bit)

        THP.sync_set_receive_expected_bit(self.channel_cache, 1 - sync_bit)

        await self._handle_message_to_app_or_channel(
            payload_length, message_length, ctrl_byte, sync_bit
        )
        if __debug__:
            log.debug(__name__, "handle_completed_message - end")

    def _check_checksum(self, message_length: int):
        if __debug__:
            log.debug(__name__, "check_checksum")
        if not checksum.is_valid(
            checksum=self.buffer[message_length - CHECKSUM_LENGTH : message_length],
            data=self.buffer[: message_length - CHECKSUM_LENGTH],
        ):
            self._todo_clear_buffer()
            if __debug__:
                log.debug(__name__, "Invalid checksum, ignoring message.")
            raise ThpError("Invalid checksum, ignoring message.")

    async def _handle_message_to_app_or_channel(
        self, payload_length: int, message_length: int, ctrl_byte: int, sync_bit: int
    ) -> None:
        state = self.get_channel_state()
        if __debug__:
            log.debug(__name__, "state: %s", _state_to_str(state))

        if state is ChannelState.ENCRYPTED_TRANSPORT:
            await self._handle_state_ENCRYPTED_TRANSPORT(message_length)
            return

        if state is ChannelState.TH1:
            await self._handle_state_TH1(
                payload_length, message_length, ctrl_byte, sync_bit
            )
            return

        if state is ChannelState.TH2:
            await self._handle_state_TH2(message_length, ctrl_byte, sync_bit)
            return
        if is_channel_state_pairing(state):
            await self._handle_pairing(message_length)
            return
        raise ThpError("Unimplemented channel state")

    async def _handle_state_TH1(
        self, payload_length: int, message_length: int, ctrl_byte: int, sync_bit: int
    ) -> None:
        if __debug__:
            log.debug(__name__, "handle_state_TH1")
        if not _is_ctrl_byte_handshake_init_req(ctrl_byte):
            raise ThpError("Message received is not a handshake init request!")
        if not payload_length == PUBKEY_LENGTH + CHECKSUM_LENGTH:
            raise ThpError("Message received is not a valid handshake init request!")
        host_ephemeral_key = bytearray(
            self.buffer[INIT_DATA_OFFSET : message_length - CHECKSUM_LENGTH]
        )
        cache_thp.set_channel_host_ephemeral_key(self.channel_cache, host_ephemeral_key)

        # send handshake init response message
        loop.schedule(
            self._write_encrypted_payload_loop(
                HANDSHAKE_INIT_RES, thp_messages.get_handshake_init_response()
            )
        )
        self.set_channel_state(ChannelState.TH2)
        return

    async def _handle_state_TH2(
        self, message_length: int, ctrl_byte: int, sync_bit: int
    ) -> None:
        if __debug__:
            log.debug(__name__, "handle_state_TH2")
        if not _is_ctrl_byte_handshake_comp_req(ctrl_byte):
            raise ThpError("Message received is not a handshake completion request!")
        host_encrypted_static_pubkey = self.buffer[
            INIT_DATA_OFFSET : INIT_DATA_OFFSET + KEY_LENGTH + TAG_LENGTH
        ]
        handshake_completion_request_noise_payload = self.buffer[
            INIT_DATA_OFFSET
            + KEY_LENGTH
            + TAG_LENGTH : message_length
            - CHECKSUM_LENGTH
        ]

        device_properties = thp_messages.decode_message(
            self.buffer[
                INIT_DATA_OFFSET
                + KEY_LENGTH
                + TAG_LENGTH : message_length
                - CHECKSUM_LENGTH
                - TAG_LENGTH
            ],
            0,
            "ThpDeviceProperties",
        )
        if TYPE_CHECKING:
            assert isinstance(device_properties, ThpDeviceProperties)
        for i in device_properties.pairing_methods:
            self.selected_pairing_methods.append(i)
        if __debug__:
            log.debug(
                __name__,
                "host static pubkey: %s, noise payload: %s",
                utils.get_bytes_as_str(host_encrypted_static_pubkey),
                utils.get_bytes_as_str(handshake_completion_request_noise_payload),
            )

        paired: bool = False  # TODO should be output from credential check

        # send hanshake completion response
        loop.schedule(
            self._write_encrypted_payload_loop(
                HANDSHAKE_COMP_RES,
                thp_messages.get_handshake_completion_response(paired=paired),
            )
        )
        # TODO add credential recognition
        if paired:
            self.set_channel_state(ChannelState.ENCRYPTED_TRANSPORT)
        else:
            self.set_channel_state(ChannelState.TP1)

    async def _handle_state_ENCRYPTED_TRANSPORT(self, message_length: int) -> None:
        if __debug__:
            log.debug(__name__, "handle_state_ENCRYPTED_TRANSPORT")
        self._decrypt_buffer(message_length)
        session_id, message_type = ustruct.unpack(">BH", self.buffer[INIT_DATA_OFFSET:])
        if session_id == 0:
            await self._handle_channel_message(message_length, message_type)
            return
        if session_id not in self.sessions:
            await self.write_error(
                FailureType.ThpUnallocatedSession, "Unallocated session"
            )
            raise ThpError("Unalloacted session")

        session_state = self.sessions[session_id].get_session_state()
        if session_state is SessionState.UNALLOCATED:
            await self.write_error(
                FailureType.ThpUnallocatedSession, "Unallocated session"
            )
            raise ThpError("Unalloacted session")
        self.sessions[session_id].incoming_message.publish(
            MessageWithType(
                message_type,
                self.buffer[
                    INIT_DATA_OFFSET
                    + MESSAGE_TYPE_LENGTH
                    + SESSION_ID_LENGTH : message_length
                    - CHECKSUM_LENGTH
                    - TAG_LENGTH
                ],
            )
        )

    async def _handle_pairing(self, message_length: int) -> None:
        from .pairing_context import PairingContext

        if self.connection_context is None:
            self.connection_context = PairingContext(self)
            loop.schedule(self.connection_context.handle())

        print("TEST selected methods")
        for i in self.selected_pairing_methods:
            print("method:", i)
        self._decrypt_buffer(message_length)

        message_type = ustruct.unpack(
            ">H", self.buffer[INIT_DATA_OFFSET + SESSION_ID_LENGTH :]
        )[0]

        self.connection_context.incoming_message.publish(
            MessageWithType(
                message_type,
                self.buffer[
                    INIT_DATA_OFFSET
                    + MESSAGE_TYPE_LENGTH
                    + SESSION_ID_LENGTH : message_length
                    - CHECKSUM_LENGTH
                    - TAG_LENGTH
                ],
            )
        )
        # 1. Check that message is expected with respect to the current state
        # 2. Handle the message
        pass

    def _should_have_ctrl_byte_encrypted_transport(self) -> bool:
        if self.get_channel_state() in [
            ChannelState.UNALLOCATED,
            ChannelState.TH1,
            ChannelState.TH2,
        ]:
            return False
        return True

    async def _handle_channel_message(
        self, message_length: int, message_type: int
    ) -> None:
        buf = self.buffer[
            INIT_DATA_OFFSET + 3 : message_length - CHECKSUM_LENGTH - TAG_LENGTH
        ]

        expected_type = protobuf.type_for_wire(message_type)
        message = message_handler.wrap_protobuf_load(buf, expected_type)
        if __debug__:
            log.debug(__name__, "handle_channel_message: %s", message)
        # TODO handle other messages than CreateNewSession

        handler = get_handler(message)
        task = handler(self, message)
        response_message = await task
        # TODO handle
        await self.write(response_message)

    def _decrypt_single_packet_payload(self, payload: bytes) -> bytearray:
        payload_buffer = bytearray(payload)
        crypto.decrypt(b"\x00", b"\x00", payload_buffer, INIT_DATA_OFFSET, len(payload))
        return payload_buffer

    def _decrypt_buffer(self, message_length: int) -> None:
        if not isinstance(self.buffer, bytearray):
            self.buffer = bytearray(self.buffer)
        crypto.decrypt(
            b"\x00",
            b"\x00",
            self.buffer,
            INIT_DATA_OFFSET,
            message_length - INIT_DATA_OFFSET - CHECKSUM_LENGTH,
        )

    def _encrypt(self, buffer: bytearray, noise_payload_len: int) -> None:
        if __debug__:
            log.debug(__name__, "encrypt")
        min_required_length = noise_payload_len + TAG_LENGTH + CHECKSUM_LENGTH
        if len(buffer) < min_required_length or not isinstance(buffer, bytearray):
            new_buffer = bytearray(min_required_length)
            utils.memcpy(new_buffer, 0, buffer, 0)
            buffer = new_buffer
        tag = crypto.encrypt(
            b"\x00",
            b"\x00",
            buffer,
            0,
            noise_payload_len,
        )
        buffer[noise_payload_len : noise_payload_len + TAG_LENGTH] = tag

    async def _buffer_packet_data(
        self, payload_buffer: utils.BufferType, packet: utils.BufferType, offset: int
    ):
        self.bytes_read += utils.memcpy(payload_buffer, self.bytes_read, packet, offset)

    def _finish_message(self):
        self.bytes_read = 0
        self.expected_payload_length = 0
        self.is_cont_packet_expected = False

    async def _send_ack(self, ack_bit: int) -> None:
        ctrl_byte = self._add_sync_bit_to_ctrl_byte(ACK_MESSAGE, ack_bit)
        header = InitHeader(ctrl_byte, self.get_channel_id_int(), CHECKSUM_LENGTH)
        chksum = checksum.compute(header.to_bytes())
        if __debug__:
            log.debug(
                __name__,
                "Writing ACK message to a channel with id: %d, sync bit: %d",
                self.get_channel_id_int(),
                ack_bit,
            )
        await write_payload_to_wire(self.iface, header, chksum)

    def _add_sync_bit_to_ctrl_byte(self, ctrl_byte, sync_bit):
        if sync_bit == 0:
            return ctrl_byte & 0xEF
        if sync_bit == 1:
            return ctrl_byte | 0x10
        raise ThpError("Unexpected synchronization bit")

    # CALLED BY WORKFLOW / SESSION CONTEXT

    async def write(self, msg: protobuf.MessageType, session_id: int = 0) -> None:
        if __debug__:
            log.debug(__name__, "write message: %s", msg.MESSAGE_NAME)
        noise_payload_len = self._encode_into_buffer(msg, session_id)
        await self.write_and_encrypt(self.buffer[:noise_payload_len])

    async def write_error(self, err_type: FailureType, message: str) -> None:
        if __debug__:
            log.debug(__name__, "write_error")
        msg_size = self._encode_error_into_buffer(err_type, message)
        data_length = MESSAGE_TYPE_LENGTH + msg_size
        header: InitHeader = InitHeader(
            ERROR, self.get_channel_id_int(), data_length + CHECKSUM_LENGTH
        )
        chksum = checksum.compute(
            header.to_bytes() + memoryview(self.buffer[:data_length])
        )

        utils.memcpy(self.buffer, data_length, chksum, 0)
        await write_payload_to_wire(
            self.iface, header, memoryview(self.buffer[: data_length + CHECKSUM_LENGTH])
        )

    async def write_and_encrypt(self, payload: bytes) -> None:
        payload_length = len(payload)

        if not isinstance(self.buffer, bytearray):
            self.buffer = bytearray(self.buffer)
        self._encrypt(self.buffer, payload_length)
        payload_length = payload_length + TAG_LENGTH

        loop.schedule(
            self._write_encrypted_payload_loop(
                ENCRYPTED_TRANSPORT, memoryview(self.buffer[:payload_length])
            )
        )

    async def _write_encrypted_payload_loop(
        self, ctrl_byte: int, payload: bytes
    ) -> None:
        if __debug__:
            log.debug(__name__, "write_encrypted_payload_loop")
        payload_len = len(payload) + CHECKSUM_LENGTH
        sync_bit = THP.sync_get_send_bit(self.channel_cache)
        ctrl_byte = self._add_sync_bit_to_ctrl_byte(ctrl_byte, sync_bit)
        header = InitHeader(ctrl_byte, self.get_channel_id_int(), payload_len)
        chksum = checksum.compute(header.to_bytes() + payload)
        payload = payload + chksum

        # TODO add condition that disallows to write when can_send_message is false
        THP.sync_set_can_send_message(self.channel_cache, False)
        while True:
            if __debug__:
                log.debug(
                    __name__,
                    "write_encrypted_payload_loop - loop start, sync_bit: %d, sync_send_bit: %d",
                    (header.ctrl_byte & 0x10) >> 4,
                    THP.sync_get_send_bit(self.channel_cache),
                )
            await write_payload_to_wire(self.iface, header, payload)
            self.waiting_for_ack_timeout = loop.spawn(self._wait_for_ack())
            try:
                await self.waiting_for_ack_timeout
            except loop.TaskClosed:
                break

        THP.sync_set_send_bit_to_opposite(self.channel_cache)

        # Let the main loop be restarted and clear loop, if there is no other
        # workflow and the state is ENCRYPTED_TRANSPORT
        if (
            not workflow.tasks
            and self.get_channel_state() is ChannelState.ENCRYPTED_TRANSPORT
        ):
            loop.clear()

    async def _wait_for_ack(self) -> None:
        await loop.sleep(1000)

    def _encode_into_buffer(self, msg: protobuf.MessageType, session_id: int) -> int:

        # cannot write message without wire type
        assert msg.MESSAGE_WIRE_TYPE is not None

        msg_size = protobuf.encoded_length(msg)
        payload_size = SESSION_ID_LENGTH + MESSAGE_TYPE_LENGTH + msg_size
        required_min_size = payload_size + CHECKSUM_LENGTH + TAG_LENGTH

        if required_min_size > len(self.buffer):
            # message is too big, we need to allocate a new buffer
            self.buffer = bytearray(required_min_size)

        buffer = self.buffer

        _encode_session_into_buffer(memoryview(buffer), session_id)
        _encode_message_type_into_buffer(
            memoryview(buffer), msg.MESSAGE_WIRE_TYPE, SESSION_ID_LENGTH
        )
        _encode_message_into_buffer(
            memoryview(buffer), msg, SESSION_ID_LENGTH + MESSAGE_TYPE_LENGTH
        )

        return payload_size

    def _encode_error_into_buffer(self, err_code: FailureType, message: str) -> int:
        error_message: protobuf.MessageType = Failure(code=err_code, message=message)
        _encode_message_type_into_buffer(memoryview(self.buffer), MessageType.Failure)
        _encode_message_into_buffer(
            memoryview(self.buffer), error_message, MESSAGE_TYPE_LENGTH
        )
        return protobuf.encoded_length(error_message)

    def _todo_clear_buffer(self):
        # TODO Buffer clearing not implemented
        pass


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
    if __debug__:
        log.debug(__name__, "get_buffer_for_message - length: %d", length)
        log.debug(
            __name__,
            "get_buffer_for_message - existing buffer type: %s",
            type(existing_buffer),
        )
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


def _is_ctrl_byte_handshake_init_req(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == HANDSHAKE_INIT_REQ


def _is_ctrl_byte_handshake_comp_req(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == HANDSHAKE_COMP_REQ


def _is_ctrl_byte_ack(ctrl_byte: int) -> bool:
    return ctrl_byte & 0xEF == ACK_MESSAGE


def is_channel_state_pairing(state: int) -> bool:
    if state in (
        ChannelState.TP1,
        ChannelState.TP2,
        ChannelState.TP3,
        ChannelState.TP4,
        ChannelState.TC1,
    ):
        return True
    return False


def _encode_session_into_buffer(
    buffer: memoryview, session_id: int, buffer_offset: int = 0
) -> None:
    session_id_bytes = int.to_bytes(session_id, SESSION_ID_LENGTH, "big")
    utils.memcpy(buffer, buffer_offset, session_id_bytes, 0)


def _encode_message_type_into_buffer(
    buffer: memoryview, message_type: int, offset: int = 0
) -> None:
    msg_type_bytes = int.to_bytes(message_type, MESSAGE_TYPE_LENGTH, "big")
    utils.memcpy(buffer, offset, msg_type_bytes, 0)


def _encode_message_into_buffer(
    buffer: memoryview, message: protobuf.MessageType, buffer_offset: int = 0
) -> None:
    protobuf.encode(memoryview(buffer[buffer_offset:]), message)


def _state_to_str(state: int) -> str:
    name = {
        v: k for k, v in ChannelState.__dict__.items() if not k.startswith("__")
    }.get(state)
    if name is not None:
        return name
    return "UNKNOWN_STATE"
