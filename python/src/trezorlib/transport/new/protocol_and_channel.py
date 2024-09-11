from __future__ import annotations

import logging
import struct
import typing as t

from ...log import DUMP_BYTES
from ...mapping import ProtobufMapping
from .channel_data import ChannelData
from .transport import NewTransport

LOG = logging.getLogger(__name__)


class ProtocolAndChannel:
    def __init__(
        self,
        transport: NewTransport,
        mapping: ProtobufMapping,
        channel_keys: ChannelData | None = None,
    ) -> None:
        self.transport = transport
        self.mapping = mapping
        self.channel_keys = channel_keys

    def close(self) -> None: ...

    # def write(self, session_id: bytes, msg: t.Any) -> None: ...

    # def read(self, session_id: bytes) -> t.Any: ...

    def get_channel_keys(self) -> ChannelData: ...


class ProtocolV1(ProtocolAndChannel):
    HEADER_LEN = struct.calcsize(">HL")

    def read(self) -> t.Any:
        msg_type, msg_bytes = self._read()
        LOG.log(
            DUMP_BYTES,
            f"received type {msg_type} ({len(msg_bytes)} bytes): {msg_bytes.hex()}",
        )
        msg = self.mapping.decode(msg_type, msg_bytes)
        LOG.debug(
            f"received message: {msg.__class__.__name__}",
            extra={"protobuf": msg},
        )
        return msg

    def write(self, msg: t.Any) -> None:
        LOG.debug(
            f"sending message: {msg.__class__.__name__}",
            extra={"protobuf": msg},
        )
        msg_type, msg_bytes = self.mapping.encode(msg)
        LOG.log(
            DUMP_BYTES,
            f"encoded as type {msg_type} ({len(msg_bytes)} bytes): {msg_bytes.hex()}",
        )
        self._write(msg_type, msg_bytes)

    def _write(self, message_type: int, message_data: bytes) -> None:
        print("wooooo")
        chunk_size = self.transport.CHUNK_SIZE
        header = struct.pack(">HL", message_type, len(message_data))
        buffer = bytearray(b"##" + header + message_data)
        print("wooooo")

        while buffer:
            # Report ID, data padded to 63 bytes
            chunk = b"?" + buffer[: chunk_size - 1]
            chunk = chunk.ljust(chunk_size, b"\x00")
            self.transport.write_chunk(chunk)
            buffer = buffer[63:]

    def _read(self) -> t.Tuple[int, bytes]:
        buffer = bytearray()
        # Read header with first part of message data
        msg_type, datalen, first_chunk = self.read_first()
        buffer.extend(first_chunk)

        # Read the rest of the message
        while len(buffer) < datalen:
            buffer.extend(self.read_next())

        return msg_type, buffer[:datalen]

    def read_first(self) -> t.Tuple[int, int, bytes]:
        chunk = self.transport.read_chunk()
        if chunk[:3] != b"?##":
            raise RuntimeError("Unexpected magic characters")
        try:
            msg_type, datalen = struct.unpack(">HL", chunk[3 : 3 + self.HEADER_LEN])
        except Exception:
            raise RuntimeError("Cannot parse header")

        data = chunk[3 + self.HEADER_LEN :]
        return msg_type, datalen, data

    def read_next(self) -> bytes:
        chunk = self.transport.read_chunk()
        if chunk[:1] != b"?":
            raise RuntimeError("Unexpected magic characters")
        return chunk[1:]


class Channel:
    id: int
    channel_keys: ChannelData | None

    def __init__(self, id: int, keys: ChannelData) -> None:
        self.id = id
        self.channel_keys = keys

    def read(self) -> t.Any: ...
    def write(self, msg: t.Any) -> None: ...
