import struct
from typing import Optional, Tuple

from ..mapping import ProtobufMapping
from ..transport import MessagePayload
from ..transport.protocol import REPLEN, Protocol


class ProtocolV1(Protocol):
    """Protocol version 1. Currently (11/2018) in use on all Trezors.
    Does not understand sessions.
    """

    HEADER_LEN = struct.calcsize(">HL")

    def initialize_connection(
        self,
        mapping: "ProtobufMapping",
        session_id: Optional[bytes] = None,
        derive_caradano: Optional[bool] = None,
    ):
        from .. import messages

        msg = messages.Initialize(
            session_id=session_id,
            derive_cardano=derive_caradano,
        )
        msg_type, msg_data = mapping.encode(msg)
        self.write(msg_type, msg_data)
        (resp_type, resp_data) = self.read()
        return mapping.decode(resp_type, resp_data)

    def write(self, message_type: int, message_data: bytes) -> None:
        header = struct.pack(">HL", message_type, len(message_data))
        buffer = bytearray(b"##" + header + message_data)

        while buffer:
            # Report ID, data padded to 63 bytes
            chunk = b"?" + buffer[: REPLEN - 1]
            chunk = chunk.ljust(REPLEN, b"\x00")
            self.handle.write_chunk(chunk)
            buffer = buffer[63:]

    def read(self) -> MessagePayload:
        buffer = bytearray()
        # Read header with first part of message data
        msg_type, datalen, first_chunk = self.read_first()
        buffer.extend(first_chunk)

        # Read the rest of the message
        while len(buffer) < datalen:
            buffer.extend(self.read_next())

        return msg_type, buffer[:datalen]

    def read_first(self) -> Tuple[int, int, bytes]:
        chunk = self.handle.read_chunk()
        if chunk[:3] != b"?##":
            raise RuntimeError("Unexpected magic characters")
        try:
            msg_type, datalen = struct.unpack(">HL", chunk[3 : 3 + self.HEADER_LEN])
        except Exception:
            raise RuntimeError("Cannot parse header")

        data = chunk[3 + self.HEADER_LEN :]
        return msg_type, datalen, data

    def read_next(self) -> bytes:
        chunk = self.handle.read_chunk()
        if chunk[:1] != b"?":
            raise RuntimeError("Unexpected magic characters")
        return chunk[1:]

    def end_session(self, session_id: bytes) -> None:
        return super().end_session(session_id)
