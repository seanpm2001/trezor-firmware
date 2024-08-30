# This file is part of the Trezor project.
#
# Copyright (C) 2012-2022 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import logging
from typing import TYPE_CHECKING, Optional, TypeVar

from typing_extensions import Protocol as StructuralType

from ..mapping import ProtobufMapping
from . import MessagePayload, Transport

PROTOCOL_VERSION_1 = 1
PROTOCOL_VERSION_2 = 2

REPLEN = 64

V2_FIRST_CHUNK = 0x01
V2_NEXT_CHUNK = 0x02
V2_BEGIN_SESSION = 0x03
V2_END_SESSION = 0x04

LOG = logging.getLogger(__name__)
if TYPE_CHECKING:

    T = TypeVar("T", bound="ProtocolBasedTransport")


class Handle(StructuralType):
    """PEP 544 structural type for Handle functionality.
    (called a "Protocol" in the proposed PEP, name which is impractical here)

    Handle is a "physical" layer for a protocol.
    It can open/close a connection and read/write bare data in 64-byte chunks.

    Functionally we gain nothing from making this an (abstract) base class for handle
    implementations, so this definition is for type hinting purposes only. You can,
    but don't have to, inherit from it.
    """

    def open(self) -> None: ...

    def close(self) -> None: ...

    def read_chunk(self) -> bytes: ...

    def write_chunk(self, chunk: bytes) -> None: ...


class Protocol:
    """Wire protocol that can communicate with a Trezor device, given a Handle.

    A Protocol implements the part of the Transport API that relates to communicating
    logical messages over a physical layer. It is a thing that can:
    - open and close sessions,
    - send and receive protobuf messages,
    given the ability to:
    - open and close physical connections,
    - and send and receive binary chunks.

    For now, the class also handles session counting and opening the underlying Handle.
    This will probably be removed in the future.

    We will need a new Protocol class if we change the way a Trezor device encapsulates
    its messages.
    """

    def __init__(self, handle: Handle) -> None:
        self.handle = handle
        self.session_counter = 0

    def initialize_connection(
        self,
        mapping: "ProtobufMapping",
        session_id: Optional[bytes] = None,
        derive_caradano: Optional[bool] = None,
    ):
        raise NotImplementedError

    def start_session(self, passphrase: bytes) -> bytes:
        raise NotImplementedError

    def resume_session(self, session_id: bytes) -> bytes:
        raise NotImplementedError

    def end_session(self, session_id: bytes) -> None:
        raise NotImplementedError

    # XXX we might be able to remove this now that TrezorClient does session handling
    def deprecated_begin_session(self) -> None:
        if self.session_counter == 0:
            self.handle.open()
        self.session_counter += 1

    def deprecated_end_session(self) -> None:
        self.session_counter = max(self.session_counter - 1, 0)
        if self.session_counter == 0:
            self.handle.close()

    def read(self) -> MessagePayload:
        raise NotImplementedError

    def write(self, message_type: int, message_data: bytes) -> None:
        raise NotImplementedError


class ProtocolBasedTransport(Transport):
    """Transport that implements its communications through a Protocol.

    Intended as a base class for implementations that proxy their communication
    operations to a Protocol.
    """

    def __init__(self, protocol: Protocol) -> None:
        self.protocol = protocol
        self.handle: Handle

    def write(self, message_type: int, message_data: bytes) -> None:
        self.protocol.write(message_type, message_data)

    def read(self) -> MessagePayload:
        return self.protocol.read()

    def initialize_connection(
        self,
        mapping: ProtobufMapping,
        session_id: Optional[bytes] = None,
        derive_cardano: Optional[bool] = None,
    ):
        return self.protocol.initialize_connection(mapping, session_id, derive_cardano)

    def start_session(self, passphrase: bytes) -> bytes:
        return self.protocol.start_session(passphrase)

    def resume_session(self, session_id: bytes) -> bytes:
        return self.protocol.resume_session(session_id)

    def end_session(self, session_id: bytes) -> None:
        return self.protocol.end_session(session_id)

    def deprecated_begin_session(self) -> None:
        self.protocol.deprecated_begin_session()

    def deprecated_end_session(self) -> None:
        self.protocol.deprecated_end_session()

    def get_protocol(self, version: Optional[int] = None) -> Protocol:
        if version is not None:
            return _get_protocol(version, self.handle)

        from .. import mapping, messages
        from ..messages import FailureType
        from .protocol_v1 import ProtocolV1

        request_type, request_data = mapping.DEFAULT_MAPPING.encode(
            messages.Initialize()
        )
        self.handle.open()
        protocol = ProtocolV1(self.handle)
        protocol.write(request_type, request_data)
        response_type, response_data = protocol.read()
        response = mapping.DEFAULT_MAPPING.decode(response_type, response_data)
        self.handle.close()
        if isinstance(response, messages.Failure):
            from .protocol_v2 import ProtocolV2

            if (
                response.code == FailureType.UnexpectedMessage
                and response.message == "Invalid protocol"
            ):
                LOG.debug("Protocol V2 detected")
                protocol = ProtocolV2(self.handle)

        return protocol


def _get_protocol(version: int, handle: Handle) -> Protocol:
    if version == PROTOCOL_VERSION_1:
        from .protocol_v1 import ProtocolV1

        return ProtocolV1(handle)

    if version == PROTOCOL_VERSION_2:
        from .protocol_v2 import ProtocolV2

        return ProtocolV2(handle)

    raise NotImplementedError
