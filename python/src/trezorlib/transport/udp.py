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
import socket
import time
from typing import TYPE_CHECKING, Iterable, Optional, Tuple

from ..log import DUMP_PACKETS
from . import TransportException
from .protocol import Protocol, ProtocolBasedTransport, ProtocolV1

if TYPE_CHECKING:
    from ..models import TrezorModel

SOCKET_TIMEOUT = 10

LOG = logging.getLogger(__name__)


class UdpHandle:
    def __init__(self, device: "Tuple[str, int]") -> None:
        self.socket: Optional[socket.socket] = None
        self.device = device

    def open(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect(self.device)
        self.socket.settimeout(SOCKET_TIMEOUT)

    def close(self) -> None:
        if self.socket is not None:
            self.socket.close()
        self.socket = None

    def write_chunk(self, chunk: bytes) -> None:
        assert self.socket is not None
        if len(chunk) != 64:
            raise TransportException("Unexpected data length")
        LOG.log(DUMP_PACKETS, f"sending packet: {chunk.hex()}")
        self.socket.sendall(chunk)

    def read_chunk(self) -> bytes:
        assert self.socket is not None
        while True:
            try:
                chunk = self.socket.recv(64)
                break
            except socket.timeout:
                continue
        LOG.log(DUMP_PACKETS, f"received packet: {chunk.hex()}")
        if len(chunk) != 64:
            raise TransportException(f"Unexpected chunk size: {len(chunk)}")
        return bytearray(chunk)

    def ping(self) -> bool:
        """Test if the device is listening."""
        assert self.socket is not None
        resp = None
        try:
            self.socket.sendall(b"PINGPING")
            resp = self.socket.recv(8)
        except Exception:
            pass
        return resp == b"PONGPONG"


class UdpTransport(ProtocolBasedTransport):

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 21324
    PATH_PREFIX = "udp"
    ENABLED: bool = True

    def __init__(
        self,
        device: Optional[str] = None,
        protocol: Optional[Protocol] = None,
        skip_protocol_detection: bool = False,
    ) -> None:
        if not device:
            host = UdpTransport.DEFAULT_HOST
            port = UdpTransport.DEFAULT_PORT
        else:
            devparts = device.split(":")
            host = devparts[0]
            port = int(devparts[1]) if len(devparts) > 1 else UdpTransport.DEFAULT_PORT
        self.device = (host, port)
        self.handle: UdpHandle = UdpHandle(self.device)
        if protocol is None and not skip_protocol_detection:
            protocol = self.get_protocol()
        elif protocol is None:
            protocol = ProtocolV1(self.handle)

        super().__init__(protocol)

    def open(self) -> None:
        self.handle.open()

    def close(self) -> None:
        self.handle.close()

    def get_path(self) -> str:
        return "{}:{}:{}".format(self.PATH_PREFIX, *self.device)

    def find_debug(self) -> "UdpTransport":
        host, port = self.device
        return UdpTransport(f"{host}:{port + 1}")

    @classmethod
    def _try_path(cls, path: str) -> "UdpTransport":
        d = cls(path, skip_protocol_detection=False)
        try:
            d.open()
            if d._ping():
                return d
            else:
                raise TransportException(
                    f"No Trezor device found at address {d.get_path()}"
                )
        except Exception as e:
            raise TransportException(f"Error opening {d.get_path()}") from e

        finally:
            d.close()

    @classmethod
    def enumerate(
        cls, _models: Optional[Iterable["TrezorModel"]] = None
    ) -> Iterable["UdpTransport"]:
        default_path = f"{cls.DEFAULT_HOST}:{cls.DEFAULT_PORT}"
        try:
            return [cls._try_path(default_path)]
        except TransportException:
            return []

    @classmethod
    def find_by_path(cls, path: str, prefix_search: bool = False) -> "UdpTransport":
        try:
            address = path.replace(f"{cls.PATH_PREFIX}:", "")
            return cls._try_path(address)
        except TransportException:
            if not prefix_search:
                raise

        if prefix_search:
            return super().find_by_path(path, prefix_search)
        else:
            raise TransportException(f"No UDP device at {path}")

    def wait_until_ready(self, timeout: float = 10) -> None:
        try:
            self.open()
            start = time.monotonic()
            while True:
                if self._ping():
                    break
                elapsed = time.monotonic() - start
                if elapsed >= timeout:
                    raise TransportException("Timed out waiting for connection.")

                time.sleep(0.05)
        finally:
            self.close()

    def _ping(self) -> bool:
        """Test if the device is listening."""
        return self.handle.ping()
