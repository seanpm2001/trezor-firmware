from __future__ import annotations

import typing as t
from typing import TYPE_CHECKING, Iterable, Type, TypeVar

from ...exceptions import TrezorException

if TYPE_CHECKING:
    from ...models import TrezorModel

    T = TypeVar("T", bound="NewTransport")


class TransportException(TrezorException):
    pass


class NewTransport:
    PATH_PREFIX: str

    @classmethod
    def enumerate(
        cls: Type["T"], models: Iterable["TrezorModel"] | None = None
    ) -> Iterable["T"]:
        raise NotImplementedError

    @classmethod
    def find_by_path(cls: Type["T"], path: str, prefix_search: bool = False) -> "T":
        for device in cls.enumerate():

            if device.get_path() == path:
                return device

            if prefix_search and device.get_path().startswith(path):
                return device

        raise TransportException(f"{cls.PATH_PREFIX} device not found: {path}")

    def get_path(self) -> str: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def write_chunk(self, chunk: bytes) -> None: ...

    def read_chunk(self) -> bytes: ...

    CHUNK_SIZE: t.ClassVar[int]
