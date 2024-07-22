from ..transport.protocol import Handle, Protocol


class ProtocolV2(Protocol):
    def __init__(self, handle: Handle) -> None:
        super().__init__(handle)
