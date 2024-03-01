class Message:
    def __init__(
        self,
        message_type: int,
        message_data: bytes,
        session_id: bytearray | None = None,
    ) -> None:
        self.type = message_type
        self.data = message_data
        self.session_id = session_id


class WireError(Exception):
    pass
