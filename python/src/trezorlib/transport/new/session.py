from __future__ import annotations

import typing as t

from ...messages import Features, Initialize, ThpCreateNewSession, ThpNewSession
from .protocol_and_channel import ProtocolV1
from .protocol_v2 import ProtocolV2

if t.TYPE_CHECKING:
    from .client import NewTrezorClient


class Session:
    features: Features

    def __init__(self, client: NewTrezorClient, id: bytes) -> None:
        self.client = client
        self.id = id

    @classmethod
    def new(
        cls, client: NewTrezorClient, passphrase: str, derive_cardano: bool
    ) -> Session:
        raise NotImplementedError

    def call(self, msg: t.Any) -> t.Any:
        raise NotImplementedError


class SessionV1(Session):
    @classmethod
    def new(
        cls, client: NewTrezorClient, passphrase: str, derive_cardano: bool
    ) -> SessionV1:
        assert isinstance(client.protocol, ProtocolV1)
        session = SessionV1(client, b"")
        session.features = session.call(
            # Initialize(passphrase=passphrase, derive_cardano=derive_cardano) # TODO
            Initialize()
        )
        session.id = session.features.session_id
        return session

    def call(self, msg: t.Any, should_reinit: bool = False) -> t.Any:
        # if should_reinit:
        #    self.initialize() # TODO
        if t.TYPE_CHECKING:
            assert isinstance(self.client.protocol, ProtocolV1)
        self.client.protocol.write(msg)
        return self.client.protocol.read()


class SessionV2(Session):

    @classmethod
    def new(
        cls, client: NewTrezorClient, passphrase: str, derive_cardano: bool
    ) -> SessionV2:

        assert isinstance(client.protocol, ProtocolV2)
        session = SessionV2(client, b"\x00")
        new_session: ThpNewSession = session.call(
            ThpCreateNewSession(passphrase=passphrase, derive_cardano=derive_cardano)
        )
        assert new_session.new_session_id is not None
        session_id = new_session.new_session_id
        session.update_id_and_sid(session_id.to_bytes(1, "big"))
        return session

    def __init__(self, client: NewTrezorClient, id: bytes) -> None:
        super().__init__(client, id)
        assert isinstance(client.protocol, ProtocolV2)

        self.channel: ProtocolV2 = client.protocol.get_channel()
        self.update_id_and_sid(id)
        if not self.channel.has_valid_features:
            self.channel.update_features()
        self.features = self.channel.features

    def call(self, msg: t.Any) -> t.Any:
        self.channel.write(self.sid, msg)
        return self.channel.read(self.sid)

    def update_id_and_sid(self, id: bytes) -> None:
        self.id = id
        self.sid = int.from_bytes(id, "big")  # TODO update to extract only sid
