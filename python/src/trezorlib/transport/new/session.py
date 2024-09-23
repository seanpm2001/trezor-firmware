from __future__ import annotations

import typing as t

from ... import models
from ...messages import Features, ThpCreateNewSession, ThpNewSession
from .protocol_v1 import ProtocolV1
from .protocol_v2 import ProtocolV2

if t.TYPE_CHECKING:
    from ...client import TrezorClient


class Session:

    def __init__(self, client: TrezorClient, id: bytes) -> None:
        self.client = client
        self._id = id

    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
    ) -> Session:
        raise NotImplementedError

    def call(self, msg: t.Any) -> t.Any:
        raise NotImplementedError

    def refresh_features(self) -> None:
        self.client.refresh_features()

    def end(self) -> None:
        raise NotImplementedError

    @property
    def features(self) -> Features:
        return self.client.features

    @property
    def model(self) -> models.TrezorModel:
        return self.client.model

    @property
    def version(self) -> t.Tuple[int, int, int]:
        return self.client.version

    @property
    def id(self) -> bytes:
        return self._id


class SessionV1(Session):
    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
    ) -> SessionV1:
        assert isinstance(client.protocol, ProtocolV1)
        session_id = client.features.session_id
        assert session_id is not None
        session = SessionV1(client, session_id)
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
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
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

    def __init__(self, client: TrezorClient, id: bytes) -> None:
        super().__init__(client, id)
        assert isinstance(client.protocol, ProtocolV2)

        self.channel: ProtocolV2 = client.protocol.get_channel()
        self.update_id_and_sid(id)

    def call(self, msg: t.Any) -> t.Any:
        self.channel.write(self.sid, msg)
        return self.channel.read(self.sid)

    def update_id_and_sid(self, id: bytes) -> None:
        self._id = id
        self.sid = int.from_bytes(id, "big")  # TODO update to extract only sid
