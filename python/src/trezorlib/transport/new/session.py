from __future__ import annotations

import typing as t

from ... import models
from ...messages import (
    Features,
    GetFeatures,
    Initialize,
    ThpCreateNewSession,
    ThpNewSession,
)
from .protocol_and_channel import ProtocolV1
from .protocol_v2 import ProtocolV2

if t.TYPE_CHECKING:
    from ...client import TrezorClient


class Session:

    def __init__(self, client: TrezorClient, id: bytes) -> None:
        self.client = client
        self.id = id

    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
    ) -> Session:
        raise NotImplementedError

    def call(self, msg: t.Any) -> t.Any:
        raise NotImplementedError

    def refresh_features(self) -> None:
        raise NotImplementedError

    def get_features(self) -> Features:
        raise NotImplementedError

    def get_model(self) -> models.TrezorModel:
        features = self.get_features()
        model = models.by_name(features.model or "1")

        if model is None:
            raise RuntimeError(
                "Unsupported Trezor model"
                f" (internal_model: {features.internal_model}, model: {features.model})"
            )
        return model

    def get_version(self) -> t.Tuple[int, int, int]:
        features = self.get_features()
        version = (
            features.major_version,
            features.minor_version,
            features.patch_version,
        )
        return version


class SessionV1(Session):
    features: Features

    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
    ) -> SessionV1:
        assert isinstance(client.protocol, ProtocolV1)
        session = SessionV1(client, b"")
        session.features = session.call(
            # Initialize(passphrase=passphrase, derive_cardano=derive_cardano) # TODO
            Initialize()
        )
        session.id = session.get_features().session_id
        return session

    def call(self, msg: t.Any, should_reinit: bool = False) -> t.Any:
        # if should_reinit:
        #    self.initialize() # TODO
        if t.TYPE_CHECKING:
            assert isinstance(self.client.protocol, ProtocolV1)
        self.client.protocol.write(msg)
        return self.client.protocol.read()

    def refresh_features(self) -> None:
        self.features = self.call(GetFeatures())

    def get_features(self) -> Features:
        return self.features


class SessionV2(Session):

    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
    ) -> SessionV2:
        assert isinstance(client.protocol, ProtocolV2)
        session = cls(client, b"\x00")
        new_session: ThpNewSession = session.call(
            ThpCreateNewSession(passphrase=passphrase, derive_cardano=derive_cardano)
        )
        assert new_session.new_session_id is not None
        session_id = new_session.new_session_id
        session.update_id_and_sid(session_id.to_bytes(1, "big"))
        session.is_mgmt_session = passphrase is None
        session.active = True
        return session

    def __init__(self, client: TrezorClient, id: bytes) -> None:
        super().__init__(client, id)
        assert isinstance(client.protocol, ProtocolV2)

        self.channel: ProtocolV2 = client.protocol.get_channel()
        self.update_id_and_sid(id)
        self.features = self.channel.get_features()

    def call(self, msg: t.Any) -> t.Any:
        if not self.active:
            raise InactiveSessionError
        self.channel.write(self.sid, msg)
        resp = self.channel.read(self.sid)
        if isinstance(resp, Failure):
            ...
            if resp.code == FailureType.SeedRequired:
                self.active = False

    def get_features(self) -> Features:
        return self.channel.get_features()

    def refresh_features(self) -> None:
        self.channel.update_features()

    def update_id_and_sid(self, id: bytes) -> None:
        self.id = id
        self.sid = int.from_bytes(id, "big")  # TODO update to extract only sid
