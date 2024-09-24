from __future__ import annotations

import logging
import typing as t

from ... import models, messages, exceptions
from .protocol_v1 import ProtocolV1
from .protocol_v2 import ProtocolV2

if t.TYPE_CHECKING:
    from ...client import TrezorClient

LOG = logging.getLogger(__name__)

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
        # TODO self.check_firmware_version()
        resp = self.call_raw(msg)
        while True:
            if isinstance(resp, messages.PinMatrixRequest):
                resp = self._callback_pin(resp)
            elif isinstance(resp, messages.PassphraseRequest):
                resp = self._callback_passphrase(resp)
            elif isinstance(resp, messages.ButtonRequest):
                resp = self._callback_button(resp)
            elif isinstance(resp, messages.Failure):
                if resp.code == messages.FailureType.ActionCancelled:
                    raise exceptions.Cancelled
                raise exceptions.TrezorFailure(resp)
            else:
                return resp

    def call_raw(self, msg: t.Any) -> t.Any:
        raise NotImplementedError

    def _callback_pin(self, msg: t.Any) -> t.Any:
        raise NotImplementedError

    def _callback_passphrase(self, msg: t.Any) -> t.Any:
        raise NotImplementedError

    def _callback_button(self, msg: t.Any) -> t.Any:
        raise NotImplementedError

    def refresh_features(self) -> None:
        self.client.refresh_features()

    def end(self) -> None:
        raise NotImplementedError

    @property
    def features(self) -> messages.Features:
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
        if session_id is None:
            LOG.debug("warning, session id of protocol_v1 session is None")
            return SessionV1(client, id=b"")
        return SessionV1(client, session_id)

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
        new_session: messages.ThpNewSession = session.call(
            messages.ThpCreateNewSession(
                passphrase=passphrase, derive_cardano=derive_cardano
            )
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

    def call_raw(self, msg: t.Any) -> t.Any:

        self.channel.write(self.sid, msg)
        return self.channel.read(self.sid)

    def update_id_and_sid(self, id: bytes) -> None:
        self._id = id
        self.sid = int.from_bytes(id, "big")  # TODO update to extract only sid

    def _callback_button(self, msg: t.Any) -> t.Any:
        print("Please confirm action on your Trezor device.")  # TODO how to handle UI?
        return self.call(messages.ButtonAck())
