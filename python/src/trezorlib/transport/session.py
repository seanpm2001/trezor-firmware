from __future__ import annotations

import logging
import typing as t


from .. import exceptions, messages, models
from .thp.protocol_v1 import ProtocolV1
from .thp.protocol_v2 import ProtocolV2

if t.TYPE_CHECKING:
    from ..client import TrezorClient

LOG = logging.getLogger(__name__)


class Session:
    button_callback: t.Callable[[Session, t.Any], t.Any] | None = None
    pin_callback: t.Callable[[Session, t.Any], t.Any] | None = None
    passphrase_callback: t.Callable[[Session, t.Any], t.Any] | None = None

    def __init__(
        self, client: TrezorClient, id: bytes, passphrase: str | object | None = None
    ) -> None:
        self.client = client
        self._id = id
        self.passphrase = passphrase

    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | object | None, derive_cardano: bool
    ) -> Session:
        raise NotImplementedError

    def call(self, msg: t.Any) -> t.Any:
        # TODO self.check_firmware_version()
        resp = self.call_raw(msg)

        while True:
            if isinstance(resp, messages.PinMatrixRequest):
                if self.pin_callback is None:
                    raise Exception  # TODO
                resp = self.pin_callback(self, resp)
            elif isinstance(resp, messages.PassphraseRequest):
                if self.passphrase_callback is None:
                    raise Exception  # TODO
                print(self.passphrase_callback)
                resp = self.passphrase_callback(self, resp)
            elif isinstance(resp, messages.ButtonRequest):
                if self.button_callback is None:
                    raise Exception  # TODO
                resp = self.button_callback(self, resp)
            elif isinstance(resp, messages.Failure):
                if resp.code == messages.FailureType.ActionCancelled:
                    raise exceptions.Cancelled
                raise exceptions.TrezorFailure(resp)
            else:
                return resp

    def call_raw(self, msg: t.Any) -> t.Any:
        self._write(msg)
        return self._read()

    def _write(self, msg: t.Any) -> None:
        raise NotImplementedError

    def _read(self) -> t.Any:
        raise NotImplementedError

    def refresh_features(self) -> None:
        self.client.refresh_features()

    def end(self) -> t.Any:
        return self.call(messages.EndSession())

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
    derive_cardano: bool = False
    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str = "", derive_cardano: bool = False
    ) -> SessionV1:
        assert isinstance(client.protocol, ProtocolV1)
        session_id = client.features.session_id
        if session_id is None:
            LOG.debug("warning, session id of protocol_v1 session is None")
            session = SessionV1(client, id=b"")
        else:
            session = SessionV1(client, session_id)
        session.button_callback = client.button_callback
        session.pin_callback = client.pin_callback
        session.passphrase_callback = client.passphrase_callback
        session.passphrase = passphrase
        session.derive_cardano = derive_cardano
        session.init_session()
        return session

    def _write(self, msg: t.Any) -> None:
        if t.TYPE_CHECKING:
            assert isinstance(self.client.protocol, ProtocolV1)
        self.client.protocol.write(msg)

    def _read(self) -> t.Any:
        if t.TYPE_CHECKING:
            assert isinstance(self.client.protocol, ProtocolV1)
        return self.client.protocol.read()

    def init_session(self):
        if self.id == b"":
            session_id = None
        else:
            session_id = self.id
        resp: messages.Features = self.call_raw(
            messages.Initialize(
                session_id=session_id, derive_cardano=self.derive_cardano
            )
        )
        self._id = resp.session_id


def _callback_button(session: Session, msg: t.Any) -> t.Any:
    print("Please confirm action on your Trezor device.")  # TODO how to handle UI?
    return session.call(messages.ButtonAck())


class SessionV2(Session):

    @classmethod
    def new(
        cls, client: TrezorClient, passphrase: str | None, derive_cardano: bool
    ) -> SessionV2:
        assert isinstance(client.protocol, ProtocolV2)
        session = cls(client, b"\x00")
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

        self.pin_callback = client.pin_callback
        self.button_callback = client.button_callback
        if self.button_callback is None:
            self.button_callback = _callback_button
        self.channel: ProtocolV2 = client.protocol.get_channel()
        self.update_id_and_sid(id)

    def _write(self, msg: t.Any) -> None:
        LOG.debug("writing message %s", type(msg))
        self.channel.write(self.sid, msg)

    def _read(self) -> t.Any:
        msg = self.channel.read(self.sid)
        LOG.debug("reading message %s", type(msg))
        return msg

    def update_id_and_sid(self, id: bytes) -> None:
        self._id = id
        self.sid = int.from_bytes(id, "big")  # TODO update to extract only sid
