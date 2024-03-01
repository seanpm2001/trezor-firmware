import ustruct
from storage import cache_thp as storage_thp_cache
from storage.cache_thp import SessionThpCache, BROADCAST_CHANNEL_ID
from trezor import io
from trezor.wire.protocol_common import WireError
from typing import TYPE_CHECKING
from ubinascii import hexlify

if TYPE_CHECKING:
    from enum import IntEnum
else:
    IntEnum = object


class ThpError(WireError):
    pass


class WorkflowState(IntEnum):
    NOT_STARTED = 0
    PENDING = 1
    FINISHED = 2


class Workflow:
    id: int
    workflow_state: WorkflowState


class SessionState(IntEnum):
    UNALLOCATED = 0
    INITIALIZED = 1  # do not change, is denoted as constant in storage.cache _THP_SESSION_STATE_INITIALIZED = 1
    PAIRED = 2
    UNPAIRED = 3
    PAIRING = 4
    APP_TRAFFIC = 5


def get_workflow() -> Workflow:
    pass  # TODO


def print_all_test_sessions() -> None:
    for session in storage_thp_cache._UNAUTHENTICATED_SESSIONS:
        if session is None:
            print("none")
        else:
            print(hexlify(session.session_id).decode("utf-8"), session.state)


#
def create_autenticated_session(unauthenticated_session: SessionThpCache):
    storage_thp_cache.start_session()  # TODO something like this but for THP
    raise


def create_new_unauthenticated_session(iface: WireInterface, cid: int):
    session_id = _get_id(iface, cid)
    new_session = storage_thp_cache.create_new_unauthenticated_session(session_id)
    set_session_state(new_session, SessionState.INITIALIZED)


def get_active_session() -> SessionThpCache | None:
    return storage_thp_cache.get_active_session()


def get_session(iface: WireInterface, cid: int) -> SessionThpCache | None:
    session_id = _get_id(iface, cid)
    return get_session_from_id(session_id)


def get_session_from_id(session_id) -> SessionThpCache | None:
    session = _get_authenticated_session_or_none(session_id)
    if session is None:
        session = _get_unauthenticated_session_or_none(session_id)
    return session


def get_state(session: SessionThpCache) -> int:
    if session is None:
        return SessionState.UNALLOCATED
    return _decode_session_state(session.state)


def get_cid(session: SessionThpCache) -> int:
    return storage_thp_cache._get_cid(session)


def get_next_channel_id() -> int:
    return storage_thp_cache.get_next_channel_id()


def sync_can_send_message(session: SessionThpCache) -> bool:
    return session.sync & 0x80 == 0x80


def sync_get_receive_expected_bit(session: SessionThpCache) -> int:
    return (session.sync & 0x40) >> 6


def sync_get_send_bit(session: SessionThpCache) -> int:
    return (session.sync & 0x20) >> 5


def sync_set_can_send_message(session: SessionThpCache, can_send: bool) -> None:
    session.sync &= 0x7F
    if can_send:
        session.sync |= 0x80


def sync_set_receive_expected_bit(session: SessionThpCache, bit: int) -> None:
    if bit != 0 and bit != 1:
        raise ThpError("Unexpected receive sync bit")

    # set second bit to "bit" value
    session.sync &= 0xBF
    session.sync |= 0x40


def sync_set_send_bit_to_opposite(session: SessionThpCache) -> None:
    _sync_set_send_bit(session=session, bit=1 - sync_get_send_bit(session))


def is_active_session(session: SessionThpCache):
    if session is None:
        return False
    return session.session_id == storage_thp_cache.get_active_session_id()


def set_session_state(session: SessionThpCache, new_state: SessionState):
    session.state = new_state.to_bytes(1, "big")


def _get_id(iface: WireInterface, cid: int) -> bytearray:
    return ustruct.pack(">HH", iface.iface_num(), cid)


def _get_authenticated_session_or_none(session_id) -> SessionThpCache:
    for authenticated_session in storage_thp_cache._SESSIONS:
        if authenticated_session.session_id == session_id:
            return authenticated_session
    return None


def _get_unauthenticated_session_or_none(session_id) -> SessionThpCache:
    for unauthenticated_session in storage_thp_cache._UNAUTHENTICATED_SESSIONS:
        if unauthenticated_session.session_id == session_id:
            return unauthenticated_session
    return None


def _sync_set_send_bit(session: SessionThpCache, bit: int) -> None:
    if bit != 0 and bit != 1:
        raise ThpError("Unexpected send sync bit")

    # set third bit to "bit" value
    session.sync &= 0xDF
    session.sync |= 0x20


def _decode_session_state(state: bytearray) -> int:
    return ustruct.unpack("B", state)[0]


def _encode_session_state(state: SessionState) -> bytearray:
    return ustruct.pack("B", state)
