import builtins
from micropython import const
from typing import TYPE_CHECKING

from storage.cache_common import DataCache, InvalidSessionError
from trezor import utils


if TYPE_CHECKING:
    from typing import Sequence, TypeVar, overload

    T = TypeVar("T")

# THP specific constants
_MAX_SESSIONS_COUNT = const(20)
_MAX_UNAUTHENTICATED_SESSIONS_COUNT = const(5)
_THP_SESSION_STATE_LENGTH = const(1)
_SESSION_ID_LENGTH = const(4)
BROADCAST_CHANNEL_ID = const(65535)


class SessionThpCache(DataCache):  # TODO implement, this is just copied SessionCache
    def __init__(self) -> None:
        self.session_id = bytearray(_SESSION_ID_LENGTH)
        self.state = bytearray(_THP_SESSION_STATE_LENGTH)
        if utils.BITCOIN_ONLY:
            self.fields = (
                64,  # APP_COMMON_SEED
                2,  # APP_COMMON_AUTHORIZATION_TYPE
                128,  # APP_COMMON_AUTHORIZATION_DATA
                32,  # APP_COMMON_NONCE
            )
        else:
            self.fields = (
                64,  # APP_COMMON_SEED
                2,  # APP_COMMON_AUTHORIZATION_TYPE
                128,  # APP_COMMON_AUTHORIZATION_DATA
                32,  # APP_COMMON_NONCE
                1,  # APP_COMMON_DERIVE_CARDANO
                96,  # APP_CARDANO_ICARUS_SECRET
                96,  # APP_CARDANO_ICARUS_TREZOR_SECRET
                1,  # APP_MONERO_LIVE_REFRESH
            )
        self.sync = 0x80  # can_send_bit | sync_receive_bit | sync_send_bit | rfu(5)
        self.last_usage = 0
        super().__init__()

    def export_session_id(self) -> bytes:
        from trezorcrypto import random  # avoid pulling in trezor.crypto

        # generate a new session id if we don't have it yet
        if not self.session_id:
            self.session_id[:] = random.bytes(_SESSION_ID_LENGTH)
        # export it as immutable bytes
        return bytes(self.session_id)

    def clear(self) -> None:
        super().clear()
        self.state = 0  # Set state to UNALLOCATED
        self.last_usage = 0
        self.session_id[:] = b""


_SESSIONS: list[SessionThpCache] = []
_UNAUTHENTICATED_SESSIONS: list[SessionThpCache] = []


def initialize() -> None:
    global _SESSIONS
    global _UNAUTHENTICATED_SESSIONS

    for _ in range(_MAX_SESSIONS_COUNT):
        _SESSIONS.append(SessionThpCache())
    for _ in range(_MAX_UNAUTHENTICATED_SESSIONS_COUNT):
        _UNAUTHENTICATED_SESSIONS.append(SessionThpCache())

    for session in _SESSIONS:
        session.clear()
    for session in _UNAUTHENTICATED_SESSIONS:
        session.clear()


initialize()


# THP vars
_next_unauthenicated_session_index: int = 0
_is_active_session_authenticated: bool
_active_session_idx: int | None = None
_session_usage_counter = 0


# with this (arbitrary) value=4659, the first allocated channel will have cid=1234 (hex)
cid_counter: int = 4659


def get_active_session_id() -> bytearray | None:
    active_session = get_active_session()

    if active_session is None:
        return None
    return active_session.session_id


def get_active_session() -> SessionThpCache | None:
    if _active_session_idx is None:
        return None
    if _is_active_session_authenticated:
        return _SESSIONS[_active_session_idx]
    return _UNAUTHENTICATED_SESSIONS[_active_session_idx]


def get_next_channel_id() -> int:
    global cid_counter
    while True:
        cid_counter += 1
        if cid_counter >= BROADCAST_CHANNEL_ID:
            cid_counter = 1
        if _is_cid_unique():
            break
    return cid_counter


def _is_cid_unique() -> bool:
    for session in _SESSIONS + _UNAUTHENTICATED_SESSIONS:
        if cid_counter == _get_cid(session):
            return False
    return True


def _get_cid(session: SessionThpCache) -> int:
    return int.from_bytes(session.session_id[2:], "big")


def create_new_unauthenticated_session(session_id: bytes) -> SessionThpCache:
    if len(session_id) != 4:
        raise ValueError("session_id must be 4 bytes long.")
    global _active_session_idx
    global _is_active_session_authenticated
    global _next_unauthenicated_session_index

    i = _next_unauthenicated_session_index
    _UNAUTHENTICATED_SESSIONS[i] = SessionThpCache()
    _UNAUTHENTICATED_SESSIONS[i].session_id = bytearray(session_id)
    _next_unauthenicated_session_index += 1
    if _next_unauthenicated_session_index >= _MAX_UNAUTHENTICATED_SESSIONS_COUNT:
        _next_unauthenicated_session_index = 0

    # Set session as active if and only if there is no active session
    if _active_session_idx is None:
        _active_session_idx = i
        _is_active_session_authenticated = False
    return _UNAUTHENTICATED_SESSIONS[i]


def get_unauth_session_index(unauth_session: SessionThpCache) -> int | None:
    for i in range(_MAX_UNAUTHENTICATED_SESSIONS_COUNT):
        if unauth_session == _UNAUTHENTICATED_SESSIONS[i]:
            return i
    return None


def create_new_auth_session(unauth_session: SessionThpCache) -> SessionThpCache:
    global _session_usage_counter

    unauth_session_idx = get_unauth_session_index(unauth_session)
    if unauth_session_idx is None:
        raise InvalidSessionError

    # replace least recently used authenticated session by the new session
    new_auth_session_index = get_least_recently_used_authetnicated_session_index()

    _SESSIONS[new_auth_session_index] = _UNAUTHENTICATED_SESSIONS[unauth_session_idx]
    _UNAUTHENTICATED_SESSIONS[unauth_session_idx].clear()

    _session_usage_counter += 1
    _SESSIONS[new_auth_session_index].last_usage = _session_usage_counter


def get_least_recently_used_authetnicated_session_index() -> int:
    lru_counter = _session_usage_counter
    lru_session_idx = 0
    for i in range(_MAX_SESSIONS_COUNT):
        if _SESSIONS[i].last_usage < lru_counter:
            lru_counter = _SESSIONS[i].last_usage
            lru_session_idx = i
    return lru_session_idx


# The function start_session should not be used in production code. It is present only to assure compatibility with old tests.
def start_session(session_id: bytes | None) -> bytes:  # TODO incomplete
    global _active_session_idx
    global _is_active_session_authenticated

    if session_id is not None:
        if get_active_session_id() == session_id:
            return session_id
        for index in range(_MAX_SESSIONS_COUNT):
            if _SESSIONS[index].session_id == session_id:
                _active_session_idx = index
                _is_active_session_authenticated = True
                return session_id
        for index in range(_MAX_UNAUTHENTICATED_SESSIONS_COUNT):
            if _UNAUTHENTICATED_SESSIONS[index].session_id == session_id:
                _active_session_idx = index
                _is_active_session_authenticated = False
                return session_id
    new_session_id = b"\x00\x00" + get_next_channel_id().to_bytes(2, "big")

    new_session = create_new_unauthenticated_session(new_session_id)

    index = get_unauth_session_index(new_session)
    _active_session_idx = index
    _is_active_session_authenticated = False

    return new_session_id


def start_existing_session(session_id: bytearray) -> bytes:
    if session_id is None:
        raise ValueError("session_id cannot be None")
    if get_active_session_id() == session_id:
        return session_id
    for index in range(_MAX_SESSIONS_COUNT):
        if _SESSIONS[index].session_id == session_id:
            _active_session_idx = index
            _is_active_session_authenticated = True
            return session_id
    for index in range(_MAX_UNAUTHENTICATED_SESSIONS_COUNT):
        if _UNAUTHENTICATED_SESSIONS[index].session_id == session_id:
            _active_session_idx = index
            _is_active_session_authenticated = False
            return session_id
    raise ValueError("There is no active session with provided session_id")


def end_current_session() -> None:
    global _active_session_idx
    active_session = get_active_session()
    if active_session is None:
        return
    active_session.clear()
    _active_session_idx = None


def get_int_all_sessions(key: int) -> builtins.set[int]:
    values = builtins.set()
    for session in _SESSIONS:  # Should there be _SESSIONS + _UNAUTHENTICATED_SESSIONS ?
        encoded = session.get(key)
        if encoded is not None:
            values.add(int.from_bytes(encoded, "big"))
    return values


def clear_all() -> None:
    global _active_session_idx
    _active_session_idx = None
    for session in _SESSIONS + _UNAUTHENTICATED_SESSIONS:
        session.clear()
