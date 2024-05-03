import builtins
import gc
from micropython import const
from typing import TYPE_CHECKING

from storage.cache_common import InvalidSessionError, SessionlessCache
from trezor import utils

SESSIONLESS_FLAG = const(128)

if TYPE_CHECKING:
    from typing import Callable, ParamSpec, TypeVar, overload

    T = TypeVar("T")
    P = ParamSpec("P")


def check_thp_is_not_used(f: Callable[P, T]) -> Callable[P, T]:
    """A type-safe decorator to raise an exception when the function is called with THP enabled.

    This decorator should be removed after the caches for Codec_v1 and THP are properly refactored and separated.
    """

    def inner(*args: P.args, **kwargs: P.kwargs) -> T:
        if utils.USE_THP:
            raise Exception("Cannot call this function with the new THP enabled")
        return f(*args, **kwargs)

    return inner


# Traditional cache keys
APP_COMMON_SEED = const(0)
APP_COMMON_AUTHORIZATION_TYPE = const(1)
APP_COMMON_AUTHORIZATION_DATA = const(2)
APP_COMMON_NONCE = const(3)
if not utils.BITCOIN_ONLY:
    APP_COMMON_DERIVE_CARDANO = const(4)
    APP_CARDANO_ICARUS_SECRET = const(5)
    APP_CARDANO_ICARUS_TREZOR_SECRET = const(6)
    APP_MONERO_LIVE_REFRESH = const(7)

# Keys that are valid across sessions
APP_COMMON_SEED_WITHOUT_PASSPHRASE = const(0 | SESSIONLESS_FLAG)
APP_COMMON_SAFETY_CHECKS_TEMPORARY = const(1 | SESSIONLESS_FLAG)
STORAGE_DEVICE_EXPERIMENTAL_FEATURES = const(2 | SESSIONLESS_FLAG)
APP_COMMON_REQUEST_PIN_LAST_UNLOCK = const(3 | SESSIONLESS_FLAG)
APP_COMMON_BUSY_DEADLINE_MS = const(4 | SESSIONLESS_FLAG)
APP_MISC_COSI_NONCE = const(5 | SESSIONLESS_FLAG)
APP_MISC_COSI_COMMITMENT = const(6 | SESSIONLESS_FLAG)

# === Homescreen storage ===
# This does not logically belong to the "cache" functionality, but the cache module is
# a convenient place to put this.
# When a Homescreen layout is instantiated, it checks the value of `homescreen_shown`
# to know whether it should render itself or whether the result of a previous instance
# is still on. This way we can avoid unnecessary fadeins/fadeouts when a workflow ends.
HOMESCREEN_ON = object()
LOCKSCREEN_ON = object()
BUSYSCREEN_ON = object()
homescreen_shown: object | None = None

# Timestamp of last autolock activity.
# Here to persist across main loop restart between workflows.
autolock_last_touch: int | None = None


# XXX
# Allocation notes:
# Instantiation of a DataCache subclass should make as little garbage as possible, so
# that the preallocated bytearrays are compact in memory.
# That is why the initialization is two-step: first create appropriately sized
# bytearrays, then later call `clear()` on all the existing objects, which resets them
# to zero length. This is producing some trash - `b[:]` allocates a slice.

_SESSIONLESS_CACHE = SessionlessCache()


if utils.USE_THP:
    from storage import cache_thp

    _PROTOCOL_CACHE = cache_thp
else:
    from storage import cache_codec

    _PROTOCOL_CACHE = cache_codec

_PROTOCOL_CACHE.initialize()
_SESSIONLESS_CACHE.clear()

gc.collect()

if TYPE_CHECKING:

    @overload
    def get(key: int) -> bytes | None: ...

    @overload
    def get(key: int, default: T) -> bytes | T:  # noqa: F811
        ...


# Common functions


def clear_all() -> None:
    global autolock_last_touch
    autolock_last_touch = None
    _SESSIONLESS_CACHE.clear()
    _PROTOCOL_CACHE.clear_all()


def get_int_all_sessions(key: int) -> builtins.set[int]:
    if key & SESSIONLESS_FLAG:
        values = builtins.set()
        encoded = _SESSIONLESS_CACHE.get(key)
        if encoded is not None:
            values.add(int.from_bytes(encoded, "big"))
        return values
    return _PROTOCOL_CACHE.get_int_all_sessions(key)


# Sessionless functions


def get_sessionless(
    key: int, default: T | None = None
) -> bytes | T | None:  # noqa: F811
    if key & SESSIONLESS_FLAG:
        return _SESSIONLESS_CACHE.get(key ^ SESSIONLESS_FLAG, default)
    raise ValueError("Argument 'key' does not have a sessionless flag")


def get_int_sessionless(
    key: int, default: T | None = None
) -> int | T | None:  # noqa: F811
    encoded = get_sessionless(key)
    if encoded is None:
        return default
    else:
        return int.from_bytes(encoded, "big")


def is_set_sessionless(key: int) -> bool:
    if key & SESSIONLESS_FLAG:
        return _SESSIONLESS_CACHE.is_set(key ^ SESSIONLESS_FLAG)
    raise ValueError("Argument 'key' does not have a sessionless flag")


def set_sessionless(key: int, value: bytes) -> None:
    if key & SESSIONLESS_FLAG:
        _SESSIONLESS_CACHE.set(key ^ SESSIONLESS_FLAG, value)
        return
    raise ValueError("Argument 'key' does not have a sessionless flag")


def set_int_sessionless(key: int, value: int) -> None:

    if not key & SESSIONLESS_FLAG:
        raise ValueError("Argument 'key' does not have a sessionless flag")

    length = _SESSIONLESS_CACHE.fields[key ^ SESSIONLESS_FLAG]
    encoded = value.to_bytes(length, "big")

    # Ensure that the value fits within the length. Micropython's int.to_bytes()
    # doesn't raise OverflowError.
    assert int.from_bytes(encoded, "big") == value

    set_sessionless(key, encoded)


# Codec_v1 specific functions


@check_thp_is_not_used
def start_session(received_session_id: bytes | None = None) -> bytes:
    return cache_codec.start_session(received_session_id)


@check_thp_is_not_used
def end_current_session() -> None:
    cache_codec.end_current_session()


@check_thp_is_not_used
def delete(key: int) -> None:
    if key & SESSIONLESS_FLAG:
        return _SESSIONLESS_CACHE.delete(key ^ SESSIONLESS_FLAG)
    active_session = cache_codec.get_active_session()
    if active_session is None:
        raise InvalidSessionError
    return active_session.delete(key)


@check_thp_is_not_used
def get(key: int, default: T | None = None) -> bytes | T | None:  # noqa: F811
    if key & SESSIONLESS_FLAG:
        return get_sessionless(key, default)
    active_session = cache_codec.get_active_session()
    if active_session is None:
        raise InvalidSessionError
    return active_session.get(key, default)


@check_thp_is_not_used
def get_int(key: int, default: T | None = None) -> int | T | None:  # noqa: F811
    encoded = get(key)
    if encoded is None:
        return default
    else:
        return int.from_bytes(encoded, "big")


@check_thp_is_not_used
def is_set(key: int) -> bool:
    if key & SESSIONLESS_FLAG:
        return _SESSIONLESS_CACHE.is_set(key ^ SESSIONLESS_FLAG)
    active_session = cache_codec.get_active_session()
    if active_session is None:
        raise InvalidSessionError
    return active_session.is_set(key)


@check_thp_is_not_used
def set(key: int, value: bytes) -> None:
    if key & SESSIONLESS_FLAG:
        _SESSIONLESS_CACHE.set(key ^ SESSIONLESS_FLAG, value)
        return
    active_session = cache_codec.get_active_session()
    if active_session is None:
        raise InvalidSessionError
    active_session.set(key, value)


@check_thp_is_not_used
def set_int(key: int, value: int) -> None:
    active_session = cache_codec.get_active_session()

    if key & SESSIONLESS_FLAG:
        length = _SESSIONLESS_CACHE.fields[key ^ SESSIONLESS_FLAG]
    elif active_session is None:
        raise InvalidSessionError
    else:
        length = active_session.fields[key]

    encoded = value.to_bytes(length, "big")

    # Ensure that the value fits within the length. Micropython's int.to_bytes()
    # doesn't raise OverflowError.
    assert int.from_bytes(encoded, "big") == value

    set(key, encoded)
