import builtins
import gc
from typing import TYPE_CHECKING

from storage.cache_common import SESSIONLESS_FLAG, SessionlessCache
from trezor import utils

if TYPE_CHECKING:
    from typing import Callable, ParamSpec, TypeVar

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
def get_sessionless_cache() -> SessionlessCache:
    return _SESSIONLESS_CACHE


# Codec_v1 specific functions


@check_thp_is_not_used
def start_session(received_session_id: bytes | None = None) -> bytes:
    return cache_codec.start_session(received_session_id)


@check_thp_is_not_used
def end_current_session() -> None:
    cache_codec.end_current_session()
