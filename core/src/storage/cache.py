import builtins
import gc
from typing import TYPE_CHECKING

from storage.cache_common import SESSIONLESS_FLAG, SessionlessCache
from trezor import utils

if TYPE_CHECKING:
    from typing import Tuple

    pass

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


def clear_all(excluded: Tuple[bytes, bytes] | None = None) -> None:
    from .cache_common import clear

    clear()
    _SESSIONLESS_CACHE.clear()

    if utils.USE_THP and excluded is not None:
        # If we want to keep THP connection alive, we do not clear communication keys
        cache_thp.clear_all_except_one_session_keys(excluded)
    else:
        _PROTOCOL_CACHE.clear_all()


def get_int_all_sessions(key: int) -> builtins.set[int]:
    if key & SESSIONLESS_FLAG:
        values = builtins.set()
        encoded = _SESSIONLESS_CACHE.get(key)
        if encoded is not None:
            values.add(int.from_bytes(encoded, "big"))
        return values
    return _PROTOCOL_CACHE.get_int_all_sessions(key)


def get_sessionless_cache() -> SessionlessCache:
    return _SESSIONLESS_CACHE
