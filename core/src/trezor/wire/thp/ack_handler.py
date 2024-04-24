from storage.cache_thp import ChannelCache, SessionThpCache
from trezor import log

from . import thp_session as THP


def is_ack_valid(cache: SessionThpCache | ChannelCache, sync_bit: int) -> bool:
    if not _is_ack_expected(cache):
        return False

    if not _has_ack_correct_sync_bit(cache, sync_bit):
        return False

    return True


def _is_ack_expected(cache: SessionThpCache | ChannelCache) -> bool:
    is_expected: bool = not THP.sync_can_send_message(cache)
    if __debug__ and not is_expected:
        log.debug(__name__, "Received unexpected ACK message")
    return is_expected


def _has_ack_correct_sync_bit(
    cache: SessionThpCache | ChannelCache, sync_bit: int
) -> bool:
    is_correct: bool = THP.sync_get_send_bit(cache) == sync_bit
    if __debug__ and not is_correct:
        log.debug(__name__, "Received ACK message with wrong sync bit")
    return is_correct
