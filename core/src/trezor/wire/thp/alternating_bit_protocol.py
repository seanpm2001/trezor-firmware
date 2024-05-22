from storage.cache_thp import ChannelCache
from trezor import log
from trezor.wire.thp import ThpError


def is_ack_valid(cache: ChannelCache, sync_bit: int) -> bool:
    if not _is_ack_expected(cache):
        return False

    if not _has_ack_correct_sync_bit(cache, sync_bit):
        return False

    return True


def _is_ack_expected(cache: ChannelCache) -> bool:
    is_expected: bool = not sync_can_send_message(cache)
    if __debug__ and not is_expected:
        log.debug(__name__, "Received unexpected ACK message")
    return is_expected


def _has_ack_correct_sync_bit(cache: ChannelCache, sync_bit: int) -> bool:
    is_correct: bool = sync_get_send_seq_bit(cache) == sync_bit
    if __debug__ and not is_correct:
        log.debug(__name__, "Received ACK message with wrong sync bit")
    return is_correct


def sync_can_send_message(cache: ChannelCache) -> bool:
    return cache.sync & 0x80 == 0x80


def sync_get_send_seq_bit(cache: ChannelCache) -> int:
    return (cache.sync & 0x20) >> 5


def sync_get_receive_expected_seq_bit(cache: ChannelCache) -> int:
    return (cache.sync & 0x40) >> 6


def sync_set_can_send_message(cache: ChannelCache, can_send: bool) -> None:
    cache.sync &= 0x7F
    if can_send:
        cache.sync |= 0x80


def sync_set_receive_expected_seq_bit(cache: ChannelCache, bit: int) -> None:
    if __debug__:
        log.debug(__name__, "Set sync receive expected seq bit to %d", bit)
    if bit not in (0, 1):
        raise ThpError("Unexpected receive sync bit")

    # set second bit to "bit" value
    cache.sync &= 0xBF
    if bit:
        cache.sync |= 0x40


def _sync_set_send_seq_bit(cache: ChannelCache, bit: int) -> None:
    if bit not in (0, 1):
        raise ThpError("Unexpected send seq bit")
    if __debug__:
        log.debug(__name__, "setting sync send seq bit to %d", bit)
    # set third bit to "bit" value
    cache.sync &= 0xDF
    if bit:
        cache.sync |= 0x20


def sync_set_send_seq_bit_to_opposite(cache: ChannelCache) -> None:
    _sync_set_send_seq_bit(cache=cache, bit=1 - sync_get_send_seq_bit(cache))
