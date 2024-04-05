from storage.cache_thp import ChannelCache, SessionThpCache
from trezor import log, loop

from . import thp_session as THP


def handle_received_ACK(
    cache: SessionThpCache | ChannelCache,
    sync_bit: int,
    waiting_for_ack_timeout: loop.spawn | None = None,
) -> None:

    if _ack_is_not_expected(cache):
        _conditionally_log_debug("Received unexpected ACK message")
        return
    if _ack_has_incorrect_sync_bit(cache, sync_bit):
        _conditionally_log_debug("Received ACK message with wrong sync bit")
        return

    # ACK is expected and it has correct sync bit
    _conditionally_log_debug("Received ACK message with correct sync bit")
    if waiting_for_ack_timeout is not None:
        waiting_for_ack_timeout.close()
        _conditionally_log_debug('Closed "waiting for ack" task')
    THP.sync_set_can_send_message(cache, True)


def _ack_is_not_expected(cache: SessionThpCache | ChannelCache) -> bool:
    return THP.sync_can_send_message(cache)


def _ack_has_incorrect_sync_bit(
    cache: SessionThpCache | ChannelCache, sync_bit: int
) -> bool:
    return THP.sync_get_send_bit(cache) != sync_bit


def _conditionally_log_debug(message):
    if __debug__:
        log.debug(__name__, message)
