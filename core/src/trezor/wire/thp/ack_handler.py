from storage.cache_thp import SessionThpCache

from . import thp_session as THP


def handle_received_ACK(session: SessionThpCache, sync_bit: int) -> None:

    if _ack_is_not_expected(session):
        return
    if _ack_has_incorrect_sync_bit(session, sync_bit):
        return

    # ACK is expected and it has correct sync bit
    THP.sync_set_can_send_message(session, True)


def _ack_is_not_expected(session: SessionThpCache) -> bool:
    return THP.sync_can_send_message(session)


def _ack_has_incorrect_sync_bit(session: SessionThpCache, sync_bit: int) -> bool:
    return THP.sync_get_send_bit(session) != sync_bit
