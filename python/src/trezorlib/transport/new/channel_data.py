from __future__ import annotations


class ChannelData:
    key_request: bytes
    key_response: bytes
    nonce_request: int
    nonce_response: int
    channel_id: bytes
    sync_bit_send: int
    sync_bit_receive: int
