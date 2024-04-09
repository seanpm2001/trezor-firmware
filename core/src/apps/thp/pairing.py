from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from trezor.wire.errors import UnexpectedMessage
from trezor.wire.thp import ChannelState
from trezor.wire.thp.channel import Channel
from trezor.wire.thp.thp_session import ThpError

if TYPE_CHECKING:
    from trezor.enums import ThpPairingMethod
    from trezor.messages import (
        ThpCodeEntryChallenge,
        ThpCodeEntryCommitment,
        ThpCodeEntryCpaceHost,
        ThpCodeEntryCpaceTrezor,
        ThpCodeEntrySecret,
        ThpCodeEntryTag,
        ThpNfcUnideirectionalSecret,
        ThpNfcUnidirectionalTag,
        ThpQrCodeSecret,
        ThpQrCodeTag,
        ThpStartPairingRequest,
    )


# TODO implement the following handlers


async def handle_pairing_request(
    channel: Channel, message: ThpStartPairingRequest
) -> ThpCodeEntryCommitment | None:
    _check_state(channel, ChannelState.TP1)
    if _is_method_included(channel, ThpPairingMethod.PairingMethod_CodeEntry):
        channel.set_channel_state(ChannelState.TP2)
        return ThpCodeEntryCommitment()
    channel.set_channel_state(ChannelState.TP3)
    return None


async def handle_code_entry_challenge(
    channel: Channel, message: ThpCodeEntryChallenge
) -> None:
    _check_state(channel, ChannelState.TP2)
    channel.set_channel_state(ChannelState.TP3)


async def handle_code_entry_cpace(
    channel: Channel, message: ThpCodeEntryCpaceHost
) -> ThpCodeEntryCpaceTrezor:
    _check_state(channel, ChannelState.TP3)
    _check_method_is_allowed(channel, ThpPairingMethod.PairingMethod_CodeEntry)
    channel.set_channel_state(ChannelState.TP4)
    return ThpCodeEntryCpaceTrezor()


async def handle_code_entry_tag(
    channel: Channel, message: ThpCodeEntryTag
) -> ThpCodeEntrySecret:
    _check_state(channel, ChannelState.TP4)
    channel.set_channel_state(ChannelState.TC1)
    return ThpCodeEntrySecret()


async def handle_qr_code_tag(
    channel: Channel, message: ThpQrCodeTag
) -> ThpQrCodeSecret:
    _check_state(channel, ChannelState.TP3)
    _check_method_is_allowed(channel, ThpPairingMethod.PairingMethod_QrCode)
    channel.set_channel_state(ChannelState.TC1)
    return ThpQrCodeSecret()


async def handle_nfc_unidirectional_tag(
    channel: Channel, message: ThpNfcUnidirectionalTag
) -> ThpNfcUnideirectionalSecret:
    _check_state(channel, ChannelState.TP3)
    _check_method_is_allowed(channel, ThpPairingMethod.PairingMethod_NFC_Unidirectional)
    channel.set_channel_state(ChannelState.TC1)
    return ThpNfcUnideirectionalSecret()


def _check_state(channel: Channel, expected_state: ChannelState) -> None:
    if expected_state is not channel.get_channel_state():
        raise UnexpectedMessage("Unexpected message")


def _check_method_is_allowed(channel: Channel, method: ThpPairingMethod) -> None:
    if not _is_method_included(channel, method):
        raise ThpError("Unexpected pairing method")


def _is_method_included(channel: Channel, method: ThpPairingMethod) -> bool:
    return method in channel.selected_pairing_methods
