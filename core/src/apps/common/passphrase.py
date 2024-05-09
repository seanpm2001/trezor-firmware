from micropython import const
from typing import TYPE_CHECKING

import storage.device as storage_device
from storage.cache import check_thp_is_not_used
from trezor.wire import DataError

_MAX_PASSPHRASE_LEN = const(50)

if TYPE_CHECKING:
    from trezor.messages import ThpCreateNewSession


def is_enabled() -> bool:
    return storage_device.is_passphrase_enabled()


async def get_passphrase(msg: ThpCreateNewSession) -> str:
    if not is_enabled():
        return ""

    if msg.on_device or storage_device.get_passphrase_always_on_device():
        passphrase = await _get_on_device()
    else:
        passphrase = msg.passphrase or ""
        if passphrase:
            await _handle_displaying_passphrase_from_host(passphrase)

    if len(passphrase.encode()) > _MAX_PASSPHRASE_LEN:
        raise DataError(f"Maximum passphrase length is {_MAX_PASSPHRASE_LEN} bytes")

    return passphrase


async def _get_on_device() -> str:
    from trezor import workflow
    from trezor.ui.layouts import request_passphrase_on_device

    workflow.close_others()  # request exclusive UI access
    passphrase = await request_passphrase_on_device(_MAX_PASSPHRASE_LEN)

    return passphrase


@check_thp_is_not_used
async def get() -> str:
    from trezor import workflow

    if not is_enabled():
        return ""
    else:
        workflow.close_others()  # request exclusive UI access
        if storage_device.get_passphrase_always_on_device():
            from trezor.ui.layouts import request_passphrase_on_device

            passphrase = await request_passphrase_on_device(_MAX_PASSPHRASE_LEN)
        else:
            passphrase = await _request_on_host()
        if len(passphrase.encode()) > _MAX_PASSPHRASE_LEN:
            raise DataError(f"Maximum passphrase length is {_MAX_PASSPHRASE_LEN} bytes")

        return passphrase


@check_thp_is_not_used
async def _request_on_host() -> str:
    from trezor.messages import PassphraseAck, PassphraseRequest
    from trezor.ui.layouts import request_passphrase_on_host
    from trezor.wire.context import call

    request_passphrase_on_host()

    request = PassphraseRequest()
    ack = await call(request, PassphraseAck)
    passphrase = ack.passphrase  # local_cache_attribute

    if ack.on_device:
        from trezor.ui.layouts import request_passphrase_on_device

        if passphrase is not None:
            raise DataError("Passphrase provided when it should not be")
        return await request_passphrase_on_device(_MAX_PASSPHRASE_LEN)

    if passphrase is None:
        raise DataError(
            "Passphrase not provided and on_device is False. Use empty string to set an empty passphrase."
        )

    # non-empty passphrase
    if passphrase:
        await _handle_displaying_passphrase_from_host(passphrase)

    return passphrase


async def _handle_displaying_passphrase_from_host(passphrase: str) -> None:
    from trezor import TR
    from trezor.ui.layouts import confirm_action, confirm_blob

    # We want to hide the passphrase, or show it, according to settings.
    if storage_device.get_hide_passphrase_from_host():
        await confirm_action(
            "passphrase_host1_hidden",
            TR.passphrase__hidden_wallet,
            description=f"{TR.passphrase__access_hidden_wallet}\n{TR.passphrase__from_host_not_shown}",
        )
    else:
        await confirm_action(
            "passphrase_host1",
            TR.passphrase__hidden_wallet,
            description=TR.passphrase__next_screen_will_show_passphrase,
            verb=TR.buttons__continue,
        )

        await confirm_blob(
            "passphrase_host2",
            TR.passphrase__title_confirm,
            passphrase,
        )
