from typing import Coroutine, Callable, Any

import storage
import storage.cache
import storage.device
from trezor import config, wire
from trezor.enums import MessageType
from trezor.ui.layouts.homescreen import Busyscreen, Homescreen, Lockscreen

from apps.base import busy_expiry_ms, lock_device
from apps.common.authorization import is_set_any_session


async def busyscreen() -> None:
    obj = Busyscreen(busy_expiry_ms())
    try:
        await obj
    finally:
        obj.__del__()


async def homescreen() -> None:
    from trezor import TR
    from trezorui2 import CONFIRMED

    if storage.device.is_initialized():
        label = storage.device.get_label()
    else:
        label = None

    # TODO: add notification that translations are out of date

    notification: str | None = None
    notification_is_error: bool = False
    notification_callback: Callable[[], Coroutine[Any, Any, None]] | None = None
    if is_set_any_session(MessageType.AuthorizeCoinJoin):
        notification = TR.homescreen__title_coinjoin_authorized
    elif storage.device.is_initialized() and storage.device.no_backup():
        notification = TR.homescreen__title_seedless
        notification_is_error = True
    elif storage.device.is_initialized() and storage.device.unfinished_backup():
        notification = TR.homescreen__title_backup_failed
        notification_is_error = True
    elif storage.device.is_initialized() and storage.device.needs_backup():
        from trezor.messages import BackupDevice
        from apps.management.backup_device import backup_device

        notification = TR.homescreen__title_backup_needed
        notification_callback = backup_device(BackupDevice())
    elif storage.device.is_initialized() and not config.has_pin():
        from trezor.messages import ChangePin
        from apps.management.change_pin import change_pin

        notification = TR.homescreen__title_pin_not_set
        notification_callback = change_pin(ChangePin())
    elif storage.device.get_experimental_features():
        notification = TR.homescreen__title_experimental_mode

    obj = Homescreen(
        label=label,
        notification=notification,
        notification_is_error=notification_is_error,
        notification_clickable=notification_callback is not None,
        hold_to_lock=config.has_pin(),
    )
    try:
        res = await obj
        if isinstance(res, tuple) and res[0] is CONFIRMED:
            # res is (CONFIRMED, int), something was chosen from the menu
            choice = res[1]
            # TODO: choices values should be defined in one place
            if choice == 0:
                from trezor.messages import SetBrightness
                from apps.management.set_brightness import set_brightness

                await set_brightness(SetBrightness(current=None))
            elif choice == 1:
                from trezor.messages import ChangePin
                from apps.management.change_pin import change_pin

                await change_pin(ChangePin())
        elif res is CONFIRMED and notification_callback is not None:
            notification_callback = change_pin(ChangePin())
            await notification_callback
        else:
            lock_device()
    finally:
        obj.__del__()


async def _lockscreen(screensaver: bool = False) -> None:
    from apps.base import unlock_device
    from apps.common.request_pin import can_lock_device

    # Only show the lockscreen UI if the device can in fact be locked, or if it is
    # and OLED device (in which case the lockscreen is a screensaver).
    if can_lock_device() or screensaver:
        obj = Lockscreen(
            label=storage.device.get_label(),
            coinjoin_authorized=is_set_any_session(MessageType.AuthorizeCoinJoin),
        )
        try:
            await obj
        finally:
            obj.__del__()
    # Otherwise proceed directly to unlock() call. If the device is already unlocked,
    # it should be a no-op storage-wise, but it resets the internal configuration
    # to an unlocked state.
    try:
        await unlock_device()
    except wire.PinCancelled:
        pass


def lockscreen() -> Coroutine[None, None, None]:
    return _lockscreen()


def screensaver() -> Coroutine[None, None, None]:
    return _lockscreen(screensaver=True)
