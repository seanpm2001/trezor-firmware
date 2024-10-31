# make sure to import cache unconditionally at top level so that it is imported (and retained) together with the storage module
from storage import cache, common, device


def wipe(exclude_protocol: bool = False) -> None:
    """
    Wipes the storage. Using `exclude_protocol=False` destroys the THP communication channel.
    If the device should communicate after wipe, use `exclude_protocol=True` and clear cache manually later using
    `wipe_cache()`.
    """
    from trezor import config

    config.wipe()
    cache.clear_all(exclude_protocol=exclude_protocol)


def wipe_cache():
    cache.clear_all(exclude_protocol=False)


def init_unlocked() -> None:
    # Check for storage version upgrade.
    version = device.get_version()
    if version == common.STORAGE_VERSION_01:
        _migrate_from_version_01()

    # In FWs <= 2.3.1 'version' denoted whether the device is initialized or not.
    # In 2.3.2 we have introduced a new field 'initialized' for that.
    if device.is_version_stored() and not device.is_initialized():
        common.set_bool(common.APP_DEVICE, device.INITIALIZED, True, public=True)


def reset() -> None:
    """
    Wipes storage but keeps the device id unchanged.
    """
    device_id = device.get_device_id()
    wipe(exclude_protocol=True)
    common.set(common.APP_DEVICE, device.DEVICE_ID, device_id.encode(), public=True)


def _migrate_from_version_01() -> None:
    # Make the U2F counter public and writable even when storage is locked.
    # U2F counter wasn't public, so we are intentionally not using storage.device module.
    counter = common.get(common.APP_DEVICE, device.U2F_COUNTER)
    if counter is not None:
        device.set_u2f_counter(int.from_bytes(counter, "big"))
        # Delete the old, non-public U2F_COUNTER.
        common.delete(common.APP_DEVICE, device.U2F_COUNTER)
    # set_current_version
    device.set_version(common.STORAGE_VERSION_CURRENT)
