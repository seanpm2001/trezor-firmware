import trezorui2
from trezor import TR, ui, utils


def progress(
    message: str | None = None,
    description: str | None = None,
    indeterminate: bool = False,
) -> ui.ProgressLayout:
    if message is None:
        message = TR.progress__please_wait  # def_arg

    if utils.MODEL_IS_T2B1 and description is None:
        description = message + "..."
        title = ""
    else:
        title = message.upper()

    return ui.ProgressLayout(
        layout=trezorui2.show_progress(
            title=title,
            indeterminate=indeterminate,
            description=description or "",
        )
    )


def bitcoin_progress(message: str) -> ui.ProgressLayout:
    return progress(message)


def coinjoin_progress(message: str) -> ui.ProgressLayout:
    return ui.ProgressLayout(
        layout=trezorui2.show_progress_coinjoin(
            title=message + "...", indeterminate=False
        )
    )


def pin_progress(message: str, description: str) -> ui.ProgressLayout:
    return progress(message, description=description)

if utils.BITCOIN_ONLY:

    def monero_keyimage_sync_progress() -> ui.ProgressLayout:
        return progress(TR.progress__syncing)

    def monero_live_refresh_progress() -> ui.ProgressLayout:
        return progress(TR.progress__refreshing, indeterminate=True)

    def monero_transaction_progress_inner() -> ui.ProgressLayout:
        return progress(TR.progress__signing_transaction)
