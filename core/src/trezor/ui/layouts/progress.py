import trezorui2
from trezor import ui, utils


def progress(
    message: str = "PLEASE WAIT",
    description: str | None = None,
    indeterminate: bool = False,
) -> ui.ProgressLayout:
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


def monero_keyimage_sync_progress() -> ui.ProgressLayout:
    return progress("Syncing")


def monero_live_refresh_progress() -> ui.ProgressLayout:
    return progress("Refreshing", indeterminate=True)


def monero_transaction_progress_inner() -> ui.ProgressLayout:
    return progress("Signing transaction")
