import trezorui2
from trezor import TR, ui, utils


def progress(
    description: str = "",
    title: str | None = None,
    indeterminate: bool = False,
) -> ui.ProgressLayout:
    if not utils.MODEL_IS_T2B1:
        if title is None:
            title = TR.progress__please_wait
        title = title.upper()
    elif description:
        description += "..."

    # if message is None:
    #     if utils.MODEL_IS_T2B1:
    #         message = ""
    #     else:
    #         message = TR.progress__please_wait  # def_arg

    # if utils.MODEL_IS_T2B1 and description is None and message is not None:
    #     description = message + "..."
    #     title = ""
    # else:
    #     title = message.upper()

    return ui.ProgressLayout(
        layout=trezorui2.show_progress(
            title=title,
            indeterminate=indeterminate,
            description=description,
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
    return progress(description, title=message)

if utils.BITCOIN_ONLY:

    def monero_keyimage_sync_progress() -> ui.ProgressLayout:
        return progress(TR.progress__syncing)

    def monero_live_refresh_progress() -> ui.ProgressLayout:
        return progress(TR.progress__refreshing, indeterminate=True)

    def monero_transaction_progress_inner() -> ui.ProgressLayout:
        return progress(TR.progress__signing_transaction)
