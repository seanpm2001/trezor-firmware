from typing import *
from trezor import utils
from trezorui_api import *


# rust/src/ui/model_mercury/layout.rs
def confirm_blob_intro(
    *,
    title: str,
    data: str | bytes,
    subtitle: str | None = None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    chunkify: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm byte sequence data by showing only the first page of the data
    and instructing the user to access the menu in order to view all the data,
    which can then be confirmed using confirm_blob."""


# rust/src/ui/model_mercury/layout.rs
def flow_confirm_set_new_pin(
    *,
    title: str,
    description: str,
) -> LayoutObj[UiResult]:
    """Confirm new PIN setup with an option to cancel action."""


# rust/src/ui/model_mercury/layout.rs
def flow_get_address(
    *,
    address: str | bytes,
    title: str,
    description: str | None,
    extra: str | None,
    chunkify: bool,
    address_qr: str | None,
    case_sensitive: bool,
    account: str | None,
    path: str | None,
    xpubs: list[tuple[str, str]],
    title_success: str,
    br_code: ButtonRequestType,
    br_name: str,
) -> LayoutObj[UiResult]:
    """Get address / receive funds."""


# rust/src/ui/model_mercury/layout.rs
def flow_confirm_output(
    *,
    title: str | None,
    subtitle: str | None,
    message: str,
    amount: str | None,
    chunkify: bool,
    text_mono: bool,
    account: str | None,
    account_path: str | None,
    br_code: ButtonRequestType,
    br_name: str,
    address: str | None,
    address_title: str | None,
    summary_items: Iterable[tuple[str, str]] | None = None,
    fee_items: Iterable[tuple[str, str]] | None = None,
    summary_title: str | None = None,
    summary_br_code: ButtonRequestType | None = None,
    summary_br_name: str | None = None,
    cancel_text: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm the recipient, (optionally) confirm the amount and (optionally) confirm the summary and present a Hold to Sign page."""
from trezor import utils
from trezorui_api import *
from trezor import utils
from trezorui_api import *
