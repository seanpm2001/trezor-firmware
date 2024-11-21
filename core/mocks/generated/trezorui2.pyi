from typing import *
from trezor import utils
from trezorui_api import *


# rust/src/ui/model_mercury/layout.rs
def confirm_emphasized(
    *,
    title: str,
    items: Iterable[str | tuple[bool, str]],
    verb: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm formatted text that has been pre-split in python. For tuples
    the first component is a bool indicating whether this part is emphasized."""


# rust/src/ui/model_mercury/layout.rs
def confirm_blob(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    text_mono: bool = True,
    extra: str | None = None,
    subtitle: str | None = None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    verb_info: str | None = None,
    info: bool = True,
    hold: bool = False,
    chunkify: bool = False,
    page_counter: bool = False,
    prompt_screen: bool = False,
    cancel: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm byte sequence data."""


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
def confirm_properties(
    *,
    title: str,
    items: list[tuple[str | None, str | bytes | None, bool]],
    hold: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm list of key-value pairs. The third component in the tuple should be True if
    the value is to be rendered as binary with monospace font, False otherwise."""


# rust/src/ui/model_mercury/layout.rs
def flow_confirm_set_new_pin(
    *,
    title: str,
    description: str,
) -> LayoutObj[UiResult]:
    """Confirm new PIN setup with an option to cancel action."""


# rust/src/ui/model_mercury/layout.rs
def show_info_with_cancel(
    *,
    title: str,
    items: Iterable[Tuple[str, str]],
    horizontal: bool = False,
    chunkify: bool = False,
) -> LayoutObj[UiResult]:
    """Show metadata for outgoing transaction."""


# rust/src/ui/model_mercury/layout.rs
def confirm_value(
    *,
    title: str,
    value: str,
    description: str | None,
    subtitle: str | None,
    verb: str | None = None,
    verb_info: str | None = None,
    verb_cancel: str | None = None,
    info_button: bool = False,
    hold: bool = False,
    chunkify: bool = False,
    text_mono: bool = True,
) -> LayoutObj[UiResult]:
    """Confirm value. Merge of confirm_total and confirm_output."""


# rust/src/ui/model_mercury/layout.rs
def flow_prompt_backup() -> LayoutObj[UiResult]:
    """Prompt a user to create backup with an option to skip."""


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


# rust/src/ui/model_mercury/layout.rs
def confirm_summary(
    *,
    amount: str,
    amount_label: str,
    fee: str,
    fee_label: str,
    title: str | None = None,
    account_items: Iterable[tuple[str, str]] | None = None,
    extra_items: Iterable[tuple[str, str]] | None = None,
    extra_title: str | None = None,
    verb_cancel: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm summary of a transaction."""
from trezor import utils
from trezorui_api import *


# rust/src/ui/model_tr/layout.rs
def confirm_blob(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    text_mono: bool = True,
    extra: str | None = None,
    subtitle: str | None = None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = None,
    verb_info: str | None = None,
    info: bool = True,
    hold: bool = False,
    chunkify: bool = False,
    page_counter: bool = False,
    prompt_screen: bool = False,
    cancel: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm byte sequence data."""


# rust/src/ui/model_tr/layout.rs
def confirm_address(
    *,
    title: str,
    data: str,
    description: str | None,  # unused on TR
    extra: str | None,  # unused on TR
    verb: str = "CONFIRM",
    chunkify: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm address."""


# rust/src/ui/model_tr/layout.rs
def confirm_properties(
    *,
    title: str,
    items: list[tuple[str | None, str | bytes | None, bool]],
    hold: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm list of key-value pairs. The third component in the tuple should be True if
    the value is to be rendered as binary with monospace font, False otherwise.
    This only concerns the text style, you need to decode the value to UTF-8 in python."""


# rust/src/ui/model_tr/layout.rs
def confirm_backup() -> LayoutObj[UiResult]:
    """Strongly recommend user to do backup."""


# rust/src/ui/model_tr/layout.rs
def show_address_details(
    *,
    address: str,
    case_sensitive: bool,
    account: str | None,
    path: str | None,
    xpubs: list[tuple[str, str]],
) -> LayoutObj[UiResult]:
    """Show address details - QR code, account, path, cosigner xpubs."""


# rust/src/ui/model_tr/layout.rs
def confirm_value(
    *,
    title: str,
    description: str,
    value: str,
    verb: str | None = None,
    verb_info: str | None = None,
    hold: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm value."""


# rust/src/ui/model_tr/layout.rs
def confirm_joint_total(
    *,
    spending_amount: str,
    total_amount: str,
) -> LayoutObj[UiResult]:
    """Confirm total if there are external inputs."""


# rust/src/ui/model_tr/layout.rs
def confirm_output_address(
    *,
    address: str,
    address_label: str,
    address_title: str,
    chunkify: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm output address."""


# rust/src/ui/model_tr/layout.rs
def confirm_output_amount(
    *,
    amount: str,
    amount_title: str,
) -> LayoutObj[UiResult]:
    """Confirm output amount."""


# rust/src/ui/model_tr/layout.rs
def confirm_summary(
    *,
    amount: str,
    amount_label: str,
    fee: str,
    fee_label: str,
    title: str | None = None,
    account_items: Iterable[tuple[str, str]] | None = None,
    extra_items: Iterable[tuple[str, str]] | None = None,
    extra_title: str | None = None,
    verb_cancel: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm summary of a transaction."""


# rust/src/ui/model_tr/layout.rs
def multiple_pages_texts(
    *,
    title: str,
    verb: str,
    items: list[str],
) -> LayoutObj[UiResult]:
    """Show multiple texts, each on its own page."""


# rust/src/ui/model_tr/layout.rs
def confirm_more(
    *,
    title: str,
    button: str,
    items: Iterable[tuple[int, str | bytes]],
) -> object:
    """Confirm long content with the possibility to go back from any page.
    Meant to be used with confirm_with_info."""
from trezor import utils
from trezorui_api import *


# rust/src/ui/model_tt/layout.rs
def confirm_emphasized(
    *,
    title: str,
    items: Iterable[str | tuple[bool, str]],
    verb: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm formatted text that has been pre-split in python. For tuples
    the first component is a bool indicating whether this part is emphasized."""


# rust/src/ui/model_tt/layout.rs
def confirm_blob(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    text_mono: bool = True,
    extra: str | None = None,
    subtitle: str | None = None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    verb_info: str | None = None,
    info: bool = True,
    hold: bool = False,
    chunkify: bool = False,
    page_counter: bool = False,
    prompt_screen: bool = False,
    cancel: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm byte sequence data."""


# rust/src/ui/model_tt/layout.rs
def confirm_address(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    verb: str | None = "CONFIRM",
    extra: str | None,
    chunkify: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm address. Similar to `confirm_blob` but has corner info button
    and allows left swipe which does the same thing as the button."""


# rust/src/ui/model_tt/layout.rs
def confirm_properties(
    *,
    title: str,
    items: list[tuple[str | None, str | bytes | None, bool]],
    hold: bool = False,
) -> LayoutObj[UiResult]:
    """Confirm list of key-value pairs. The third component in the tuple should be True if
    the value is to be rendered as binary with monospace font, False otherwise."""


# rust/src/ui/model_tt/layout.rs
def show_address_details(
    *,
    qr_title: str,
    address: str,
    case_sensitive: bool,
    details_title: str,
    account: str | None,
    path: str | None,
    xpubs: list[tuple[str, str]],
) -> LayoutObj[UiResult]:
    """Show address details - QR code, account, path, cosigner xpubs."""


# rust/src/ui/model_tt/layout.rs
def show_info_with_cancel(
    *,
    title: str,
    items: Iterable[Tuple[str, str]],
    horizontal: bool = False,
    chunkify: bool = False,
) -> LayoutObj[UiResult]:
    """Show metadata for outgoing transaction."""


# rust/src/ui/model_tt/layout.rs
def confirm_value(
    *,
    title: str,
    value: str,
    description: str | None,
    subtitle: str | None,
    verb: str | None = None,
    verb_info: str | None = None,
    verb_cancel: str | None = None,
    info_button: bool = False,
    hold: bool = False,
    chunkify: bool = False,
    text_mono: bool = True,
) -> LayoutObj[UiResult]:
    """Confirm value. Merge of confirm_total and confirm_output."""


# rust/src/ui/model_tt/layout.rs
def confirm_summary(
    *,
    amount: str,
    amount_label: str,
    fee: str,
    fee_label: str,
    title: str | None = None,
    account_items: Iterable[tuple[str, str]] | None = None,
    extra_items: Iterable[tuple[str, str]] | None = None,
    extra_title: str | None = None,
    verb_cancel: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm summary of a transaction."""


# rust/src/ui/model_tt/layout.rs
def confirm_more(
    *,
    title: str,
    button: str,
    button_style_confirm: bool = False,
    items: Iterable[tuple[int, str | bytes]],
) -> LayoutObj[UiResult]:
    """Confirm long content with the possibility to go back from any page.
    Meant to be used with confirm_with_info."""
