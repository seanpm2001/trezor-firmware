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
