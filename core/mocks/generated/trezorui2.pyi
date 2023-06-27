from typing import *
CONFIRMED: object
CANCELLED: object
INFO: object


# rust/src/ui/model_tr/layout.rs
def disable_animation(disable: bool) -> None:
    """Disable animations, debug builds only."""


# rust/src/ui/model_tr/layout.rs
def toif_info(data: bytes) -> tuple[int, int, bool]:
    """Get TOIF image dimensions and format (width: int, height: int, is_grayscale: bool)."""


# rust/src/ui/model_tr/layout.rs
def confirm_action(
    *,
    title: str,
    action: str | None,
    description: str | None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = None,
    hold: bool = False,
    hold_danger: bool = False,  # unused on TR
    reverse: bool = False,
) -> object:
    """Confirm action."""


# rust/src/ui/model_tr/layout.rs
def confirm_blob(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    extra: str | None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = None,
    hold: bool = False,
) -> object:
    """Confirm byte sequence data."""


# rust/src/ui/model_tr/layout.rs
def confirm_address(
    *,
    title: str,
    data: str,
    description: str | None,  # unused on TR
    extra: str | None,  # unused on TR
) -> object:
    """Confirm address."""


# rust/src/ui/model_tr/layout.rs
def confirm_properties(
    *,
    title: str,
    items: list[tuple[str | None, str | bytes | None, bool]],
    hold: bool = False,
) -> object:
    """Confirm list of key-value pairs. The third component in the tuple should be True if
    the value is to be rendered as binary with monospace font, False otherwise.
    This only concerns the text style, you need to decode the value to UTF-8 in python."""


# rust/src/ui/model_tr/layout.rs
def confirm_reset_device(
    *,
    title: str,
    button: str,
) -> object:
    """Confirm TOS before device setup."""


# rust/src/ui/model_tr/layout.rs
def show_address_details(
    *,
    address: str,
    case_sensitive: bool,
    account: str | None,
    path: str | None,
    xpubs: list[tuple[str, str]],
) -> object:
    """Show address details - QR code, account, path, cosigner xpubs."""


# rust/src/ui/model_tr/layout.rs
def confirm_value(
    *,
    title: str,
    description: str,
    value: str,
    verb: str | None = None,
    hold: bool = False,
) -> object:
    """Confirm value."""


# rust/src/ui/model_tr/layout.rs
def confirm_joint_total(
    *,
    spending_amount: str,
    total_amount: str,
) -> object:
    """Confirm total if there are external inputs."""


# rust/src/ui/model_tr/layout.rs
def confirm_modify_output(
    *,
    address: str,
    sign: int,
    amount_change: str,
    amount_new: str,
) -> object:
    """Decrease or increase amount for given address."""


# rust/src/ui/model_tr/layout.rs
def confirm_output(
    *,
    address: str,
    amount: str,
    address_title: str,
    amount_title: str,
) -> object:
    """Confirm output."""


# rust/src/ui/model_tr/layout.rs
def confirm_total(
    *,
    total_amount: str,
    fee_amount: str,
    fee_rate_amount: str | None,
    total_label: str,
    fee_label: str,
) -> object:
    """Confirm summary of a transaction."""


# rust/src/ui/model_tr/layout.rs
def tutorial() -> object:
    """Show user how to interact with the device."""


# rust/src/ui/model_tr/layout.rs
def confirm_modify_fee(
    *,
    title: str,  # ignored
    sign: int,
    user_fee_change: str,
    total_fee_new: str,
    fee_rate_amount: str | None,
) -> object:
    """Decrease or increase transaction fee."""


# rust/src/ui/model_tr/layout.rs
def confirm_fido(
    *,
    title: str,
    app_name: str,
    icon_name: str | None,  # unused on TR
    accounts: list[str | None],
) -> int | object:
    """FIDO confirmation.
    Returns page index in case of confirmation and CANCELLED otherwise.
    """


# rust/src/ui/model_tr/layout.rs
def show_info(
    *,
    title: str,
    description: str = "",
    time_ms: int = 0,
) -> object:
    """Info modal."""


# rust/src/ui/model_tr/layout.rs
def show_mismatch() -> object:
    """Warning modal, receiving address mismatch."""


# rust/src/ui/model_tr/layout.rs
def confirm_with_info(
    *,
    title: str,
    button: str,  # unused on TR
    info_button: str,  # unused on TR
    items: Iterable[Tuple[int, str]],
) -> object:
    """Confirm given items but with third button. Always single page
    without scrolling."""


# rust/src/ui/model_tr/layout.rs
def confirm_coinjoin(
    *,
    max_rounds: str,
    max_feerate: str,
) -> object:
    """Confirm coinjoin authorization."""


# rust/src/ui/model_tr/layout.rs
def request_pin(
    *,
    prompt: str,
    subprompt: str,
    allow_cancel: bool = True,  # unused on TR
    wrong_pin: bool = False,  # unused on TR
) -> str | object:
    """Request pin on device."""


# rust/src/ui/model_tr/layout.rs
def request_passphrase(
    *,
    prompt: str,
    max_len: int,  # unused on TR
) -> str | object:
    """Get passphrase."""


# rust/src/ui/model_tr/layout.rs
def request_bip39(
    *,
    prompt: str,
) -> str:
    """Get recovery word for BIP39."""


# rust/src/ui/model_tr/layout.rs
def request_slip39(
    *,
    prompt: str,
) -> str:
   """SLIP39 word input keyboard."""


# rust/src/ui/model_tr/layout.rs
def select_word(
    *,
    title: str,  # unused on TR
    description: str,
    words: Iterable[str],
) -> int:
   """Select mnemonic word from three possibilities - seed check after backup. The
   iterable must be of exact size. Returns index in range `0..3`."""


# rust/src/ui/model_tr/layout.rs
def show_share_words(
    *,
    title: str,
    share_words: Iterable[str],
) -> object:
    """Shows a backup seed."""


# rust/src/ui/model_tr/layout.rs
def request_number(
    *,
    title: str,
    count: int,
    min_count: int,
    max_count: int,
    description: Callable[[int], str] | None = None,  # unused on TR
) -> object:
   """Number input with + and - buttons, description, and info button."""


# rust/src/ui/model_tr/layout.rs
def show_checklist(
    *,
    title: str,  # unused on TR
    items: Iterable[str],
    active: int,
    button: str,
) -> object:
   """Checklist of backup steps. Active index is highlighted, previous items have check
   mark next to them."""


# rust/src/ui/model_tr/layout.rs
def confirm_recovery(
    *,
    title: str,  # unused on TR
    description: str,
    button: str,
    dry_run: bool,
    info_button: bool,  # unused on TR
) -> object:
   """Device recovery homescreen."""


# rust/src/ui/model_tr/layout.rs
def select_word_count(
    *,
    dry_run: bool,  # unused on TR
) -> int | str:  # TR returns str
   """Select mnemonic word count from (12, 18, 20, 24, 33)."""


# rust/src/ui/model_tr/layout.rs
def show_group_share_success(
    *,
    lines: Iterable[str],
) -> int:
   """Shown after successfully finishing a group."""


# rust/src/ui/model_tr/layout.rs
def show_progress(
    *,
    title: str,
    indeterminate: bool = False,
    description: str = "",
) -> object:
   """Show progress loader. Please note that the number of lines reserved on screen for
   description is determined at construction time. If you want multiline descriptions
   make sure the initial description has at least that amount of lines."""


# rust/src/ui/model_tr/layout.rs
def show_progress_coinjoin(
    *,
    title: str,
    indeterminate: bool = False,
    time_ms: int = 0,
    skip_first_paint: bool = False,
) -> object:
   """Show progress loader for coinjoin. Returns CANCELLED after a specified time when
   time_ms timeout is passed."""


# rust/src/ui/model_tr/layout.rs
def show_homescreen(
    *,
    label: str | None,
    hold: bool,  # unused on TR
    notification: str | None,
    notification_level: int = 0,
    skip_first_paint: bool,
) -> CANCELLED:
    """Idle homescreen."""


# rust/src/ui/model_tr/layout.rs
def show_lockscreen(
    *,
    label: str | None,
    bootscreen: bool,
    skip_first_paint: bool,
) -> CANCELLED:
    """Homescreen for locked device."""


# rust/src/ui/model_tr/layout.rs
def draw_welcome_screen() -> None:
    """Show logo icon with the model name at the bottom and return."""
from trezor import utils
T = TypeVar("T")


# rust/src/ui/model_tt/layout.rs
class LayoutObj(Generic[T]):
    """Representation of a Rust-based layout object.
    see `trezor::ui::layout::obj::LayoutObj`.
    """
    def attach_timer_fn(self, fn: Callable[[int, int], None]) -> None:
        """Attach a timer setter function.
        The layout object can call the timer setter with two arguments,
        `token` and `deadline`. When `deadline` is reached, the layout object
        expects a callback to `self.timer(token)`.
        """
    if utils.USE_TOUCH:
        def touch_event(self, event: int, x: int, y: int) -> T | None:
            """Receive a touch event `event` at coordinates `x`, `y`."""
    if utils.USE_BUTTON:
        def button_event(self, event: int, button: int) -> T | None:
            """Receive a button event `event` for button `button`."""
    def progress_event(self, value: int, description: str) -> T | None:
        """Receive a progress event."""
    def usb_event(self, connected: bool) -> T | None:
        """Receive a USB connect/disconnect event."""
    def timer(self, token: int) -> T | None:
        """Callback for the timer set by `attach_timer_fn`.
        This function should be called by the executor after the corresponding
        deadline is reached.
        """
    def paint(self) -> bool:
        """Paint the layout object on screen.
        Will only paint updated parts of the layout as required.
        Returns True if any painting actually happened.
        """
    def request_complete_repaint(self) -> None:
        """Request a complete repaint of the screen.
        Does not repaint the screen, a subsequent call to `paint()` is required.
        """
    if __debug__:
        def trace(self, tracer: Callable[[str], None]) -> None:
            """Generate a JSON trace of the layout object.
            The JSON can be emitted as a sequence of calls to `tracer`, each of
            which is not necessarily a valid JSON chunk. The caller must
            reassemble the chunks to get a sensible result.
            """
        def bounds(self) -> None:
            """Paint bounds of individual components on screen."""
    def page_count(self) -> int:
        """Return the number of pages in the layout object."""
CONFIRMED: object
CANCELLED: object
INFO: object


# rust/src/ui/model_tt/layout.rs
def disable_animation(disable: bool) -> None:
    """Disable animations, debug builds only."""


# rust/src/ui/model_tt/layout.rs
def jpeg_info(data: bytes) -> tuple[int, int, int]:
    """Get JPEG image dimensions (width: int, height: int, mcu_height: int)."""


# rust/src/ui/model_tt/layout.rs
def jpeg_test(data: bytes) -> bool:
    """Test JPEG image."""


# rust/src/ui/model_tt/layout.rs
def confirm_action(
    *,
    title: str,
    action: str | None,
    description: str | None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    hold: bool = False,
    hold_danger: bool = False,
    reverse: bool = False,
) -> LayoutObj[object]:
    """Confirm action."""


# rust/src/ui/model_tt/layout.rs
def confirm_emphasized(
    *,
    title: str,
    items: Iterable[str | tuple[bool, str]],
    verb: str | None = None,
) -> LayoutObj[object]:
    """Confirm formatted text that has been pre-split in python. For tuples
    the first component is a bool indicating whether this part is emphasized."""


# rust/src/ui/model_tt/layout.rs
def confirm_homescreen(
    *,
    title: str,
    image: bytes,
) -> LayoutObj[object]:
    """Confirm homescreen."""


# rust/src/ui/model_tt/layout.rs
def confirm_blob(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    extra: str | None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    hold: bool = False,
) -> LayoutObj[object]:
    """Confirm byte sequence data."""


# rust/src/ui/model_tt/layout.rs
def confirm_address(
    *,
    title: str,
    data: str | bytes,
    description: str | None,
    extra: str | None,
) -> LayoutObj[object]:
    """Confirm address. Similar to `confirm_blob` but has corner info button
    and allows left swipe which does the same thing as the button."""


# rust/src/ui/model_tt/layout.rs
def confirm_properties(
    *,
    title: str,
    items: list[tuple[str | None, str | bytes | None, bool]],
    hold: bool = False,
) -> LayoutObj[object]:
    """Confirm list of key-value pairs. The third component in the tuple should be True if
    the value is to be rendered as binary with monospace font, False otherwise."""


# rust/src/ui/model_tt/layout.rs
def confirm_reset_device(
    *,
    title: str,
    button: str,
) -> LayoutObj[object]:
    """Confirm TOS before device setup."""


# rust/src/ui/model_tt/layout.rs
def show_address_details(
    *,
    address: str,
    case_sensitive: bool,
    account: str | None,
    path: str | None,
    xpubs: list[tuple[str, str]],
) -> LayoutObj[object]:
    """Show address details - QR code, account, path, cosigner xpubs."""


# rust/src/ui/model_tt/layout.rs
def show_spending_details(
    *,
    title: str = "INFORMATION",
    account: str | None,
    fee_rate: str | None,
    fee_rate_title: str = "Fee rate:",
) -> LayoutObj[object]:
    """Show metadata when for outgoing transaction."""


# rust/src/ui/model_tt/layout.rs
def confirm_value(
    *,
    title: str,
    value: str,
    description: str | None,
    subtitle: str | None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    info_button: bool = False,
    hold: bool = False,
) -> LayoutObj[object]:
    """Confirm value. Merge of confirm_total and confirm_output."""


# rust/src/ui/model_tt/layout.rs
def confirm_total(
    *,
    title: str,
    items: list[tuple[str, str]],
    info_button: bool = False,
) -> LayoutObj[object]:
    """Transaction summary. Always hold to confirm."""


# rust/src/ui/model_tt/layout.rs
def confirm_modify_output(
    *,
    address: str,  # ignored
    sign: int,
    amount_change: str,
    amount_new: str,
) -> LayoutObj[object]:
    """Decrease or increase amount for given address."""


# rust/src/ui/model_tt/layout.rs
def confirm_modify_fee(
    *,
    title: str,
    sign: int,
    user_fee_change: str,
    total_fee_new: str,
    fee_rate_amount: str | None,  # ignored
) -> LayoutObj[object]:
    """Decrease or increase transaction fee."""


# rust/src/ui/model_tt/layout.rs
def confirm_fido(
    *,
    title: str,
    app_name: str,
    icon_name: str | None,
    accounts: list[str | None],
) -> LayoutObj[int | object]:
    """FIDO confirmation.
    Returns page index in case of confirmation and CANCELLED otherwise.
    """


# rust/src/ui/model_tt/layout.rs
def show_error(
    *,
    title: str,
    button: str = "CONTINUE",
    description: str = "",
    allow_cancel: bool = False,
    time_ms: int = 0,
) -> LayoutObj[object]:
    """Error modal. No buttons shown when `button` is empty string."""


# rust/src/ui/model_tt/layout.rs
def show_warning(
    *,
    title: str,
    button: str = "CONTINUE",
    description: str = "",
    allow_cancel: bool = False,
    time_ms: int = 0,
) -> LayoutObj[object]:
    """Warning modal. No buttons shown when `button` is empty string."""


# rust/src/ui/model_tt/layout.rs
def show_success(
    *,
    title: str,
    button: str = "CONTINUE",
    description: str = "",
    allow_cancel: bool = False,
    time_ms: int = 0,
) -> LayoutObj[object]:
    """Success modal. No buttons shown when `button` is empty string."""


# rust/src/ui/model_tt/layout.rs
def show_info(
    *,
    title: str,
    button: str = "CONTINUE",
    description: str = "",
    allow_cancel: bool = False,
    time_ms: int = 0,
) -> LayoutObj[object]:
    """Info modal. No buttons shown when `button` is empty string."""


# rust/src/ui/model_tt/layout.rs
def show_mismatch() -> LayoutObj[object]:
    """Warning modal, receiving address mismatch."""


# rust/src/ui/model_tt/layout.rs
def show_simple(
    *,
    title: str | None,
    description: str = "",
    button: str = "",
) -> LayoutObj[object]:
    """Simple dialog with text and one button."""


# rust/src/ui/model_tt/layout.rs
def confirm_with_info(
    *,
    title: str,
    button: str,
    info_button: str,
    items: Iterable[tuple[int, str]],
) -> LayoutObj[object]:
    """Confirm given items but with third button. Always single page
    without scrolling."""


# rust/src/ui/model_tt/layout.rs
def confirm_more(
    *,
    title: str,
    button: str,
    items: Iterable[tuple[int, str]],
) -> LayoutObj[object]:
    """Confirm long content with the possibility to go back from any page.
    Meant to be used with confirm_with_info."""


# rust/src/ui/model_tt/layout.rs
def confirm_coinjoin(
    *,
    max_rounds: str,
    max_feerate: str,
) -> LayoutObj[object]:
    """Confirm coinjoin authorization."""


# rust/src/ui/model_tt/layout.rs
def request_pin(
    *,
    prompt: str,
    subprompt: str,
    allow_cancel: bool = True,
    wrong_pin: bool = False,
) -> LayoutObj[str | object]:
    """Request pin on device."""


# rust/src/ui/model_tt/layout.rs
def request_passphrase(
    *,
    prompt: str,
    max_len: int,
) -> LayoutObj[str | object]:
    """Passphrase input keyboard."""


# rust/src/ui/model_tt/layout.rs
def request_bip39(
    *,
    prompt: str,
) -> LayoutObj[str]:
    """BIP39 word input keyboard."""


# rust/src/ui/model_tt/layout.rs
def request_slip39(
    *,
    prompt: str,
) -> LayoutObj[str]:
    """SLIP39 word input keyboard."""


# rust/src/ui/model_tt/layout.rs
def select_word(
    *,
    title: str,
    description: str,
    words: Iterable[str],
) -> LayoutObj[int]:
    """Select mnemonic word from three possibilities - seed check after backup. The
   iterable must be of exact size. Returns index in range `0..3`."""


# rust/src/ui/model_tt/layout.rs
def show_share_words(
    *,
    title: str,
    pages: Iterable[str],
) -> LayoutObj[object]:
    """Show mnemonic for backup. Expects the words pre-divided into individual pages."""


# rust/src/ui/model_tt/layout.rs
def request_number(
    *,
    title: str,
    count: int,
    min_count: int,
    max_count: int,
    description: Callable[[int], str] | None = None,
) -> LayoutObj[object]:
    """Number input with + and - buttons, description, and info button."""


# rust/src/ui/model_tt/layout.rs
def show_checklist(
    *,
    title: str,
    items: Iterable[str],
    active: int,
    button: str,
) -> LayoutObj[object]:
    """Checklist of backup steps. Active index is highlighted, previous items have check
   mark next to them."""


# rust/src/ui/model_tt/layout.rs
def confirm_recovery(
    *,
    title: str,
    description: str,
    button: str,
    dry_run: bool,
    info_button: bool = False,
) -> LayoutObj[object]:
    """Device recovery homescreen."""


# rust/src/ui/model_tt/layout.rs
def select_word_count(
    *,
    dry_run: bool,
) -> LayoutObj[int | str]:  # TT returns int
    """Select mnemonic word count from (12, 18, 20, 24, 33)."""


# rust/src/ui/model_tt/layout.rs
def show_group_share_success(
    *,
    lines: Iterable[str]
) -> LayoutObj[int]:
    """Shown after successfully finishing a group."""


# rust/src/ui/model_tt/layout.rs
def show_remaining_shares(
    *,
    pages: Iterable[tuple[str, str]],
) -> LayoutObj[int]:
    """Shows SLIP39 state after info button is pressed on `confirm_recovery`."""


# rust/src/ui/model_tt/layout.rs
def show_progress(
    *,
    title: str,
    indeterminate: bool = False,
    description: str = "",
) -> LayoutObj[object]:
    """Show progress loader. Please note that the number of lines reserved on screen for
   description is determined at construction time. If you want multiline descriptions
   make sure the initial description has at least that amount of lines."""


# rust/src/ui/model_tt/layout.rs
def show_progress_coinjoin(
    *,
    title: str,
    indeterminate: bool = False,
    time_ms: int = 0,
    skip_first_paint: bool = False,
) -> LayoutObj[object]:
    """Show progress loader for coinjoin. Returns CANCELLED after a specified time when
   time_ms timeout is passed."""


# rust/src/ui/model_tt/layout.rs
def show_homescreen(
    *,
    label: str | None,
    hold: bool,
    notification: str | None,
    notification_level: int = 0,
    skip_first_paint: bool,
) -> LayoutObj[object]:
    """Idle homescreen."""


# rust/src/ui/model_tt/layout.rs
def show_lockscreen(
    *,
    label: str | None,
    bootscreen: bool,
    skip_first_paint: bool,
) -> LayoutObj[object]:
    """Homescreen for locked device."""


# rust/src/ui/model_tt/layout.rs
def draw_welcome_screen() -> LayoutObj[None]:
    """Show logo icon with the model name at the bottom and return."""
