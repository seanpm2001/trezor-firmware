from typing import *
from trezor import utils
T = TypeVar("T")


# rust/src/ui/api/firmware_upy.rs
class LayoutObj(Generic[T]):
    """Representation of a Rust-based layout object.
    see `trezor::ui::layout::obj::LayoutObj`.
    """
    def attach_timer_fn(self, fn: Callable[[int, int], None], attach_type: AttachType | None) -> LayoutState | None:
        """Attach a timer setter function.
        The layout object can call the timer setter with two arguments,
        `token` and `duration_ms`. When `duration_ms` elapses, the layout object
        expects a callback to `self.timer(token)`.
        """
    if utils.USE_TOUCH:
        def touch_event(self, event: int, x: int, y: int) -> LayoutState | None:
            """Receive a touch event `event` at coordinates `x`, `y`."""
    if utils.USE_BUTTON:
        def button_event(self, event: int, button: int) -> LayoutState | None:
            """Receive a button event `event` for button `button`."""
    def progress_event(self, value: int, description: str) -> LayoutState | None:
        """Receive a progress event."""
    def usb_event(self, connected: bool) -> LayoutState | None:
        """Receive a USB connect/disconnect event."""
    def timer(self, token: int) -> LayoutState | None:
        """Callback for the timer set by `attach_timer_fn`.
        This function should be called by the executor after the corresponding
        duration elapses.
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
    def button_request(self) -> tuple[int, str] | None:
        """Return (code, type) of button request made during the last event or timer pass."""
    def get_transition_out(self) -> AttachType:
        """Return the transition type."""
    def return_value(self) -> T:
        """Retrieve the return value of the layout object."""
    def __del__(self) -> None:
        """Calls drop on contents of the root component."""


# rust/src/ui/api/firmware_upy.rs
class UiResult:
   """Result of a UI operation."""
   pass
CONFIRMED: UiResult
CANCELLED: UiResult
INFO: UiResult


# rust/src/ui/api/firmware_upy.rs
def check_homescreen_format(data: bytes) -> bool:
    """Check homescreen format and dimensions."""


# rust/src/ui/api/firmware_upy.rs
def disable_animation(disable: bool) -> None:
    """Disable animations, debug builds only."""


# rust/src/ui/api/firmware_upy.rs
def confirm_action(
    *,
    title: str,
    action: str | None,
    description: str | None,
    subtitle: str | None = None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    hold: bool = False,
    hold_danger: bool = False,
    reverse: bool = False,
    prompt_screen: bool = False,
    prompt_title: str | None = None,
) -> LayoutObj[UiResult]:
    """Confirm action."""


# rust/src/ui/api/firmware_upy.rs
def request_bip39(
    *,
    prompt: str,
    prefill_word: str,
    can_go_back: bool,
) -> LayoutObj[str]:
    """BIP39 word input keyboard."""


# rust/src/ui/api/firmware_upy.rs
def request_slip39(
    *,
    prompt: str,
    prefill_word: str,
    can_go_back: bool,
) -> LayoutObj[str]:
   """SLIP39 word input keyboard."""


# rust/src/ui/api/firmware_upy.rs
def request_pin(
    *,
    prompt: str,
    subprompt: str,
    allow_cancel: bool = True,
    wrong_pin: bool = False,
) -> LayoutObj[str | UiResult]:
    """Request pin on device."""


# rust/src/ui/api/firmware_upy.rs
def request_passphrase(
    *,
    prompt: str,
    max_len: int,
) -> LayoutObj[str | UiResult]:
    """Passphrase input keyboard."""


# rust/src/ui/api/firmware_upy.rs
def select_word(
    *,
    title: str,
    description: str,
    words: Iterable[str],
) -> LayoutObj[int]:
    """Select mnemonic word from three possibilities - seed check after backup. The
   iterable must be of exact size. Returns index in range `0..3`."""


# rust/src/ui/api/firmware_upy.rs
def select_word_count(
    *,
    recovery_type: RecoveryType,
) -> LayoutObj[int | str]:  # TR returns str
    """Select a mnemonic word count from the options: 12, 18, 20, 24, or 33.
    For unlocking a repeated backup, select from 20 or 33."""


# rust/src/ui/api/firmware_upy.rs
def show_info(
    *,
    title: str,
    description: str = "",
    button: str = "",
    time_ms: int = 0,
) -> LayoutObj[UiResult]:
    """Info screen."""


# rust/src/ui/api/firmware_upy.rs
class BacklightLevels:
    """Backlight levels. Values dynamically update based on user settings."""
    MAX: ClassVar[int]
    NORMAL: ClassVar[int]
    LOW: ClassVar[int]
    DIM: ClassVar[int]
    NONE: ClassVar[int]


# rust/src/ui/api/firmware_upy.rs
class AttachType:
    INITIAL: ClassVar[int]
    RESUME: ClassVar[int]
    SWIPE_UP: ClassVar[int]
    SWIPE_DOWN: ClassVar[int]
    SWIPE_LEFT: ClassVar[int]
    SWIPE_RIGHT: ClassVar[int]


# rust/src/ui/api/firmware_upy.rs
class LayoutState:
    """Layout state."""
    INITIAL: "ClassVar[LayoutState]"
    ATTACHED: "ClassVar[LayoutState]"
    TRANSITIONING: "ClassVar[LayoutState]"
    DONE: "ClassVar[LayoutState]"
