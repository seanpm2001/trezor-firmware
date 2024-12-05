# This file is part of the Trezor project.
#
# Copyright (C) 2012-2024 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from __future__ import annotations

import json
import logging
import re
import textwrap
import time
import typing as t
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from enum import Enum, IntEnum, auto
from itertools import zip_longest
from pathlib import Path

from mnemonic import Mnemonic

from . import btc, mapping, messages, models, protobuf
from .client import (
    MAX_PASSPHRASE_LENGTH,
    MAX_PIN_LENGTH,
    PASSPHRASE_ON_DEVICE,
    TrezorClient,
)
from .exceptions import Cancelled, PinException, TrezorFailure
from .log import DUMP_BYTES
from .messages import Capability, DebugWaitType
from .tools import expect, parse_path
from .transport.session import Session, SessionV1
from .transport.thp.protocol_v1 import ProtocolV1

if t.TYPE_CHECKING:
    from typing_extensions import Protocol

    from .messages import PinMatrixRequestType
    from .transport import Transport

    ExpectedMessage = t.Union[
        protobuf.MessageType, t.Type[protobuf.MessageType], "MessageFilter"
    ]

    AnyDict = t.Dict[str, t.Any]

    class InputFunc(Protocol):

        def __call__(
            self,
            hold_ms: int | None = None,
            wait: bool | None = None,
        ) -> "LayoutContent": ...


EXPECTED_RESPONSES_CONTEXT_LINES = 3
PASSPHRASE_TEST_PATH = parse_path("44h/1h/0h/0/0")

LOG = logging.getLogger(__name__)


class LayoutType(Enum):
    T1 = auto()
    TT = auto()
    TR = auto()
    Mercury = auto()

    @classmethod
    def from_model(cls, model: models.TrezorModel) -> "LayoutType":
        if model in (models.T2T1,):
            return cls.TT
        if model in (models.T2B1, models.T3B1):
            return cls.TR
        if model in (models.T3T1,):
            return cls.Mercury
        if model in (models.T1B1,):
            return cls.T1
        raise ValueError(f"Unknown model: {model}")


class UnstructuredJSONReader:
    """Contains data-parsing helpers for JSON data that have unknown structure."""

    def __init__(self, json_str: str) -> None:
        self.json_str = json_str
        # We may not receive valid JSON, e.g. from an old model in upgrade tests
        try:
            self.dict: AnyDict = json.loads(json_str)
        except json.JSONDecodeError:
            self.dict = {}

    def top_level_value(self, key: str) -> t.Any:
        return self.dict.get(key)

    def find_objects_with_key_and_value(
        self, key: str, value: t.Any
    ) -> list["AnyDict"]:
        def recursively_find(data: t.Any) -> t.Iterator[t.Any]:
            if isinstance(data, dict):
                if data.get(key) == value:
                    yield data
                for val in data.values():
                    yield from recursively_find(val)
            elif isinstance(data, list):
                for item in data:
                    yield from recursively_find(item)

        return list(recursively_find(self.dict))

    def find_unique_object_with_key_and_value(
        self, key: str, value: t.Any
    ) -> AnyDict | None:
        objects = self.find_objects_with_key_and_value(key, value)
        if not objects:
            return None
        assert len(objects) == 1
        return objects[0]

    def find_values_by_key(
        self, key: str, only_type: type | None = None
    ) -> list[t.Any]:
        def recursively_find(data: t.Any) -> t.Iterator[t.Any]:
            if isinstance(data, dict):
                if key in data:
                    yield data[key]
                for val in data.values():
                    yield from recursively_find(val)
            elif isinstance(data, list):
                for item in data:
                    yield from recursively_find(item)

        values = list(recursively_find(self.dict))

        if only_type is not None:
            values = [v for v in values if isinstance(v, only_type)]

        return values

    def find_unique_value_by_key(
        self, key: str, default: t.Any, only_type: type | None = None
    ) -> t.Any:
        values = self.find_values_by_key(key, only_type=only_type)
        if not values:
            return default
        assert len(values) == 1
        return values[0]


class LayoutContent(UnstructuredJSONReader):
    """Contains helper functions to extract specific parts of the layout."""

    def __init__(self, json_tokens: t.Sequence[str]) -> None:
        json_str = "".join(json_tokens)
        super().__init__(json_str)

    def main_component(self) -> str:
        """Getting the main component of the layout."""
        return self.top_level_value("component") or "no main component"

    def all_components(self) -> list[str]:
        """Getting all components of the layout."""
        return self.find_values_by_key("component", only_type=str)

    def visible_screen(self) -> str:
        """String representation of a current screen content.
        Example:
            SIGN TRANSACTION
            --------------------
            You are about to
            sign 3 actions.
            ********************
            ICON_CANCEL, -, CONFIRM
        """
        title_separator = f"\n{20 * '-'}\n"
        btn_separator = f"\n{20 * '*'}\n"

        visible = ""
        if self.title():
            visible += self.title()
            visible += title_separator
        visible += self.screen_content()
        visible_buttons = self.button_contents()
        if visible_buttons:
            visible += btn_separator
            visible += ", ".join(visible_buttons)

        return visible

    def _get_str_or_dict_text(self, key: str) -> str:
        value = self.find_unique_value_by_key(key, "")
        if isinstance(value, dict):
            return value["text"]
        return value

    def title(self) -> str:
        """Getting text that is displayed as a title and potentially subtitle."""
        # There could be possibly subtitle as well
        title_parts: list[str] = []

        title = self._get_str_or_dict_text("title")
        if title:
            title_parts.append(title)

        subtitle = self.subtitle()
        if subtitle:
            title_parts.append(subtitle)

        return "\n".join(title_parts)

    def subtitle(self) -> str:
        """Getting text that is displayed as a subtitle."""
        subtitle = self._get_str_or_dict_text("subtitle")
        return subtitle

    def text_content(self) -> str:
        """What is on the screen, in one long string, so content can be
        asserted regardless of newlines. Also getting rid of possible ellipsis.
        """
        content = self.screen_content().replace("\n", " ")
        if content.endswith("..."):
            content = content[:-3]
        if content.startswith("..."):
            content = content[3:]
        return content

    def screen_content(self) -> str:
        """Getting text that is displayed in the main part of the screen.
        Preserving the line breaks.
        """
        # Look for paragraphs first (will match most of the time for TT)
        paragraphs = self.raw_content_paragraphs()
        if paragraphs:
            main_text_blocks: list[str] = []
            for par in paragraphs:
                par_content = ""
                for line_or_newline in par:
                    par_content += line_or_newline
                par_content.replace("\n", " ")
                main_text_blocks.append(par_content)
            return "\n".join(main_text_blocks)

        # Formatted text
        formatted_text = self.find_unique_object_with_key_and_value(
            "component", "FormattedText"
        )
        if formatted_text:
            text_lines = formatted_text["text"]
            return "".join(text_lines)

        # Check the choice_page - mainly for TR
        choice_page = self.find_unique_object_with_key_and_value(
            "component", "ChoicePage"
        )
        if choice_page:
            left = choice_page.get("prev_choice", {}).get("content", "")
            middle = choice_page.get("current_choice", {}).get("content", "")
            right = choice_page.get("next_choice", {}).get("content", "")
            return " ".join(choice for choice in (left, middle, right) if choice)

        # Screen content - in TR share words
        screen_content = self.find_unique_value_by_key(
            "screen_content", default="", only_type=str
        )
        if screen_content:
            return screen_content

        # Flow page - for TR
        flow_page = self.find_unique_value_by_key(
            "flow_page", default={}, only_type=dict
        )
        if flow_page:
            text_lines = flow_page["text"]
            return "".join(text_lines)

        # Looking for any "text": "something" values
        text_values = self.find_values_by_key("text", only_type=str)
        if text_values:
            return "\n".join(text_values)

        # Default when not finding anything
        return self.main_component()

    def raw_content_paragraphs(self) -> list[list[str]] | None:
        """Getting raw paragraphs as sent from Rust."""
        return self.find_unique_value_by_key("paragraphs", default=None, only_type=list)

    def tt_check_seed_button_contents(self) -> list[str]:
        """Getting list of button contents."""
        buttons: list[str] = []
        button_objects = self.find_objects_with_key_and_value("component", "Button")
        for button in button_objects:
            if button.get("icon"):
                buttons.append("ICON")
            elif "text" in button:
                buttons.append(button["text"])
        return buttons

    def button_contents(self) -> list[str]:
        """Getting list of button contents."""
        buttons = self.find_unique_value_by_key("buttons", default={}, only_type=dict)

        def get_button_content(btn_key: str) -> str:
            button_obj = buttons.get(btn_key, {})
            if button_obj.get("component") == "Button":
                if "icon" in button_obj:
                    return button_obj["icon"]
                elif "text" in button_obj:
                    return button_obj["text"]
            elif button_obj.get("component") == "HoldToConfirm":
                text = button_obj.get("loader", {}).get("text", "")
                duration = button_obj.get("loader", {}).get("duration", "")
                return f"{text} ({duration}ms)"

            # default value
            return "-"

        button_keys = ("left_btn", "middle_btn", "right_btn")
        return [get_button_content(btn_key) for btn_key in button_keys]

    def seed_words(self) -> list[str]:
        """Get all the seed words on the screen in order.

        Example content: "1. ladybug\n2. acid\n3. academic\n4. afraid"
          -> ["ladybug", "acid", "academic", "afraid"]
        """
        words: list[str] = []
        for line in self.screen_content().split("\n"):
            # Dot after index is optional (present on TT, not on TR)
            match = re.match(r"^\s*\d+\.? (\w+)$", line)
            if match:
                words.append(match.group(1))
        return words

    def pin(self) -> str:
        """Get PIN from the layout."""
        assert "PinKeyboard" in self.all_components()
        return self.find_unique_value_by_key("pin", default="", only_type=str)

    def passphrase(self) -> str:
        """Get passphrase from the layout."""
        assert "PassphraseKeyboard" in self.all_components()
        return self.find_unique_value_by_key("passphrase", default="", only_type=str)

    def page_count(self) -> int:
        """Get number of pages for the layout."""
        return (
            self.find_unique_value_by_key(
                "scrollbar_page_count", default=0, only_type=int
            )
            or self.find_unique_value_by_key("page_count", default=0, only_type=int)
            or 1
        )

    def active_page(self) -> int:
        """Get current page index of the layout."""
        return self.find_unique_value_by_key("active_page", default=0, only_type=int)

    def tt_pin_digits_order(self) -> str:
        """In what order the PIN buttons are shown on the screen. Only for TT."""
        return self.top_level_value("digits_order") or "no digits order"

    def get_middle_choice(self) -> str:
        """What is the choice being selected right now."""
        return self.choice_items()[1]

    def choice_items(self) -> tuple[str, str, str]:
        """Getting actions for all three possible buttons."""
        choice_obj = self.find_unique_value_by_key(
            "choice_page", default={}, only_type=dict
        )
        if not choice_obj:
            raise RuntimeError("No choice_page object in trace")
        choice_keys = ("prev_choice", "current_choice", "next_choice")
        return tuple(
            choice_obj.get(choice, {}).get("content", "") for choice in choice_keys
        )

    def footer(self) -> str:
        footer = self.find_unique_object_with_key_and_value("component", "Footer")
        if not footer:
            return ""
        return footer.get("description", "") + " " + footer.get("instruction", "")


def multipage_content(layouts: list[LayoutContent]) -> str:
    """Get overall content from multiple-page layout."""
    return "".join(layout.text_content() for layout in layouts)


def _make_input_func(
    button: messages.DebugButton | None = None,
    physical_button: messages.DebugPhysicalButton | None = None,
    swipe: messages.DebugSwipeDirection | None = None,
) -> "InputFunc":
    decision = messages.DebugLinkDecision(
        button=button,
        physical_button=physical_button,
        swipe=swipe,
    )

    def input_func(
        self: "DebugLink",
        hold_ms: int | None = None,
        wait: bool | None = None,
    ) -> LayoutContent:
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612
        decision.hold_ms = hold_ms
        return self._decision(decision, wait=wait)

    return input_func  # type: ignore [Parameter name mismatch]


class DebugLink:

    def __init__(self, transport: "Transport", auto_interact: bool = True) -> None:
        self.transport = transport
        self.allow_interactions = auto_interact
        self.mapping = mapping.DEFAULT_MAPPING

        self.protocol = ProtocolV1(self.transport, self.mapping)
        # To be set by TrezorClientDebugLink (is not known during creation time)
        self.model: models.TrezorModel | None = None
        self.version: tuple[int, int, int] = (0, 0, 0)

        # Where screenshots are being saved
        self.screenshot_recording_dir: str | None = None

        # For T1 screenshotting functionality in DebugUI
        self.t1_screenshot_directory: Path | None = None
        self.t1_screenshot_counter = 0

        # Optional file for saving text representation of the screen
        self.screen_text_file: Path | None = None
        self.last_screen_content = ""

        self.waiting_for_layout_change = False
        self.layout_dirty = True

        self.input_wait_type = DebugWaitType.IMMEDIATE

    @property
    def legacy_ui(self) -> bool:
        """Differences between UI1 and UI2."""
        return self.version < (2, 6, 0)

    @property
    def legacy_debug(self) -> bool:
        """Differences in handling debug events and LayoutContent."""
        return self.version < (2, 6, 1)

    @property
    def has_global_layout(self) -> bool:
        """Differences in waiting for Global Layout objects."""
        return self.version >= (2, 8, 6)

    @property
    def responds_to_debuglink_in_usb_tiny(self) -> bool:
        """Whether a Trezor One can respond to DebugLinkGetState while waiting
        for a Button/Pin/Passphrase Ack."""
        return self.version >= (1, 11, 0)

    @property
    def layout_type(self) -> LayoutType:
        assert self.model is not None
        return LayoutType.from_model(self.model)

    def set_screen_text_file(self, file_path: Path | None) -> None:
        if file_path is not None:
            file_path.write_bytes(b"")
        self.screen_text_file = file_path

    def open(self) -> None:
        self.transport.open()
        # raise NotImplementedError
        # TODO is this needed?
        # self.transport.deprecated_begin_session()

    def close(self) -> None:
        pass
        # raise NotImplementedError
        # TODO is this needed?
        # self.transport.deprecated_end_session()

    def _write(self, msg: protobuf.MessageType) -> None:
        if self.waiting_for_layout_change:
            raise RuntimeError(
                "Debuglink is unavailable while waiting for layout change."
            )

        LOG.debug(
            f"sending message: {msg.__class__.__name__}",
            extra={"protobuf": msg},
        )
        msg_type, msg_bytes = self.mapping.encode(msg)
        LOG.log(
            DUMP_BYTES,
            f"encoded as type {msg_type} ({len(msg_bytes)} bytes): {msg_bytes.hex()}",
        )
        self.protocol.write(msg)

    def _read(self) -> protobuf.MessageType:
        msg = self.protocol.read()

        # Collapse tokens to make log use less lines.
        msg_for_log = msg
        if isinstance(msg, (messages.DebugLinkState, messages.DebugLinkLayout)):
            msg_for_log = deepcopy(msg)
            msg_for_log.tokens = ["".join(msg_for_log.tokens)]

        LOG.debug(
            f"received message: {msg_for_log.__class__.__name__}",
            extra={"protobuf": msg_for_log},
        )
        return msg

    def _call(self, msg: protobuf.MessageType) -> t.Any:
        self._write(msg)
        return self._read()

    def state(
        self,
        wait_type: DebugWaitType | None = None,
        thp_channel_id: bytes | None = None,
    ) -> messages.DebugLinkState:
        if wait_type is None:
            wait_type = (
                DebugWaitType.CURRENT_LAYOUT
                if self.has_global_layout
                else DebugWaitType.IMMEDIATE
            )
        result = self._call(
            messages.DebugLinkGetState(
                wait_layout=wait_type,
                thp_channel_id=thp_channel_id,
            )
        )
        while not isinstance(result, (messages.Failure, messages.DebugLinkState)):
            result = self._read()
        if isinstance(result, messages.Failure):
            raise TrezorFailure(result)
        return result

    def read_layout(self) -> LayoutContent:
        return LayoutContent(self.state().tokens)

    def wait_layout(self, wait_for_external_change: bool = False) -> LayoutContent:
        # Next layout change will be caused by external event
        # (e.g. device being auto-locked or as a result of device_handler.run_with_session(xxx))
        # and not by our debug actions/decisions.
        # Resetting the debug state so we wait for the next layout change
        # (and do not return the current state).
        if wait_for_external_change:
            self.reset_debug_events()

        obj = self._call(
            messages.DebugLinkGetState(wait_layout=DebugWaitType.NEXT_LAYOUT)
        )
        self.layout_dirty = True
        if isinstance(obj, messages.Failure):
            raise TrezorFailure(obj)
        return LayoutContent(obj.tokens)

    @contextmanager
    def wait_for_layout_change(self) -> t.Iterator[LayoutContent]:
        # set up a dummy layout content object to be yielded
        layout_content = LayoutContent(
            ["DUMMY CONTENT, WAIT UNTIL THE END OF THE BLOCK :("]
        )

        # make sure some current layout is up by issuing a dummy GetState
        self.state()

        # send GetState without waiting for reply
        self._write(messages.DebugLinkGetState(wait_layout=DebugWaitType.NEXT_LAYOUT))

        # allow the block to proceed
        self.waiting_for_layout_change = True
        try:
            yield layout_content
        finally:
            self.waiting_for_layout_change = False
            self.layout_dirty = True

        # wait for the reply
        resp = self._read()
        assert isinstance(resp, messages.DebugLinkState)

        # replace contents of the yielded object with the new thing
        layout_content.__init__(resp.tokens)

    def reset_debug_events(self) -> None:
        # Only supported on TT and above certain version
        if (self.model is not models.T1B1) and not self.legacy_debug:
            return self._call(messages.DebugLinkResetDebugEvents())
        return None

    def synchronize_at(self, layout_text: str, timeout: float = 5) -> LayoutContent:
        now = time.monotonic()
        while True:
            layout = self.read_layout()
            if layout_text in layout.json_str:
                return layout
            if time.monotonic() - now > timeout:
                raise RuntimeError("Timeout waiting for layout")
            time.sleep(0.1)

    def watch_layout(self, watch: bool) -> None:
        """Enable or disable watching layouts.
        If disabled, wait_layout will not work.

        The message is missing on T1. Use `TrezorClientDebugLink.watch_layout` for
        cross-version compatibility.
        """
        self._call(messages.DebugLinkWatchLayout(watch=watch))

    def encode_pin(self, pin: str, matrix: str | None = None) -> str:
        """Transform correct PIN according to the displayed matrix."""
        if matrix is None:
            matrix = self.state().matrix
            if matrix is None:
                # we are on trezor-core
                return pin

        return "".join([str(matrix.index(p) + 1) for p in pin])

    def read_recovery_word(self) -> t.Tuple[str | None, int | None]:
        state = self.state()
        return (state.recovery_fake_word, state.recovery_word_pos)

    def read_reset_word(self) -> str:
        state = self._call(messages.DebugLinkGetState(wait_word_list=True))
        return state.reset_word

    def _decision(
        self, decision: messages.DebugLinkDecision, wait: bool | None = None
    ) -> LayoutContent:
        """Send a debuglink decision and returns the resulting layout.

        If hold_ms is set, an additional 200ms is added to account for processing
        delays. (This is needed for hold-to-confirm to trigger reliably.)

        If `wait` is unset, the following wait mode is used:

        - `IMMEDIATE`, when in normal tests, which never deadlocks the device, but may
          return an empty layout in case the next one didn't come up immediately. (E.g.,
          in SignTx flow, the device is waiting for more TxRequest/TxAck exchanges
          before showing the next UI layout.)
        - `CURRENT_LAYOUT`, when in tests running through a `DeviceHandler`. This mode
          returns the current layout or waits for some layout to come up if there is
          none at the moment. The assumption is that wirelink is communicating on
          another thread and won't be blocked by waiting on debuglink.

        Force waiting for the layout by setting `wait=True`. Force not waiting by
        setting `wait=False` -- useful when, e.g., you are causing the next layout to be
        deliberately delayed.
        """
        if not self.allow_interactions:
            return self.wait_layout()

        if decision.hold_ms is not None:
            decision.hold_ms += 200

        self._write(decision)
        self.layout_dirty = True
        if wait is True:
            wait_type = DebugWaitType.CURRENT_LAYOUT
        elif wait is False:
            wait_type = DebugWaitType.IMMEDIATE
        else:
            wait_type = self.input_wait_type
        return self._snapshot_core(wait_type)

    press_yes = _make_input_func(button=messages.DebugButton.YES)
    """Confirm current layout. See `_decision` for more details."""
    press_no = _make_input_func(button=messages.DebugButton.NO)
    """Reject current layout. See `_decision` for more details."""
    press_info = _make_input_func(button=messages.DebugButton.INFO)
    """Trigger the Info action. See `_decision` for more details."""
    swipe_up = _make_input_func(swipe=messages.DebugSwipeDirection.UP)
    """Swipe up. See `_decision` for more details."""
    swipe_down = _make_input_func(swipe=messages.DebugSwipeDirection.DOWN)
    """Swipe down. See `_decision` for more details."""
    swipe_right = _make_input_func(swipe=messages.DebugSwipeDirection.RIGHT)
    """Swipe right. See `_decision` for more details."""
    swipe_left = _make_input_func(swipe=messages.DebugSwipeDirection.LEFT)
    """Swipe left. See `_decision` for more details."""
    press_left = _make_input_func(physical_button=messages.DebugPhysicalButton.LEFT_BTN)
    """Press left button. See `_decision` for more details."""
    press_middle = _make_input_func(
        physical_button=messages.DebugPhysicalButton.MIDDLE_BTN
    )
    """Press middle button. See `_decision` for more details."""
    press_right = _make_input_func(
        physical_button=messages.DebugPhysicalButton.RIGHT_BTN
    )
    """Press right button. See `_decision` for more details."""

    def input(self, word: str, wait: bool | None = None) -> LayoutContent:
        """Send text input to the device. See `_decision` for more details."""
        return self._decision(messages.DebugLinkDecision(input=word), wait)

    def click(
        self,
        click: t.Tuple[int, int],
        hold_ms: int | None = None,
        wait: bool | None = None,
    ) -> LayoutContent:
        """Send a click to the device. See `_decision` for more details."""
        x, y = click
        return self._decision(
            messages.DebugLinkDecision(x=x, y=y, hold_ms=hold_ms), wait
        )

    def _snapshot_core(
        self, wait_type: DebugWaitType = DebugWaitType.IMMEDIATE
    ) -> LayoutContent:
        """Save text and image content of the screen to relevant directories."""
        # skip the snapshot if we are on T1
        if self.model is models.T1B1:
            return LayoutContent([])

        # take the snapshot
        state = self.state(wait_type)
        layout = LayoutContent(state.tokens)

        if state.tokens and self.layout_dirty:
            # save it, unless we already did or unless it's empty
            self.save_debug_screen(layout.visible_screen())
            self.layout_dirty = False

        # return the layout
        return layout

    def save_debug_screen(self, screen_content: str) -> None:
        if self.screen_text_file is None:
            return

        if not self.screen_text_file.exists():
            self.screen_text_file.write_bytes(b"")

        # Not writing the same screen twice
        if screen_content == self.last_screen_content:
            return

        self.last_screen_content = screen_content

        with open(self.screen_text_file, "a") as f:
            f.write(screen_content)
            f.write("\n" + 80 * "/" + "\n")

    def stop(self) -> None:
        self._write(messages.DebugLinkStop())

    def reseed(self, value: int) -> protobuf.MessageType:
        return self._call(messages.DebugLinkReseedRandom(value=value))

    def start_recording(self, directory: str, refresh_index: int | None = None) -> None:
        self.screenshot_recording_dir = directory
        # Different recording logic between core and legacy
        if self.model is not models.T1B1:
            self._call(
                messages.DebugLinkRecordScreen(
                    target_directory=directory, refresh_index=refresh_index
                )
            )
        else:
            self.t1_screenshot_directory = Path(directory)
            self.t1_screenshot_counter = 0
            self.t1_take_screenshots = True

    def stop_recording(self) -> None:
        self.screenshot_recording_dir = None
        # Different recording logic between TT and T1
        if self.model is not models.T1B1:
            self._call(messages.DebugLinkRecordScreen(target_directory=None))
        else:
            self.t1_take_screenshots = False

    @expect(messages.DebugLinkMemory, field="memory", ret_type=bytes)
    def memory_read(self, address: int, length: int) -> protobuf.MessageType:
        return self._call(messages.DebugLinkMemoryRead(address=address, length=length))

    def memory_write(self, address: int, memory: bytes, flash: bool = False) -> None:
        self._write(
            messages.DebugLinkMemoryWrite(address=address, memory=memory, flash=flash)
        )

    def flash_erase(self, sector: int) -> None:
        self._write(messages.DebugLinkFlashErase(sector=sector))

    @expect(messages.Success)
    def erase_sd_card(self, format: bool = True) -> messages.Success:
        return self._call(messages.DebugLinkEraseSdCard(format=format))

    def snapshot_legacy(self) -> None:
        """Snapshot the current state of the device."""
        if self.model is not models.T1B1:
            return

        if not self.responds_to_debuglink_in_usb_tiny:
            return

        state = self.state()
        if state.layout is not None:
            self._save_screenshot_t1(state.layout)

    def _save_screenshot_t1(self, data: bytes) -> None:
        if self.t1_screenshot_directory is None:
            return

        from PIL import Image

        assert len(data) == 128 * 64 // 8

        pixels: list[int] = []
        for byteline in range(64 // 8):
            offset = byteline * 128
            row = data[offset : offset + 128]
            for bit in range(8):
                pixels.extend(bool(px & (1 << bit)) for px in row)

        im = Image.new("1", (128, 64))
        im.putdata(pixels[::-1])

        img_location = (
            self.t1_screenshot_directory / f"{self.t1_screenshot_counter:04d}.png"
        )
        im.save(img_location)
        self.t1_screenshot_counter += 1


del _make_input_func


class NullDebugLink(DebugLink):
    def __init__(self) -> None:
        # Ignoring type error as self.transport will not be touched while using NullDebugLink
        super().__init__(None)  # type: ignore [Argument of type "None" cannot be assigned to parameter "transport"]

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def _call(
        self, msg: protobuf.MessageType, nowait: bool = False
    ) -> messages.DebugLinkState | None:
        if not nowait:
            if isinstance(msg, messages.DebugLinkGetState):
                return messages.DebugLinkState()
            else:
                raise RuntimeError("unexpected call to a fake debuglink")

        return None


class DebugUI:
    INPUT_FLOW_DONE = object()

    def __init__(self, debuglink: DebugLink) -> None:
        self.debuglink = debuglink
        self.clear()

    def clear(self) -> None:
        self.pins: t.Iterator[str] | None = None
        self.passphrase = ""
        self.input_flow: t.Union[
            t.Generator[None, messages.ButtonRequest, None], object, None
        ] = None

    def _default_input_flow(self, br: messages.ButtonRequest) -> None:
        if br.code == messages.ButtonRequestType.PinEntry:
            self.debuglink.input(self.get_pin())
        else:
            # Paginating (going as further as possible) and pressing Yes
            if br.pages is not None:
                for _ in range(br.pages - 1):
                    self.debuglink.swipe_up(wait=True)
            if self.debuglink.model is models.T3T1:
                layout = self.debuglink.read_layout()
                if "PromptScreen" in layout.all_components():
                    self.debuglink.press_yes()
                elif "SwipeContent" in layout.all_components():
                    self.debuglink.swipe_up()
                else:
                    self.debuglink.press_yes()
            else:
                self.debuglink.press_yes()

    def button_request(self, br: messages.ButtonRequest) -> None:
        self.debuglink.snapshot_legacy()

        if self.input_flow is None:
            self._default_input_flow(br)
        elif self.input_flow is self.INPUT_FLOW_DONE:
            raise AssertionError("input flow ended prematurely")
        else:
            try:
                assert isinstance(self.input_flow, t.Generator)
                self.input_flow.send(br)
            except StopIteration:
                self.input_flow = self.INPUT_FLOW_DONE

    def get_pin(self, code: PinMatrixRequestType | None = None) -> str:
        self.debuglink.snapshot_legacy()

        if self.pins is None:
            raise RuntimeError("PIN requested but no sequence was configured")

        try:
            return self.debuglink.encode_pin(next(self.pins))
        except StopIteration:
            raise AssertionError("PIN sequence ended prematurely")

    def get_passphrase(self, available_on_device: bool) -> str:
        self.debuglink.snapshot_legacy()
        return self.passphrase


class MessageFilter:

    def __init__(
        self, message_type: t.Type[protobuf.MessageType], **fields: t.Any
    ) -> None:
        self.message_type = message_type
        self.fields: t.Dict[str, t.Any] = {}
        self.update_fields(**fields)

    def update_fields(self, **fields: t.Any) -> "MessageFilter":
        for name, value in fields.items():
            try:
                self.fields[name] = self.from_message_or_type(value)
            except TypeError:
                self.fields[name] = value

        return self

    @classmethod
    def from_message_or_type(
        cls, message_or_type: "ExpectedMessage"
    ) -> "MessageFilter":
        if isinstance(message_or_type, cls):
            return message_or_type
        if isinstance(message_or_type, protobuf.MessageType):
            return cls.from_message(message_or_type)
        if isinstance(message_or_type, type) and issubclass(
            message_or_type, protobuf.MessageType
        ):
            return cls(message_or_type)
        raise TypeError("Invalid kind of expected response")

    @classmethod
    def from_message(cls, message: protobuf.MessageType) -> "MessageFilter":
        fields = {}
        for field in message.FIELDS.values():
            value = getattr(message, field.name)
            if value in (None, [], protobuf.REQUIRED_FIELD_PLACEHOLDER):
                continue
            fields[field.name] = value
        return cls(type(message), **fields)

    def match(self, message: protobuf.MessageType) -> bool:
        if type(message) is not self.message_type:
            return False

        for field, expected_value in self.fields.items():
            actual_value = getattr(message, field, None)
            if isinstance(expected_value, MessageFilter):
                if actual_value is None or not expected_value.match(actual_value):
                    return False
            elif expected_value != actual_value:
                return False

        return True

    def to_string(self, maxwidth: int = 80) -> str:
        fields: list[t.Tuple[str, str]] = []
        for field in self.message_type.FIELDS.values():
            if field.name not in self.fields:
                continue
            value = self.fields[field.name]
            if isinstance(value, IntEnum):
                field_str = value.name
            elif isinstance(value, MessageFilter):
                field_str = value.to_string(maxwidth - 4)
            elif isinstance(value, protobuf.MessageType):
                field_str = protobuf.format_message(value)
            else:
                field_str = repr(value)
            field_str = textwrap.indent(field_str, "    ").lstrip()
            fields.append((field.name, field_str))

        pairs = [f"{k}={v}" for k, v in fields]
        oneline_str = ", ".join(pairs)
        if len(oneline_str) < maxwidth:
            return f"{self.message_type.__name__}({oneline_str})"
        else:
            item: list[str] = []
            item.append(f"{self.message_type.__name__}(")
            for pair in pairs:
                item.append(f"    {pair}")
            item.append(")")
            return "\n".join(item)


class MessageFilterGenerator:

    def __getattr__(self, key: str) -> t.Callable[..., "MessageFilter"]:
        message_type = getattr(messages, key)
        return MessageFilter(message_type).update_fields


message_filters = MessageFilterGenerator()


class SessionDebugWrapper(Session):
    def __init__(self, session: Session) -> None:
        self._session = session
        self.reset_debug_features()
        if isinstance(session, SessionDebugWrapper):
            raise Exception("Cannot wrap already wrapped session!")

    @property
    def protocol_version(self) -> int:
        return self.client.protocol_version

    @property
    def client(self) -> TrezorClientDebugLink:
        assert isinstance(self._session.client, TrezorClientDebugLink)
        return self._session.client

    @property
    def id(self) -> bytes:
        return self._session.id

    def _write(self, msg: t.Any) -> None:
        print("writing message:", msg.__class__.__name__)
        self._session._write(self._filter_message(msg))

    def _read(self) -> t.Any:
        resp = self._filter_message(self._session._read())
        print("reading message:", resp.__class__.__name__)
        if self.actual_responses is not None:
            self.actual_responses.append(resp)
        return resp

    def set_expected_responses(
        self,
        expected: list["ExpectedMessage" | t.Tuple[bool, "ExpectedMessage"]],
    ) -> None:
        """Set a sequence of expected responses to session calls.

        Within a given with-block, the list of received responses from device must
        match the list of expected responses, otherwise an ``AssertionError`` is raised.

        If an expected response is given a field value other than ``None``, that field value
        must exactly match the received field value. If a given field is ``None``
        (or unspecified) in the expected response, the received field value is not
        checked.

        Each expected response can also be a tuple ``(bool, message)``. In that case, the
        expected response is only evaluated if the first field is ``True``.
        This is useful for differentiating sequences between Trezor models:

        >>> trezor_one = session.features.model == "1"
        >>> session.set_expected_responses([
        >>>     messages.ButtonRequest(code=ConfirmOutput),
        >>>     (trezor_one, messages.ButtonRequest(code=ConfirmOutput)),
        >>>     messages.Success(),
        >>> ])
        """
        if not self.in_with_statement:
            raise RuntimeError("Must be called inside 'with' statement")

        # make sure all items are (bool, message) tuples
        expected_with_validity = (
            e if isinstance(e, tuple) else (True, e) for e in expected
        )

        # only apply those items that are (True, message)
        self.expected_responses = [
            MessageFilter.from_message_or_type(expected)
            for valid, expected in expected_with_validity
            if valid
        ]
        self.actual_responses = []

    def lock(self, *, _refresh_features: bool = True) -> None:
        """Lock the device.

        If the device does not have a PIN configured, this will do nothing.
        Otherwise, a lock screen will be shown and the device will prompt for PIN
        before further actions.

        This call does _not_ invalidate passphrase cache. If passphrase is in use,
        the device will not prompt for it after unlocking.

        To invalidate passphrase cache, use `end_session()`. To lock _and_ invalidate
        passphrase cache, use `clear_session()`.
        """
        # TODO update the documentation above
        # Private argument _refresh_features can be used internally to avoid
        # refreshing in cases where we will refresh soon anyway. This is used
        # in TrezorClient.clear_session()
        self.call(messages.LockDevice())
        if _refresh_features:
            self.refresh_features()

    def cancel(self) -> None:
        self._write(messages.Cancel())

    def ensure_unlocked(self) -> None:
        btc.get_address(self, "Testnet", PASSPHRASE_TEST_PATH)
        self.refresh_features()

    def set_filter(
        self,
        message_type: t.Type[protobuf.MessageType],
        callback: t.Callable[[protobuf.MessageType], protobuf.MessageType] | None,
    ) -> None:
        """Configure a filter function for a specified message type.

        The `callback` must be a function that accepts a protobuf message, and returns
        a (possibly modified) protobuf message of the same type. Whenever a message
        is sent or received that matches `message_type`, `callback` is invoked on the
        message and its result is substituted for the original.

        Useful for test scenarios with an active malicious actor on the wire.
        """
        if not self.in_with_statement:
            raise RuntimeError("Must be called inside 'with' statement")

        self.filters[message_type] = callback

    def _filter_message(self, msg: protobuf.MessageType) -> protobuf.MessageType:
        message_type = msg.__class__
        callback = self.filters.get(message_type)
        if callable(callback):
            return callback(deepcopy(msg))
        else:
            return msg

    def reset_debug_features(self) -> None:
        """Prepare the debugging session for a new testcase.

        Clears all debugging state that might have been modified by a testcase.
        """
        self.in_with_statement = False
        self.expected_responses: list[MessageFilter] | None = None
        self.actual_responses: list[protobuf.MessageType] | None = None
        self.filters: t.Dict[
            t.Type[protobuf.MessageType],
            t.Callable[[protobuf.MessageType], protobuf.MessageType] | None,
        ] = {}
        self.button_callback = self.client.button_callback
        self.pin_callback = self.client.pin_callback
        self.passphrase_callback = self._session.passphrase_callback
        self.passphrase = self._session.passphrase

    def __enter__(self) -> "SessionDebugWrapper":
        # For usage in with/expected_responses
        if self.in_with_statement:
            raise RuntimeError("Do not nest!")
        self.in_with_statement = True
        return self

    def __exit__(self, exc_type: t.Any, value: t.Any, traceback: t.Any) -> None:
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612

        # copy expected/actual responses before clearing them
        expected_responses = self.expected_responses
        actual_responses = self.actual_responses

        # grab a copy of the inputflow generator to raise an exception through it
        if isinstance(self.client.ui, DebugUI):
            input_flow = self.client.ui.input_flow
        else:
            input_flow = None

        self.reset_debug_features()

        if exc_type is None:
            # If no other exception was raised, evaluate missed responses
            # (raises AssertionError on mismatch)
            self._verify_responses(expected_responses, actual_responses)
            if isinstance(input_flow, t.Generator):
                # Ensure that the input flow is exhausted
                try:
                    input_flow.throw(
                        AssertionError("input flow continues past end of test")
                    )
                except StopIteration:
                    pass

        elif isinstance(input_flow, t.Generator):
            # Propagate the exception through the input flow, so that we see in
            # traceback where it is stuck.
            input_flow.throw(exc_type, value, traceback)

    @classmethod
    def _verify_responses(
        cls,
        expected: list[MessageFilter] | None,
        actual: list[protobuf.MessageType] | None,
    ) -> None:
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612

        if expected is None and actual is None:
            return

        assert expected is not None
        assert actual is not None

        for i, (exp, act) in enumerate(zip_longest(expected, actual)):
            if exp is None:
                output = cls._expectation_lines(expected, i)
                output.append("No more messages were expected, but we got:")
                for resp in actual[i:]:
                    output.append(
                        textwrap.indent(protobuf.format_message(resp), "    ")
                    )
                raise AssertionError("\n".join(output))

            if act is None:
                output = cls._expectation_lines(expected, i)
                output.append("This and the following message was not received.")
                raise AssertionError("\n".join(output))

            if not exp.match(act):
                output = cls._expectation_lines(expected, i)
                output.append("Actually received:")
                output.append(textwrap.indent(protobuf.format_message(act), "    "))
                raise AssertionError("\n".join(output))

    @staticmethod
    def _expectation_lines(expected: list[MessageFilter], current: int) -> list[str]:
        start_at = max(current - EXPECTED_RESPONSES_CONTEXT_LINES, 0)
        stop_at = min(current + EXPECTED_RESPONSES_CONTEXT_LINES + 1, len(expected))
        output: list[str] = []
        output.append("Expected responses:")
        if start_at > 0:
            output.append(f"    (...{start_at} previous responses omitted)")
        for i in range(start_at, stop_at):
            exp = expected[i]
            prefix = "    " if i != current else ">>> "
            output.append(textwrap.indent(exp.to_string(), prefix))
        if stop_at < len(expected):
            omitted = len(expected) - stop_at
            output.append(f"    (...{omitted} following responses omitted)")

        output.append("")
        return output


class TrezorClientDebugLink(TrezorClient):
    # This class implements automatic responses
    # and other functionality for unit tests
    # for various callbacks, created in order
    # to automatically pass unit tests.
    #
    # This mixing should be used only for purposes
    # of unit testing, because it will fail to work
    # without special DebugLink interface provided
    # by the device.

    def __init__(self, transport: "Transport", auto_interact: bool = True) -> None:
        try:
            debug_transport = transport.find_debug()
            self.debug = DebugLink(debug_transport, auto_interact)
            # try to open debuglink, see if it works
            self.debug.open()
            self.debug.close()
        except Exception:
            if not auto_interact:
                self.debug = NullDebugLink()
            else:
                raise

        # set transport explicitly so that sync_responses can work
        super().__init__(transport)

        self.transport = transport
        self.ui: DebugUI = DebugUI(self.debug)

        self.reset_debug_features(new_management_session=True)
        self.sync_responses()
        # So that we can choose right screenshotting logic (T1 vs TT)
        # and know the supported debug capabilities
        self.debug.model = self.model
        self.debug.version = self.version
        self.passphrase: str | None = None

    @property
    def layout_type(self) -> LayoutType:
        return self.debug.layout_type

    def get_new_client(self) -> TrezorClientDebugLink:
        return TrezorClientDebugLink(self.transport, self.debug.allow_interactions)

    def reset_debug_features(self, new_management_session: bool = False) -> None:
        """
        Prepare the debugging client for a new testcase.

        Clears all debugging state that might have been modified by a testcase.
        """
        self.ui: DebugUI = DebugUI(self.debug)
        # self.pin_callback = self.ui.debug_callback_button
        self.in_with_statement = False
        self.expected_responses: list[MessageFilter] | None = None
        self.actual_responses: list[protobuf.MessageType] | None = None
        self.filters: t.Dict[
            t.Type[protobuf.MessageType],
            t.Callable[[protobuf.MessageType], protobuf.MessageType] | None,
        ] = {}
        if new_management_session:
            self._management_session = self.get_management_session(new_session=True)

    @property
    def button_callback(self):

        def _callback_button(session: Session, msg: messages.ButtonRequest) -> t.Any:
            __tracebackhide__ = True  # for pytest # pylint: disable=W0612
            # do this raw - send ButtonAck first, notify UI later
            session._write(messages.ButtonAck())
            self.ui.button_request(msg)
            return session._read()

        return _callback_button

    @property
    def pin_callback(self):

        def _callback_pin(session: Session, msg: messages.PinMatrixRequest) -> t.Any:
            try:
                pin = self.ui.get_pin(msg.type)
            except Cancelled:
                session.call_raw(messages.Cancel())
                raise

            if any(d not in "123456789" for d in pin) or not (
                1 <= len(pin) <= MAX_PIN_LENGTH
            ):
                session.call_raw(messages.Cancel())
                raise ValueError("Invalid PIN provided")
            resp = session.call_raw(messages.PinMatrixAck(pin=pin))
            if isinstance(resp, messages.Failure) and resp.code in (
                messages.FailureType.PinInvalid,
                messages.FailureType.PinCancelled,
                messages.FailureType.PinExpected,
            ):
                raise PinException(resp.code, resp.message)
            else:
                return resp

        return _callback_pin

    @property
    def passphrase_callback(self):
        def _callback_passphrase(
            session: Session, msg: messages.PassphraseRequest
        ) -> t.Any:
            available_on_device = (
                Capability.PassphraseEntry in session.features.capabilities
            )

            def send_passphrase(
                passphrase: str | None = None, on_device: bool | None = None
            ) -> t.Any:
                msg = messages.PassphraseAck(passphrase=passphrase, on_device=on_device)
                resp = session.call_raw(msg)
                if isinstance(resp, messages.Deprecated_PassphraseStateRequest):
                    # session.session_id = resp.state
                    resp = session.call_raw(messages.Deprecated_PassphraseStateAck())
                return resp

            # short-circuit old style entry
            if msg._on_device is True:
                return send_passphrase(None, None)

            try:
                if session.passphrase is None and isinstance(session, SessionV1):
                    passphrase = self.ui.get_passphrase(
                        available_on_device=available_on_device
                    )
                else:
                    passphrase = session.passphrase
            except Cancelled:
                session.call_raw(messages.Cancel())
                raise

            if passphrase is PASSPHRASE_ON_DEVICE:
                if not available_on_device:
                    session.call_raw(messages.Cancel())
                    raise RuntimeError("Device is not capable of entering passphrase")
                else:
                    return send_passphrase(on_device=True)

            # else process host-entered passphrase
            if not isinstance(passphrase, str):
                raise RuntimeError("Passphrase must be a str")
            passphrase = Mnemonic.normalize_string(passphrase)
            if len(passphrase) > MAX_PASSPHRASE_LENGTH:
                session.call_raw(messages.Cancel())
                raise ValueError("Passphrase too long")

            return send_passphrase(passphrase, on_device=False)

        return _callback_passphrase

    def ensure_open(self) -> None:
        """Only open session if there isn't already an open one."""
        # if self.session_counter == 0:
        #     self.open()
        # TODO check if is this needed

    def open(self) -> None:
        pass
        # TODO is this needed?
        # self.debug.open()

    def close(self) -> None:
        pass
        # TODO is this needed?
        # self.debug.close()

    def lock(self) -> None:
        s = SessionDebugWrapper(self.get_management_session())
        s.lock()

    def get_session(
        self,
        passphrase: str | object | None = "",
        derive_cardano: bool = False,
    ) -> Session:
        if isinstance(passphrase, str):
            passphrase = Mnemonic.normalize_string(passphrase)
        return super().get_session(passphrase, derive_cardano)

    def set_filter(
        self,
        message_type: t.Type[protobuf.MessageType],
        callback: t.Callable[[protobuf.MessageType], protobuf.MessageType] | None,
    ) -> None:
        """Configure a filter function for a specified message type.

        The `callback` must be a function that accepts a protobuf message, and returns
        a (possibly modified) protobuf message of the same type. Whenever a message
        is sent or received that matches `message_type`, `callback` is invoked on the
        message and its result is substituted for the original.

        Useful for test scenarios with an active malicious actor on the wire.
        """
        if not self.in_with_statement:
            raise RuntimeError("Must be called inside 'with' statement")

        self.filters[message_type] = callback

    def _filter_message(self, msg: protobuf.MessageType) -> protobuf.MessageType:
        message_type = msg.__class__
        callback = self.filters.get(message_type)
        if callable(callback):
            return callback(deepcopy(msg))
        else:
            return msg

    def set_input_flow(
        self,
        input_flow: t.Generator[None, messages.ButtonRequest | None, None],
    ) -> None:
        """Configure a sequence of input events for the current with-block.

        The `input_flow` must be a generator function. A `yield` statement in the
        input flow function waits for a ButtonRequest from the device, and returns
        its code.

        Example usage:

        >>> def input_flow():
        >>>     # wait for first button prompt
        >>>     code = yield
        >>>     assert code == ButtonRequestType.Other
        >>>     # press No
        >>>     client.debug.press_no()
        >>>
        >>>     # wait for second button prompt
        >>>     yield
        >>>     # press Yes
        >>>     client.debug.press_yes()
        >>>
        >>> with client:
        >>>     client.set_input_flow(input_flow)
        >>>     some_call(client)
        """
        if not self.in_with_statement:
            raise RuntimeError("Must be called inside 'with' statement")

        if callable(input_flow):
            input_flow = input_flow()
        if not hasattr(input_flow, "send"):
            raise RuntimeError("input_flow should be a generator function")
        self.ui.input_flow = input_flow
        assert input_flow is not None
        input_flow.send(None)  # start the generator

    def watch_layout(self, watch: bool = True) -> None:
        """Enable or disable watching layout changes.

        Since trezor-core v2.3.2, it is necessary to call `watch_layout()` before
        using `debug.wait_layout()`, otherwise layout changes are not reported.
        """
        if self.version >= (2, 3, 2):
            # version check is necessary because otherwise we cannot reliably detect
            # whether and where to wait for reply:
            # - T1 reports unknown debuglink messages on the wirelink
            # - TT < 2.3.0 does not reply to unknown debuglink messages due to a bug
            self.debug.watch_layout(watch)

    def __enter__(self) -> "TrezorClientDebugLink":
        # For usage in with/expected_responses
        if self.in_with_statement:
            raise RuntimeError("Do not nest!")
        self.in_with_statement = True
        return self

    def __exit__(self, exc_type: t.Any, value: t.Any, traceback: t.Any) -> None:
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612

        # copy expected/actual responses before clearing them
        expected_responses = self.expected_responses
        actual_responses = self.actual_responses

        # grab a copy of the inputflow generator to raise an exception through it
        if isinstance(self.ui, DebugUI):
            input_flow = self.ui.input_flow
        else:
            input_flow = None

        self.reset_debug_features(new_management_session=False)

        if exc_type is None:
            # If no other exception was raised, evaluate missed responses
            # (raises AssertionError on mismatch)
            self._verify_responses(expected_responses, actual_responses)

        elif isinstance(input_flow, t.Generator):
            # Propagate the exception through the input flow, so that we see in
            # traceback where it is stuck.
            input_flow.throw(exc_type, value, traceback)

    def set_expected_responses(
        self,
        expected: list["ExpectedMessage" | t.Tuple[bool, "ExpectedMessage"]],
    ) -> None:
        """Set a sequence of expected responses to client calls.

        Within a given with-block, the list of received responses from device must
        match the list of expected responses, otherwise an AssertionError is raised.

        If an expected response is given a field value other than None, that field value
        must exactly match the received field value. If a given field is None
        (or unspecified) in the expected response, the received field value is not
        checked.

        Each expected response can also be a tuple (bool, message). In that case, the
        expected response is only evaluated if the first field is True.
        This is useful for differentiating sequences between Trezor models:

        >>> trezor_one = client.features.model == "1"
        >>> client.set_expected_responses([
        >>>     messages.ButtonRequest(code=ConfirmOutput),
        >>>     (trezor_one, messages.ButtonRequest(code=ConfirmOutput)),
        >>>     messages.Success(),
        >>> ])
        """
        if not self.in_with_statement:
            raise RuntimeError("Must be called inside 'with' statement")

        # make sure all items are (bool, message) tuples
        expected_with_validity = (
            e if isinstance(e, tuple) else (True, e) for e in expected
        )

        # only apply those items that are (True, message)
        self.expected_responses = [
            MessageFilter.from_message_or_type(expected)
            for valid, expected in expected_with_validity
            if valid
        ]
        self.actual_responses = []

    def use_pin_sequence(self, pins: t.Iterable[str]) -> None:
        """Respond to PIN prompts from device with the provided PINs.
        The sequence must be at least as long as the expected number of PIN prompts.
        """
        self.ui.pins = iter(pins)

    def use_passphrase(self, passphrase: str) -> None:
        """Respond to passphrase prompts from device with the provided passphrase."""
        self.passphrase = passphrase
        self.ui.passphrase = Mnemonic.normalize_string(passphrase)

    def use_mnemonic(self, mnemonic: str) -> None:
        """Use the provided mnemonic to respond to device.
        Only applies to T1, where device prompts the host for mnemonic words."""
        self.mnemonic = Mnemonic.normalize_string(mnemonic).split(" ")

    def _raw_read(self) -> protobuf.MessageType:
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612
        resp = self.get_management_session()._read()
        resp = self._filter_message(resp)
        if self.actual_responses is not None:
            self.actual_responses.append(resp)
        return resp

    def _raw_write(self, msg: protobuf.MessageType) -> None:
        return self.get_management_session()._write(self._filter_message(msg))

    @staticmethod
    def _expectation_lines(expected: list[MessageFilter], current: int) -> list[str]:
        start_at = max(current - EXPECTED_RESPONSES_CONTEXT_LINES, 0)
        stop_at = min(current + EXPECTED_RESPONSES_CONTEXT_LINES + 1, len(expected))
        output: list[str] = []
        output.append("Expected responses:")
        if start_at > 0:
            output.append(f"    (...{start_at} previous responses omitted)")
        for i in range(start_at, stop_at):
            exp = expected[i]
            prefix = "    " if i != current else ">>> "
            output.append(textwrap.indent(exp.to_string(), prefix))
        if stop_at < len(expected):
            omitted = len(expected) - stop_at
            output.append(f"    (...{omitted} following responses omitted)")

        output.append("")
        return output

    @classmethod
    def _verify_responses(
        cls,
        expected: list[MessageFilter] | None,
        actual: list[protobuf.MessageType] | None,
    ) -> None:
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612

        if expected is None and actual is None:
            return

        assert expected is not None
        assert actual is not None

        for i, (exp, act) in enumerate(zip_longest(expected, actual)):
            if exp is None:
                output = cls._expectation_lines(expected, i)
                output.append("No more messages were expected, but we got:")
                for resp in actual[i:]:
                    output.append(
                        textwrap.indent(protobuf.format_message(resp), "    ")
                    )
                raise AssertionError("\n".join(output))

            if act is None:
                output = cls._expectation_lines(expected, i)
                output.append("This and the following message was not received.")
                raise AssertionError("\n".join(output))

            if not exp.match(act):
                output = cls._expectation_lines(expected, i)
                output.append("Actually received:")
                output.append(textwrap.indent(protobuf.format_message(act), "    "))
                raise AssertionError("\n".join(output))

    def sync_responses(self) -> None:
        """Synchronize Trezor device receiving with caller.

        When a failed test does not read out the response, the next caller will write
        a request, but read the previous response -- while the device had already sent
        and placed into queue the new response.

        This function will call `Ping` and read responses until it locates a `Success`
        with the expected text. This means that we are reading up-to-date responses.
        """
        import secrets

        # Start by canceling whatever is on screen. This will work to cancel T1 PIN
        # prompt, which is in TINY mode and does not respond to `Ping`.
        # TODO REMOVE: cancel_msg = mapping.DEFAULT_MAPPING.encode(messages.Cancel())
        self.transport.open()
        try:
            # self.protocol.write(messages.Cancel())
            message = "SYNC" + secrets.token_hex(8)
            self.get_management_session()._write(messages.Ping(message=message))
            resp = None
            while resp != messages.Success(message=message):
                try:
                    resp = self.get_management_session()._read()

                    raise Exception

                except Exception:
                    pass

        finally:
            pass  # TODO fix
            # self.transport.end_session(self.session_id or b"")

    def mnemonic_callback(self, _) -> str:
        word, pos = self.debug.read_recovery_word()
        if word:
            return word
        if pos:
            return self.mnemonic[pos - 1]

        raise RuntimeError("Unexpected call")


@expect(messages.Success, field="message", ret_type=str)
def load_device(
    session: "Session",
    mnemonic: str | t.Iterable[str],
    pin: str | None,
    passphrase_protection: bool,
    label: str | None,
    skip_checksum: bool = False,
    needs_backup: bool = False,
    no_backup: bool = False,
) -> protobuf.MessageType:
    if isinstance(mnemonic, str):
        mnemonic = [mnemonic]

    mnemonics = [Mnemonic.normalize_string(m) for m in mnemonic]

    if session.features.initialized:
        raise RuntimeError(
            "Device is initialized already. Call device.wipe() and try again."
        )

    resp = session.call(
        messages.LoadDevice(
            mnemonics=mnemonics,
            pin=pin,
            passphrase_protection=passphrase_protection,
            label=label,
            skip_checksum=skip_checksum,
            needs_backup=needs_backup,
            no_backup=no_backup,
        )
    )
    session.refresh_features()
    return resp


# keep the old name for compatibility
load_device_by_mnemonic = load_device


@expect(messages.Success, field="message", ret_type=str)
def prodtest_t1(session: "Session") -> protobuf.MessageType:
    if session.features.bootloader_mode is not True:
        raise RuntimeError("Device must be in bootloader mode")

    return session.call(
        messages.ProdTestT1(
            payload=b"\x00\xFF\x55\xAA\x66\x99\x33\xCCABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\x00\xFF\x55\xAA\x66\x99\x33\xCC"
        )
    )


def record_screen(
    debug_client: "TrezorClientDebugLink",
    directory: str | None,
    report_func: t.Callable[[str], None] | None = None,
) -> None:
    """Record screen changes into a specified directory.

    Passing `None` as `directory` stops the recording.

    Creates subdirectories inside a specified directory, one for each session
    (for each new call of this function).
    (So that older screenshots are not overwritten by new ones.)

    Is available only for emulators, hardware devices are not capable of that.
    """

    def get_session_screenshot_dir(directory: Path) -> Path:
        """Create and return screenshot dir for the current session, according to datetime."""
        session_dir = directory / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

    if not _is_emulator(debug_client):
        raise RuntimeError("Recording is only supported on emulator.")

    if directory is None:
        debug_client.debug.stop_recording()
        if report_func is not None:
            report_func("Recording stopped.")
    else:
        # Transforming the directory into an absolute path,
        # because emulator demands it
        abs_directory = Path(directory).resolve()
        # Creating the dir when it does not exist yet
        if not abs_directory.exists():
            abs_directory.mkdir(parents=True, exist_ok=True)
        # Getting a new screenshot dir for the current session
        current_session_dir = get_session_screenshot_dir(abs_directory)
        debug_client.debug.start_recording(str(current_session_dir))
        if report_func is not None:
            report_func(f"Recording started into {current_session_dir}.")


def _is_emulator(debug_client: "TrezorClientDebugLink") -> bool:
    """Check if we are connected to emulator, in contrast to hardware device."""
    return debug_client.features.fw_vendor == "EMULATOR"


@expect(messages.Success, field="message", ret_type=str)
def optiga_set_sec_max(session: "Session") -> protobuf.MessageType:
    return session.call(messages.DebugLinkOptigaSetSecMax())
