from typing import TYPE_CHECKING

from shamir_mnemonic import shamir  # type: ignore

from trezorlib import messages

from .. import buttons

if TYPE_CHECKING:
    from trezorlib.debuglink import DebugLink


def confirm_new_wallet(debug: "DebugLink") -> None:
    layout = debug.read_layout()
    assert layout.title().startswith("CREATE WALLET")
    if debug.model == "T":
        debug.click(buttons.OK)
    elif debug.model == "Safe 3":
        debug.press_right()
        debug.press_right()


def confirm_read(debug: "DebugLink", title: str, middle_r: bool = False) -> None:
    layout = debug.read_layout()
    if title == "Caution":
        assert "Never make a digital copy" in layout.text_content()
    elif title == "Success":
        # TODO: improve this
        assert any(
            text in layout.text_content()
            for text in (
                "success",
                "finished",
                "done",
                "created",
                "Keep it safe",
            )
        )
    elif title == "Checklist":
        assert "number of shares" in layout.text_content().lower()
    else:
        assert title.upper() in layout.title()

    if debug.model == "T":
        debug.click(buttons.OK)
    elif debug.model == "Safe 3":
        if layout.page_count() > 1:
            debug.press_right()
        if middle_r:
            debug.press_middle()
        else:
            debug.press_right()


def set_selection(debug: "DebugLink", button: tuple[int, int], diff: int) -> None:
    if debug.model == "T":
        assert "NumberInputDialog" in debug.read_layout().all_components()
        for _ in range(diff):
            debug.click(button)
        debug.click(buttons.OK)
    elif debug.model == "Safe 3":
        layout = debug.read_layout()
        if layout.title() in ("NUMBER OF SHARES", "THRESHOLD"):
            # Special info screens
            layout = debug.press_right()
        assert "NumberInput" in layout.all_components()
        if button == buttons.RESET_MINUS:
            for _ in range(diff):
                debug.press_left()
        else:
            for _ in range(diff):
                debug.press_right()
        debug.press_middle()


def read_words(
    debug: "DebugLink", backup_type: messages.BackupType, do_htc: bool = True
) -> list[str]:
    words: list[str] = []
    layout = debug.read_layout()

    if debug.model == "T":
        if backup_type == messages.BackupType.Slip39_Advanced:
            assert layout.title().startswith("GROUP")
        elif backup_type == messages.BackupType.Slip39_Basic:
            assert layout.title().startswith("RECOVERY SHARE #")
        else:
            assert layout.title() == "RECOVERY SEED"
    elif debug.model == "Safe 3":
        if backup_type == messages.BackupType.Slip39_Advanced:
            assert "SHARE" in layout.title()
        elif backup_type == messages.BackupType.Slip39_Basic:
            assert layout.title().startswith("SHARE #")
        else:
            assert layout.title() == "STANDARD BACKUP"

        assert "Write down" in layout.text_content()
        layout = debug.press_right()

    # Swiping through all the pages and loading the words
    for _ in range(layout.page_count() - 1):
        words.extend(layout.seed_words())
        layout = debug.swipe_up()
        assert layout is not None
    if debug.model == "T":
        words.extend(layout.seed_words())

    # There is hold-to-confirm button
    if do_htc:
        if debug.model == "T":
            debug.click(buttons.OK, hold_ms=1500)
        elif debug.model == "Safe 3":
            debug.press_right(hold_ms=1200)
    else:
        # It would take a very long time to test 16-of-16 with doing 1500 ms HTC after
        # each word set
        debug.press_yes()

    return words


def confirm_words(debug: "DebugLink", words: list[str]) -> None:
    layout = debug.read_layout()
    if debug.model == "T":
        assert "Select word" in layout.text_content()
        for _ in range(3):
            # "Select word 3 of 20"
            #              ^
            word_pos = int(layout.text_content().split()[2])
            # Unifying both the buttons and words to lowercase
            btn_texts = [
                text.lower() for text in layout.tt_check_seed_button_contents()
            ]
            wanted_word = words[word_pos - 1].lower()
            button_pos = btn_texts.index(wanted_word)
            layout = debug.click(buttons.RESET_WORD_CHECK[button_pos])
    elif debug.model == "Safe 3":
        assert "Select the correct word" in layout.text_content()
        layout = debug.press_right()
        for _ in range(3):
            # "SELECT 2ND WORD"
            #         ^
            word_pos = int(layout.title().split()[1][:-2])
            wanted_word = words[word_pos - 1].lower()

            while not layout.get_middle_choice() == wanted_word:
                layout = debug.press_right()

            layout = debug.press_middle()


def validate_mnemonics(mnemonics: list[str], expected_ems: bytes) -> None:
    # We expect these combinations to recreate the secret properly
    # In case of click tests the mnemonics are always XofX so no need for combinations
    groups = shamir.decode_mnemonics(mnemonics)
    ems = shamir.recover_ems(groups)
    assert expected_ems == ems.ciphertext
