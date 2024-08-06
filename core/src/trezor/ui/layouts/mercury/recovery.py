from typing import Callable, Iterable

import trezorui2
from trezor import TR, ui
from trezor.enums import ButtonRequestType, RecoveryType

from ..common import interact
from . import raise_if_not_confirmed

CONFIRMED = trezorui2.CONFIRMED  # global_import_cache
CANCELLED = trezorui2.CANCELLED  # global_import_cache
INFO = trezorui2.INFO  # global_import_cache


async def _is_confirmed_info(
    dialog: ui.LayoutObj[ui.UiResult],
    info_func: Callable,
    br_name: str,
    br_code: ButtonRequestType,
) -> bool:
    send_button_request = True
    while True:
        result = await interact(
            dialog, br_name if send_button_request else None, br_code
        )

        if result is trezorui2.INFO:
            await info_func()
        else:
            return result is CONFIRMED


async def request_word_count(recovery_type: RecoveryType) -> int:
    selector = trezorui2.select_word_count(recovery_type=recovery_type)
    count = await interact(selector, "word_count", ButtonRequestType.MnemonicWordCount)
    return int(count)


async def request_word(
    word_index: int,
    word_count: int,
    is_slip39: bool,
    send_button_request: bool,
    prefill_word: str = "",
) -> str:
    prompt = TR.recovery__word_x_of_y_template.format(word_index + 1, word_count)
    can_go_back = word_index > 0
    if is_slip39:
        keyboard = trezorui2.request_slip39(
            prompt=prompt, prefill_word=prefill_word, can_go_back=can_go_back
        )
    else:
        keyboard = trezorui2.request_bip39(
            prompt=prompt, prefill_word=prefill_word, can_go_back=can_go_back
        )

    word: str = await interact(
        keyboard,
        "mnemonic" if send_button_request else None,
        ButtonRequestType.MnemonicInput,
    )
    return word


async def show_remaining_shares(
    groups: Iterable[tuple[int, tuple[str, ...]]],  # remaining + list 3 words
    shares_remaining: list[int],
    group_threshold: int,
) -> None:
    from trezor import strings
    from trezor.crypto.slip39 import MAX_SHARE_COUNT

    pages: list[tuple[str, str]] = []
    for remaining, group in groups:
        if 0 < remaining < MAX_SHARE_COUNT:
            title = strings.format_plural(
                TR.recovery__x_more_items_starting_template_plural,
                remaining,
                TR.plurals__x_shares_needed,
            )
            words = "\n".join(group)
            pages.append((title, words))
        elif (
            remaining == MAX_SHARE_COUNT and shares_remaining.count(0) < group_threshold
        ):
            groups_remaining = group_threshold - shares_remaining.count(0)
            title = strings.format_plural(
                TR.recovery__x_more_items_starting_template_plural,
                groups_remaining,
                TR.plurals__x_groups_needed,
            )
            words = "\n".join(group)
            pages.append((title, words))

    await raise_if_not_confirmed(
        trezorui2.show_remaining_shares(pages=pages),
        "show_shares",
        ButtonRequestType.Other,
    )


async def show_group_share_success(share_index: int, group_index: int) -> None:
    await raise_if_not_confirmed(
        trezorui2.show_group_share_success(
            lines=[
                TR.recovery__you_have_entered,
                TR.recovery__share_num_template.format(share_index + 1),
                TR.words__from,
                TR.recovery__group_num_template.format(group_index + 1),
            ],
        ),
        "share_success",
        ButtonRequestType.Other,
    )


async def continue_recovery(
    button_label: str,  # unused on mercury
    text: str,
    subtext: str | None,
    info_func: Callable | None,  # TODO: see below
    recovery_type: RecoveryType,
    show_info: bool = False,
) -> bool:
    if show_info:
        # Show this just one-time
        description = TR.recovery__enter_each_word
    else:
        description = subtext or ""

    homepage = trezorui2.confirm_recovery(
        title=text,
        description=description,
        button=button_label,
        info_button=info_func is not None,
        recovery_type=recovery_type,
    )

    if info_func is not None:
        return await _is_confirmed_info(
            homepage, info_func, "recovery", ButtonRequestType.RecoveryHomepage
        )
    else:
        result = await interact(
            homepage, "recovery", ButtonRequestType.RecoveryHomepage
        )
        return result is CONFIRMED


async def show_recovery_warning(
    br_name: str,
    content: str,
    subheader: str | None = None,
    button: str | None = None,
    br_code: ButtonRequestType = ButtonRequestType.Warning,
) -> None:
    button = button or TR.buttons__try_again  # def_arg
    await raise_if_not_confirmed(
        trezorui2.show_warning(
            title=content or TR.words__warning,
            value=subheader or "",
            button=button,
            description="",
        ),
        br_name,
        br_code,
    )
