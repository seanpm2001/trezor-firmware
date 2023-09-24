from typing import TYPE_CHECKING

import trezorui2
from trezor import ui
from trezor.enums import ButtonRequestType
from trezor.wire import ActionCancelled

from ..common import interact

if TYPE_CHECKING:
    from typing import Any, Awaitable, Iterable, NoReturn, Sequence, TypeVar

    from ..common import ExceptionType, PropertyType

    T = TypeVar("T")


BR_TYPE_OTHER = ButtonRequestType.Other  # global_import_cache

CONFIRMED = trezorui2.CONFIRMED
CANCELLED = trezorui2.CANCELLED
INFO = trezorui2.INFO


if __debug__:
    from trezor.utils import DISABLE_ANIMATION

    trezorui2.disable_animation(bool(DISABLE_ANIMATION))


def draw_simple(layout: Any) -> None:
    # Simple drawing not supported for layouts that set timers.
    def dummy_set_timer(token: int, duration: int) -> None:
        raise RuntimeError

    layout.attach_timer_fn(dummy_set_timer)
    ui.backlight_fade(ui.style.BACKLIGHT_DIM)
    layout.paint()
    ui.refresh()
    ui.backlight_fade(ui.style.BACKLIGHT_NORMAL)


async def confirm_action(
    br_type: str,
    title: str,
    action: str | None = None,
    description: str | None = None,
    description_param: str | None = None,
    verb: str | None = None,
    verb_cancel: str | None = None,
    hold: bool = False,
    hold_danger: bool = False,
    reverse: bool = False,
    exc: ExceptionType = ActionCancelled,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> None:
    if verb is not None:
        verb = verb.upper()
    if verb_cancel is not None:
        verb_cancel = verb_cancel.upper()

    if description is not None and description_param is not None:
        description = description.format(description_param)

    await interact(
        trezorui2.confirm_action(
            title=title.upper(),
            action=action,
            description=description,
            verb=verb,
            verb_cancel=verb_cancel,
            hold=hold,
            hold_danger=hold_danger,
            reverse=reverse,
        ),
        br_type,
        br_code,
        raise_on_cancel=exc,
    )


async def confirm_single(
    br_type: str,
    title: str,
    description: str,
    description_param: str | None = None,
    verb: str | None = None,
) -> None:
    if verb is not None:
        verb = verb.upper()
    description_param = description_param or ""
    begin, _separator, end = description.partition("{}")
    await interact(
        trezorui2.confirm_emphasized(
            title=title.upper(),
            items=(begin, (True, description_param), end),
            verb=verb,
        ),
        br_type,
        ButtonRequestType.ProtectCall,
    )


async def confirm_reset_device(title: str, recovery: bool = False) -> None:
    if recovery:
        button = "RECOVER WALLET"
    else:
        button = "CREATE WALLET"

    await interact(
        trezorui2.confirm_reset_device(
            title=title.upper(),
            button=button,
        ),
        "recover_device" if recovery else "setup_device",
        ButtonRequestType.ProtectCall if recovery else ButtonRequestType.ResetDevice,
    )


# TODO cleanup @ redesign
async def prompt_backup() -> bool:
    result = await interact(
        trezorui2.confirm_action(
            title="SUCCESS",
            action="New wallet created successfully.",
            description="You should back up your new wallet right now.",
            verb="BACK UP",
            verb_cancel="SKIP",
        ),
        "backup_device",
        ButtonRequestType.ResetDevice,
        raise_on_cancel=None,
    )
    if result is CONFIRMED:
        return True

    result = await interact(
        trezorui2.confirm_action(
            title="WARNING",
            action="Are you sure you want to skip the backup?",
            description="You can back up your Trezor once, at any time.",
            verb="BACK UP",
            verb_cancel="SKIP",
        ),
        "backup_device",
        ButtonRequestType.ResetDevice,
        raise_on_cancel=None,
    )
    return result is CONFIRMED


async def confirm_path_warning(
    path: str,
    path_type: str | None = None,
) -> None:
    title = (
        "Wrong derivation path for selected account."
        if not path_type
        else f"Unknown {path_type.lower()}."
    )
    await interact(
        trezorui2.show_warning(
            title=title,
            value=path,
            description="Continue anyway?",
            button="CONTINUE",
        ),
        "path_warning",
        br_code=ButtonRequestType.UnknownDerivationPath,
    )


async def confirm_homescreen(
    image: bytes,
) -> None:
    await interact(
        trezorui2.confirm_homescreen(
            title="CHANGE HOMESCREEN",
            image=image,
        ),
        "set_homesreen",
        ButtonRequestType.ProtectCall,
    )


async def show_address(
    address: str,
    *,
    title: str | None = None,
    address_qr: str | None = None,
    case_sensitive: bool = True,
    path: str | None = None,
    account: str | None = None,
    network: str | None = None,
    multisig_index: int | None = None,
    xpubs: Sequence[str] = (),
    mismatch_title: str = "Address mismatch?",
    details_title: str | None = None,
    br_type: str = "show_address",
    br_code: ButtonRequestType = ButtonRequestType.Address,
    chunkify: bool = False,
) -> None:
    send_button_request = True
    if title is None:
        title = (
            "RECEIVE ADDRESS\n(MULTISIG)"
            if multisig_index is not None
            else "RECEIVE ADDRESS"
        )
        details_title = "RECEIVING TO"
    elif details_title is None:
        details_title = title
    while True:
        result = await interact(
            trezorui2.confirm_address(
                title=title,
                data=address,
                description=network or "",
                extra=None,
                chunkify=chunkify,
            ),
            br_type if send_button_request else None,
            br_code,
            raise_on_cancel=None,
        )
        send_button_request = False

        # User pressed right button.
        if result is CONFIRMED:
            break

        # User pressed corner button or swiped left, go to address details.
        elif result is INFO:

            def xpub_title(i: int) -> str:
                result = f"MULTISIG XPUB #{i + 1}\n"
                result += "(YOURS)" if i == multisig_index else "(COSIGNER)"
                return result

            result = await interact(
                trezorui2.show_address_details(
                    qr_title=title,
                    address=address if address_qr is None else address_qr,
                    case_sensitive=case_sensitive,
                    details_title=details_title,
                    account=account,
                    path=path,
                    xpubs=[(xpub_title(i), xpub) for i, xpub in enumerate(xpubs)],
                ),
                None,
                raise_on_cancel=None,
            )
            assert result is CANCELLED

        else:
            result = await interact(
                trezorui2.show_mismatch(title=mismatch_title),
                None,
                raise_on_cancel=None,
            )
            assert result in (CONFIRMED, CANCELLED)
            # Right button aborts action, left goes back to showing address.
            if result is CONFIRMED:
                raise ActionCancelled


def show_pubkey(
    pubkey: str,
    title: str = "Public key",
    *,
    account: str | None = None,
    path: str | None = None,
    mismatch_title: str = "Key mismatch?",
    br_type="show_pubkey",
) -> Awaitable[None]:
    return show_address(
        address=pubkey,
        title=title.upper(),
        account=account,
        path=path,
        br_type=br_type,
        br_code=ButtonRequestType.PublicKey,
        mismatch_title=mismatch_title,
        chunkify=False,
    )


async def show_error_and_raise(
    br_type: str,
    content: str,
    subheader: str | None = None,
    button: str = "TRY AGAIN",
    exc: ExceptionType = ActionCancelled,
) -> NoReturn:
    await interact(
        trezorui2.show_error(
            title=subheader or "",
            description=content,
            button=button.upper(),
            allow_cancel=False,
        ),
        br_type,
        BR_TYPE_OTHER,
        raise_on_cancel=None,
    )
    # always raise regardless of result
    raise exc


async def show_warning(
    br_type: str,
    content: str,
    subheader: str | None = None,
    button: str = "CONTINUE",
    br_code: ButtonRequestType = ButtonRequestType.Warning,
) -> None:
    await interact(
        trezorui2.show_warning(
            title=content,
            description=subheader or "",
            button=button.upper(),
        ),
        br_type,
        br_code,
    )


def show_success(
    br_type: str,
    content: str,
    subheader: str | None = None,
    button: str = "CONTINUE",
) -> Awaitable[ui.UiResult]:
    return interact(
        trezorui2.show_success(
            title=content,
            description=subheader or "",
            button=button.upper(),
            allow_cancel=False,
        ),
        br_type,
        ButtonRequestType.Success,
    )


async def confirm_output(
    address: str,
    amount: str,
    title: str | None = None,
    hold: bool = False,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
    address_label: str | None = None,
    output_index: int | None = None,
    chunkify: bool = False,
) -> None:
    if title is not None:
        if title.upper().startswith("CONFIRM "):
            title = title[len("CONFIRM ") :]
        amount_title = title.upper()
        recipient_title = title.upper()
    elif output_index is not None:
        amount_title = f"AMOUNT #{output_index + 1}"
        recipient_title = f"RECIPIENT #{output_index + 1}"
    else:
        amount_title = "SENDING AMOUNT"
        recipient_title = "SENDING TO"

    while True:
        # if the user cancels here, raise ActionCancelled (by default)
        await interact(
            trezorui2.confirm_value(
                title=recipient_title,
                subtitle=address_label,
                description=None,
                value=address,
                verb="CONTINUE",
                hold=False,
                info_button=False,
                chunkify=chunkify,
            ),
            "confirm_output",
            br_code,
        )

        try:
            await interact(
                trezorui2.confirm_value(
                    title=amount_title,
                    subtitle=None,
                    description=None,
                    value=amount,
                    verb=None if hold else "CONFIRM",
                    verb_cancel="^",
                    hold=hold,
                    info_button=False,
                ),
                "confirm_output",
                br_code,
            )
        except ActionCancelled:
            # if the user cancels here, go back to confirm_value
            continue
        else:
            return


async def confirm_payment_request(
    recipient_name: str,
    amount: str,
    memos: list[str],
) -> bool:
    result = await interact(
        trezorui2.confirm_with_info(
            title="SENDING",
            items=[(ui.NORMAL, f"{amount} to\n{recipient_name}")]
            + [(ui.NORMAL, memo) for memo in memos],
            button="CONFIRM",
            info_button="DETAILS",
        ),
        "confirm_payment_request",
        ButtonRequestType.ConfirmOutput,
    )

    # When user pressed INFO, returning False, which gets processed in higher function
    # to differentiate it from CONFIRMED. Raising otherwise.
    if result is CONFIRMED:
        return True
    elif result is INFO:
        return False
    else:
        raise ActionCancelled


async def should_show_more(
    title: str,
    para: Iterable[tuple[int, str]],
    button_text: str = "Show all",
    br_type: str = "should_show_more",
    br_code: ButtonRequestType = BR_TYPE_OTHER,
    confirm: str | bytes | None = None,
) -> bool:
    """Return True if the user wants to show more (they click a special button)
    and False when the user wants to continue without showing details.

    Raises ActionCancelled if the user cancels.
    """
    if confirm is None or not isinstance(confirm, str):
        confirm = "CONFIRM"

    result = await interact(
        trezorui2.confirm_with_info(
            title=title.upper(),
            items=para,
            button=confirm.upper(),
            info_button=button_text.upper(),
        ),
        br_type,
        br_code,
    )

    if result is CONFIRMED:
        return False
    elif result is INFO:
        return True
    else:
        raise ActionCancelled


async def _confirm_ask_pagination(
    br_type: str,
    title: str,
    data: bytes | str,
    description: str,
    br_code: ButtonRequestType,
) -> None:
    # TODO: make should_show_more/confirm_more accept bytes directly
    if isinstance(data, (bytes, bytearray, memoryview)):
        from ubinascii import hexlify

        data = hexlify(data).decode()

    confirm_more_layout = trezorui2.confirm_more(
        title=title,
        button="CLOSE",
        items=[(ui.MONO, data)],
    )
    while True:
        if not await should_show_more(
            title,
            para=[(ui.NORMAL, description), (ui.MONO, data)],
            br_type=br_type,
            br_code=br_code,
        ):
            return

        await interact(confirm_more_layout, br_type, br_code, raise_on_cancel=None)

    assert False


async def confirm_blob(
    br_type: str,
    title: str,
    data: bytes | str,
    description: str | None = None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = None,
    hold: bool = False,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
    ask_pagination: bool = False,
    chunkify: bool = False,
) -> None:
    title = title.upper()
    description = description or ""
    layout = trezorui2.confirm_blob(
        title=title,
        description=description,
        data=data,
        extra=None,
        hold=hold,
        verb=verb,
        verb_cancel=verb_cancel,
        chunkify=chunkify,
    )

    if ask_pagination and layout.page_count() > 1:
        assert not hold
        await _confirm_ask_pagination(br_type, title, data, description, br_code)

    else:
        await interact(layout, br_type, br_code)


async def confirm_address(
    title: str,
    address: str,
    description: str | None = "Address:",
    br_type: str = "confirm_address",
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> None:
    await confirm_value(
        title,
        address,
        description or "",
        br_type,
        br_code,
        verb="CONFIRM",
    )


async def confirm_text(
    br_type: str,
    title: str,
    data: str,
    description: str | None = None,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> None:
    await confirm_value(
        title,
        data,
        description or "",
        br_type,
        br_code,
        verb="CONFIRM",
    )


def confirm_amount(
    title: str,
    amount: str,
    description: str = "Amount:",
    br_type: str = "confirm_amount",
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Awaitable[trezorui2.UiResult]:
    return confirm_value(
        title,
        amount,
        description,
        br_type,
        br_code,
        verb="CONFIRM",
    )


def confirm_value(
    title: str,
    value: str,
    description: str,
    br_type: str,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
    *,
    verb: str | None = None,
    subtitle: str | None = None,
    hold: bool = False,
    info_button: bool = False,
) -> Awaitable[trezorui2.UiResult]:
    """General confirmation dialog, used by many other confirm_* functions."""

    if not verb and not hold:
        raise ValueError("Either verb or hold=True must be set")

    if verb:
        verb = verb.upper()

    return interact(
        trezorui2.confirm_value(
            title=title.upper(),
            subtitle=subtitle,
            description=description,
            value=value,
            verb=verb,
            hold=hold,
            info_button=info_button,
        ),
        br_type,
        br_code,
    )


async def confirm_properties(
    br_type: str,
    title: str,
    props: Iterable[PropertyType],
    hold: bool = False,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
) -> None:
    # Monospace flag for values that are bytes.
    items = [(prop[0], prop[1], isinstance(prop[1], bytes)) for prop in props]

    await interact(
        trezorui2.confirm_properties(
            title=title.upper(),
            items=items,
            hold=hold,
        ),
        br_type,
        br_code,
    )


async def confirm_total(
    total_amount: str,
    fee_amount: str,
    fee_rate_amount: str | None = None,
    title: str = "SUMMARY",
    total_label: str = "Total amount:",
    fee_label: str = "Including fee:",
    account_label: str | None = None,
    br_type: str = "confirm_total",
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
) -> None:
    total_layout = trezorui2.confirm_total(
        title=title,
        items=[
            (total_label, total_amount),
            (fee_label, fee_amount),
        ],
        info_button=bool(account_label or fee_rate_amount),
    )
    items: list[tuple[str, str]] = []
    if account_label:
        items.append(("Sending from account:", account_label))
    if fee_rate_amount:
        items.append(("Fee rate:", fee_rate_amount))
    info_layout = trezorui2.show_info_with_cancel(
        title="INFORMATION",
        items=items,
    )

    await with_info(total_layout, info_layout, br_type, br_code)


async def confirm_ethereum_tx(
    recipient: str,
    total_amount: str,
    maximum_fee: str,
    items: Iterable[tuple[str, str]],
    br_type: str = "confirm_ethereum_tx",
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
    chunkify: bool = False,
) -> None:
    total_layout = trezorui2.confirm_total(
        title="SUMMARY",
        items=[
            ("Amount:", total_amount),
            ("Maximum fee:", maximum_fee),
        ],
        info_button=True,
        cancel_arrow=True,
    )
    info_layout = trezorui2.show_info_with_cancel(
        title="FEE INFORMATION",
        items=items,
    )

    while True:
        # Allowing going back and forth between recipient and summary/details
        await confirm_blob(
            br_type,
            "RECIPIENT",
            recipient,
            verb="CONTINUE",
            chunkify=chunkify,
        )

        try:
            await with_info(total_layout, info_layout, br_type, br_code)
            break
        except ActionCancelled:
            continue


async def confirm_joint_total(spending_amount: str, total_amount: str) -> None:
    await interact(
        trezorui2.confirm_total(
            title="JOINT TRANSACTION",
            items=[
                ("You are contributing:", spending_amount),
                ("To the total amount:", total_amount),
            ],
        ),
        "confirm_joint_total",
        ButtonRequestType.SignTx,
    )


async def confirm_metadata(
    br_type: str,
    title: str,
    content: str,
    param: str | None = None,
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
    hold: bool = False,
    verb: str = "CONTINUE",
) -> None:
    await confirm_action(
        br_type,
        title=title.upper(),
        action="",
        description=content,
        description_param=param,
        verb=verb.upper(),
        hold=hold,
        br_code=br_code,
    )


async def confirm_replacement(title: str, txid: str) -> None:
    await confirm_blob(
        title=title.upper(),
        data=txid,
        description="Transaction ID:",
        verb="CONTINUE",
        br_type="confirm_replacement",
        br_code=ButtonRequestType.SignTx,
    )


async def confirm_modify_output(
    address: str,
    sign: int,
    amount_change: str,
    amount_new: str,
) -> None:
    send_button_request = True
    while True:
        # if the user cancels here, raise ActionCancelled (by default)
        await interact(
            trezorui2.confirm_blob(
                title="MODIFY AMOUNT",
                data=address,
                verb="CONTINUE",
                verb_cancel=None,
                description="Address:",
                extra=None,
            ),
            "modify_output" if send_button_request else None,
            ButtonRequestType.ConfirmOutput,
        )

        try:
            await interact(
                trezorui2.confirm_modify_output(
                    address=address,
                    sign=sign,
                    amount_change=amount_change,
                    amount_new=amount_new,
                ),
                "modify_output" if send_button_request else None,
                ButtonRequestType.ConfirmOutput,
            )
        except ActionCancelled:
            # if the user cancels here, go back to confirm_blob
            send_button_request = False
            continue
        else:
            return


async def with_info(
    main_layout: trezorui2.LayoutObj,
    info_layout: trezorui2.LayoutObj,
    br_type: str,
    br_code: ButtonRequestType,
) -> None:
    send_button_request = True

    while True:
        result = await interact(
            main_layout, br_type if send_button_request else None, br_code
        )
        send_button_request = False

        if result is CONFIRMED:
            return
        elif result is INFO:
            await interact(info_layout, None, raise_on_cancel=None)
            continue
        else:
            return result


async def confirm_modify_fee(
    title: str,
    sign: int,
    user_fee_change: str,
    total_fee_new: str,
    fee_rate_amount: str | None = None,
) -> None:
    fee_layout = trezorui2.confirm_modify_fee(
        title=title.upper(),
        sign=sign,
        user_fee_change=user_fee_change,
        total_fee_new=total_fee_new,
        fee_rate_amount=fee_rate_amount,
    )
    items: list[tuple[str, str]] = []
    if fee_rate_amount:
        items.append(("New fee rate:", fee_rate_amount))
    info_layout = trezorui2.show_info_with_cancel(
        title="FEE INFORMATION",
        items=items,
    )
    await with_info(fee_layout, info_layout, "modify_fee", ButtonRequestType.SignTx)


async def confirm_coinjoin(max_rounds: int, max_fee_per_vbyte: str) -> None:
    await interact(
        trezorui2.confirm_coinjoin(
            max_rounds=str(max_rounds),
            max_feerate=max_fee_per_vbyte,
        ),
        "coinjoin_final",
        BR_TYPE_OTHER,
    )


# TODO cleanup @ redesign
async def confirm_sign_identity(
    proto: str, identity: str, challenge_visual: str | None
) -> None:
    await confirm_blob(
        title=f"Sign {proto}",
        data=identity,
        description=challenge_visual + "\n" if challenge_visual else "",
        br_type="sign_identity",
        br_code=BR_TYPE_OTHER,
    )


async def confirm_signverify(
    message: str,
    address: str,
    verify: bool,
    path: str | None = None,
    account: str | None = None,
    chunkify: bool = False,
) -> None:
    if verify:
        address_title = "VERIFY ADDRESS"
        br_type = "verify_message"
    else:
        address_title = "SIGNING ADDRESS"
        br_type = "sign_message"

    address_layout = trezorui2.confirm_address(
        title=address_title,
        data=address,
        description="",
        verb="CONTINUE",
        extra=None,
        chunkify=chunkify,
    )

    items: list[tuple[str, str]] = []
    if account is not None:
        items.append(("Account:", account))
    if path is not None:
        items.append(("Derivation path:", path))
    items.append(("Message size:", f"{len(message)} Bytes"))

    info_layout = trezorui2.show_info_with_cancel(
        title="INFORMATION",
        items=items,
        horizontal=True,
    )

    message_layout = trezorui2.confirm_blob(
        title="CONFIRM MESSAGE",
        description=None,
        data=message,
        extra=None,
        hold=not verify,
        verb="CONFIRM" if verify else None,
    )

    while True:
        try:
            await with_info(address_layout, info_layout, br_type, br_code=BR_TYPE_OTHER)
        except ActionCancelled:
            result = await interact(
                trezorui2.show_mismatch(title="Address mismatch?"),
                None,
                raise_on_cancel=None,
            )
            assert result in (CONFIRMED, CANCELLED)
            # Right button aborts action, left goes back to showing address.
            if result is CONFIRMED:
                raise ActionCancelled
            else:
                continue

        result = await interact(
            message_layout, br_type, BR_TYPE_OTHER, raise_on_cancel=None
        )
        if result is CONFIRMED:
            break


def error_popup(
    title: str,
    description: str,
    subtitle: str | None = None,
    description_param: str = "",
    *,
    button: str = "",
    timeout_ms: int = 0,
) -> trezorui2.LayoutObj[trezorui2.UiResult]:
    if not button and not timeout_ms:
        raise ValueError("Either button or timeout_ms must be set")

    if subtitle:
        title += f"\n{subtitle}"
    return trezorui2.show_error(
        title=title,
        description=description.format(description_param),
        button=button,
        time_ms=timeout_ms,
        allow_cancel=False,
    )


def request_passphrase_on_host() -> None:
    draw_simple(
        trezorui2.show_simple(
            title=None,
            description="Please enter your passphrase.",
        )
    )


async def request_passphrase_on_device(max_len: int) -> str:
    result = await interact(
        trezorui2.request_passphrase(prompt="Enter passphrase", max_len=max_len),
        "passphrase_device",
        ButtonRequestType.PassphraseEntry,
        raise_on_cancel=ActionCancelled("Passphrase entry cancelled"),
    )
    assert isinstance(result, str)
    return result


async def request_pin_on_device(
    prompt: str,
    attempts_remaining: int | None,
    allow_cancel: bool,
    wrong_pin: bool = False,
) -> str:
    from trezor.wire import PinCancelled

    if attempts_remaining is None:
        subprompt = ""
    elif attempts_remaining == 1:
        subprompt = "Last attempt"
    else:
        subprompt = f"{attempts_remaining} tries left"

    result = await interact(
        trezorui2.request_pin(
            prompt=prompt,
            subprompt=subprompt,
            allow_cancel=allow_cancel,
            wrong_pin=wrong_pin,
        ),
        "pin_device",
        ButtonRequestType.PinEntry,
        raise_on_cancel=PinCancelled,
    )
    assert isinstance(result, str)
    return result


async def confirm_reenter_pin(
    is_wipe_code: bool = False,
) -> None:
    """Not supported for TT."""
    pass


async def pin_mismatch_popup(
    is_wipe_code: bool = False,
) -> None:
    title = "Wipe code mismatch" if is_wipe_code else "PIN mismatch"
    description = "wipe codes" if is_wipe_code else "PINs"
    await interact(
        error_popup(
            title,
            f"The {description} you entered do not match.",
            button="TRY AGAIN",
        ),
        "pin_mismatch",
        BR_TYPE_OTHER,
        raise_on_cancel=None,
    )


async def wipe_code_same_as_pin_popup() -> None:
    await interact(
        error_popup(
            "Invalid wipe code",
            "The wipe code must be different from your PIN.",
            button="TRY AGAIN",
        ),
        "wipe_code_same_as_pin",
        BR_TYPE_OTHER,
        raise_on_cancel=None,
    )


async def confirm_set_new_pin(
    br_type: str,
    title: str,
    description: str,
    information: str,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> None:
    await interact(
        trezorui2.confirm_emphasized(
            title=title.upper(),
            items=(
                "Turn on ",
                (True, description),
                " protection?\n\n",
                information,
            ),
            verb="TURN ON",
        ),
        br_type,
        br_code,
    )


async def confirm_firmware_update(description: str, fingerprint: str) -> None:
    await interact(
        trezorui2.confirm_firmware_update(
            description=description, fingerprint=fingerprint
        ),
        "firmware_update",
        BR_TYPE_OTHER,
    )
