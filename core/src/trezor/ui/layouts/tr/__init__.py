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


CONFIRMED = trezorui2.CONFIRMED
CANCELLED = trezorui2.CANCELLED
INFO = trezorui2.INFO

BR_TYPE_OTHER = ButtonRequestType.Other  # global_import_cache


if __debug__:
    from trezor.utils import DISABLE_ANIMATION

    trezorui2.disable_animation(bool(DISABLE_ANIMATION))


def draw_simple(layout: Any) -> None:
    # Simple drawing not supported for layouts that set timers.
    def dummy_set_timer(token: int, deadline: int) -> None:
        raise RuntimeError

    layout.attach_timer_fn(dummy_set_timer)
    layout.paint()
    ui.refresh()


# Temporary function, so we know where it is used
# Should be gradually replaced by custom designs/layouts
async def _placeholder_confirm(
    br_type: str,
    title: str,
    data: str | None = None,
    description: str | None = None,
    *,
    verb: str = "CONFIRM",
    verb_cancel: str | None = "",
    hold: bool = False,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Any:
    return await confirm_action(
        br_type,
        title.upper(),
        data,
        description,
        verb=verb,
        verb_cancel=verb_cancel,
        hold=hold,
        reverse=True,
        br_code=br_code,
    )


async def get_bool(
    br_type: str,
    title: str,
    data: str | None = None,
    description: str | None = None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = "",
    hold: bool = False,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> bool:
    result = await interact(
        trezorui2.confirm_action(
            title=title.upper(),
            action=data,
            description=description,
            verb=verb,
            verb_cancel=verb_cancel,
            hold=hold,
        ),
        br_type,
        br_code,
        raise_on_cancel=None,
    )

    return result is CONFIRMED


def confirm_action(
    br_type: str,
    title: str,
    action: str | None = None,
    description: str | None = None,
    description_param: str | None = None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = "",
    hold: bool = False,
    hold_danger: bool = False,
    reverse: bool = False,
    exc: ExceptionType = ActionCancelled,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Awaitable[ui.UiResult]:
    if verb_cancel is not None:
        verb_cancel = verb_cancel.upper()

    if description is not None and description_param is not None:
        description = description.format(description_param)

    return interact(
        trezorui2.confirm_action(
            title=title.upper(),
            action=action,
            description=description,
            verb=verb.upper(),
            verb_cancel=verb_cancel,
            hold=hold,
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
    description_param = description_param or ""
    begin, _separator, end = description.partition("{}")
    await confirm_action(
        br_type,
        title,
        description=begin + description_param + end,
        verb=verb or "CONFIRM",
        br_code=ButtonRequestType.ProtectCall,
    )


async def confirm_reset_device(
    title: str,
    recovery: bool = False,
) -> None:
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


async def prompt_backup() -> bool:
    br_type = "backup_device"
    br_code = ButtonRequestType.ResetDevice

    result = await interact(
        trezorui2.confirm_backup(),
        br_type,
        br_code,
        raise_on_cancel=None,
    )
    if result is CONFIRMED:
        return True

    return await get_bool(
        br_type,
        "SKIP BACKUP",
        description="Are you sure you want to skip the backup?",
        verb="BACK UP",
        verb_cancel="SKIP",
        br_code=br_code,
    )


async def confirm_path_warning(
    path: str,
    path_type: str | None = None,
) -> None:
    if path_type:
        title = f"Unknown {path_type}"
    else:
        title = "Unknown path"
    return await _placeholder_confirm(
        "path_warning",
        title.upper(),
        description=path,
        br_code=ButtonRequestType.UnknownDerivationPath,
    )


async def confirm_homescreen(
    image: bytes,
) -> None:
    await interact(
        trezorui2.confirm_homescreen(
            title="CHANGE HOMESCREEN?",
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
    mismatch_title: str = "ADDRESS MISMATCH?",
    br_type: str = "show_address",
    br_code: ButtonRequestType = ButtonRequestType.Address,
    chunkify: bool = False,
) -> None:
    send_button_request = True
    if title is None:
        # Will be a marquee in case of multisig
        title = (
            "RECEIVE ADDRESS (MULTISIG)"
            if multisig_index is not None
            else "RECEIVE ADDRESS"
        )
    while True:
        result = await interact(
            trezorui2.confirm_address(
                title=title,
                data=address,
                description="",  # unused on TR
                extra=None,  # unused on TR
                chunkify=chunkify,
            ),
            br_type if send_button_request else None,
            br_code,
            raise_on_cancel=None,
        )
        send_button_request = False

        # User confirmed with middle button.
        if result is CONFIRMED:
            break

        # User pressed right button, go to address details.
        elif result is INFO:

            def xpub_title(i: int) -> str:
                # Will be marquee (cannot fit one line)
                result = f"MULTISIG XPUB #{i + 1}"
                result += " (YOURS)" if i == multisig_index else " (COSIGNER)"
                return result

            result = await interact(
                trezorui2.show_address_details(
                    qr_title="",  # unused on this model
                    address=address if address_qr is None else address_qr,
                    case_sensitive=case_sensitive,
                    details_title="",  # unused on this model
                    account=account,
                    path=path,
                    xpubs=[(xpub_title(i), xpub) for i, xpub in enumerate(xpubs)],
                ),
                None,
                raise_on_cancel=None,
            )
            # Can only go back from the address details.
            assert result is CANCELLED

        # User pressed left cancel button, show mismatch dialogue.
        else:
            result = await interact(
                trezorui2.show_mismatch(title=mismatch_title.upper()),
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
    mismatch_title: str = "KEY MISMATCH?",
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


async def _show_modal(
    br_type: str,
    header: str,
    subheader: str | None,
    content: str,
    button_confirm: str | None,
    button_cancel: str | None,
    br_code: ButtonRequestType,
    exc: ExceptionType = ActionCancelled,
) -> None:
    await confirm_action(
        br_type,
        header.upper(),
        subheader,
        content,
        verb=button_confirm or "",
        verb_cancel=button_cancel,
        exc=exc,
        br_code=br_code,
    )


async def show_error_and_raise(
    br_type: str,
    content: str,
    subheader: str | None = None,
    button: str = "TRY AGAIN",
    exc: ExceptionType = ActionCancelled,
) -> NoReturn:
    await show_warning(
        br_type,
        subheader or "",
        content,
        button=button,
        br_code=BR_TYPE_OTHER,
        exc=None,
    )
    # always raise regardless of result
    raise exc


def show_warning(
    br_type: str,
    content: str,
    subheader: str | None = None,
    button: str = "CONTINUE",
    br_code: ButtonRequestType = ButtonRequestType.Warning,
    exc: ExceptionType | None = ActionCancelled,
) -> Awaitable[ui.UiResult]:
    return interact(
        trezorui2.show_warning(  # type: ignore [Argument missing for parameter "title"]
            button=button.upper(),
            warning=content,  # type: ignore [No parameter named "warning"]
            description=subheader or "",
        ),
        br_type,
        br_code,
        raise_on_cancel=exc,
    )


def show_success(
    br_type: str,
    content: str,
    subheader: str | None = None,
    button: str = "Continue",
) -> Awaitable[None]:
    title = "Success"

    # In case only subheader is supplied, showing it
    # in regular font, not bold.
    if not content and subheader:
        content = subheader
        subheader = None

    # Special case for Shamir backup - to show everything just on one page
    # in regular font.
    if "Continue with" in content:
        content = f"{subheader}\n\n{content}"
        subheader = None
        title = ""

    return _show_modal(
        br_type,
        title,
        subheader,
        content,
        button_confirm=button,
        button_cancel=None,
        br_code=ButtonRequestType.Success,
    )


async def confirm_output(
    address: str,
    amount: str,
    title: str = "Confirm sending",
    hold: bool = False,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
    address_label: str | None = None,
    output_index: int | None = None,
    chunkify: bool = False,
) -> None:
    address_title = (
        "RECIPIENT" if output_index is None else f"RECIPIENT #{output_index + 1}"
    )
    amount_title = "AMOUNT" if output_index is None else f"AMOUNT #{output_index + 1}"

    while True:
        await interact(
            trezorui2.confirm_output_address(
                address=address,
                address_label=address_label or "",
                address_title=address_title,
                chunkify=chunkify,
            ),
            "confirm_output",
            br_code,
        )

        try:
            await interact(
                trezorui2.confirm_output_amount(
                    amount_title=amount_title,
                    amount=amount,
                ),
                "confirm_output",
                br_code,
            )
        except ActionCancelled:
            # if the user cancels here, go back to confirm_value
            continue
        else:
            return


def tutorial() -> Awaitable[trezorui2.UiResult]:
    """Showing users how to interact with the device."""
    return interact(trezorui2.tutorial(), "tutorial", BR_TYPE_OTHER)


async def confirm_payment_request(
    recipient_name: str,
    amount: str,
    memos: list[str],
) -> Any:
    memos_str = "\n".join(memos)
    return await _placeholder_confirm(
        "confirm_payment_request",
        "CONFIRM SENDING",
        description=f"{amount} to\n{recipient_name}\n{memos_str}",
        br_code=ButtonRequestType.ConfirmOutput,
    )


async def should_show_more(
    title: str,
    para: Iterable[tuple[int, str]],
    button_text: str = "Show all",
    br_type: str = "should_show_more",
    br_code: ButtonRequestType = BR_TYPE_OTHER,
    confirm: str | bytes | None = None,
    verb_cancel: str | None = None,
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
            verb_cancel=verb_cancel,  # type: ignore [No parameter named "verb_cancel"]
            info_button=button_text.upper(),  # unused on TR
        ),
        br_type,
        br_code,
    )

    if result is CONFIRMED:
        return False
    elif result is INFO:
        return True
    else:
        raise RuntimeError  # ActionCancelled should have been raised by interact()


async def confirm_blob(
    br_type: str,
    title: str,
    data: bytes | str,
    description: str | None = None,
    verb: str = "CONFIRM",
    verb_cancel: str | None = "",  # icon
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
        verb=verb,
        verb_cancel=verb_cancel,
        hold=hold,
        chunkify=chunkify,
    )

    if ask_pagination and layout.page_count() > 1:
        assert not hold
        await _confirm_ask_pagination(
            br_type, title, data, description, verb_cancel, br_code
        )

    else:
        await interact(layout, br_type, br_code)


async def _confirm_ask_pagination(
    br_type: str,
    title: str,
    data: bytes | str,
    description: str,
    verb_cancel: str | None,
    br_code: ButtonRequestType,
) -> None:
    # TODO: make should_show_more/confirm_more accept bytes directly
    if isinstance(data, (bytes, bytearray, memoryview)):
        from ubinascii import hexlify

        data = hexlify(data).decode()

    confirm_more_layout = trezorui2.confirm_more(
        title=title,
        button="GO BACK",
        items=[(ui.BOLD, f"Size: {len(data)} bytes"), (ui.MONO, data)],
    )

    while True:
        if not await should_show_more(
            title,
            para=[(ui.NORMAL, description), (ui.MONO, data)],
            verb_cancel=verb_cancel,
            br_type=br_type,
            br_code=br_code,
        ):
            return

        await interact(confirm_more_layout, br_type, br_code, raise_on_cancel=None)

    assert False


async def confirm_address(
    title: str,
    address: str,
    description: str | None = "Address:",
    br_type: str = "confirm_address",
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Awaitable[None]:
    return confirm_blob(
        br_type,
        title.upper(),
        address,
        description,
        br_code=br_code,
    )


async def confirm_text(
    br_type: str,
    title: str,
    data: str,
    description: str | None = None,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Any:
    return await _placeholder_confirm(
        br_type,
        title,
        data,
        description,
        br_code=br_code,
    )


def confirm_amount(
    title: str,
    amount: str,
    description: str = "Amount:",
    br_type: str = "confirm_amount",
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Awaitable[None]:
    return confirm_blob(
        br_type,
        title.upper(),
        amount,
        description,
        br_code=br_code,
    )


async def confirm_properties(
    br_type: str,
    title: str,
    props: Iterable[PropertyType],
    hold: bool = False,
    br_code: ButtonRequestType = ButtonRequestType.ConfirmOutput,
) -> None:
    from ubinascii import hexlify

    def handle_bytes(prop: PropertyType):
        if isinstance(prop[1], (bytes, bytearray, memoryview)):
            return (prop[0], hexlify(prop[1]).decode(), True)
        else:
            # When there is not space in the text, taking it as data
            # to not include hyphens
            is_data = prop[1] and " " not in prop[1]
            return (prop[0], prop[1], is_data)

    await interact(
        trezorui2.confirm_properties(
            title=title.upper(),
            items=map(handle_bytes, props),  # type: ignore [cannot be assigned to parameter "items"]
            hold=hold,
        ),
        br_type,
        br_code,
    )


def confirm_value(
    title: str,
    value: str,
    description: str,
    br_type: str,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
    *,
    verb: str | None = None,
    hold: bool = False,
) -> Awaitable[None]:
    """General confirmation dialog, used by many other confirm_* functions."""

    if not verb and not hold:
        raise ValueError("Either verb or hold=True must be set")

    if verb:
        verb = verb.upper()

    return interact(
        trezorui2.confirm_value(  # type: ignore [Argument missing for parameter "subtitle"]
            title=title.upper(),
            description=description,
            value=value,
            verb=verb or "HOLD TO CONFIRM",
            hold=hold,
        ),
        br_type,
        br_code,
    )


async def confirm_total(
    total_amount: str,
    fee_amount: str,
    fee_rate_amount: str | None = None,
    title: str = "SENDING",
    total_label: str = "Total amount:",
    fee_label: str = "Including fee:",
    account_label: str | None = None,
    br_type: str = "confirm_total",
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
) -> None:
    await interact(
        # TODO: resolve these differences in TT's and TR's confirm_total
        trezorui2.confirm_total(  # type: ignore [Arguments missing]
            total_amount=total_amount,  # type: ignore [No parameter named]
            fee_amount=fee_amount,  # type: ignore [No parameter named]
            fee_rate_amount=fee_rate_amount,  # type: ignore [No parameter named]
            account_label=account_label,  # type: ignore [No parameter named]
            total_label=total_label,  # type: ignore [No parameter named]
            fee_label=fee_label,  # type: ignore [No parameter named]
        ),
        br_type,
        br_code,
    )


async def confirm_ethereum_tx(
    recipient: str,
    total_amount: str,
    maximum_fee: str,
    items: Iterable[tuple[str, str]],
    br_type: str = "confirm_ethereum_tx",
    br_code: ButtonRequestType = ButtonRequestType.SignTx,
    chunkify: bool = False,
) -> None:
    await interact(
        trezorui2.confirm_ethereum_tx(
            recipient=recipient,
            total_amount=total_amount,
            maximum_fee=maximum_fee,
            items=items,
            chunkify=chunkify,
        ),
        br_type,
        br_code,
    )


async def confirm_joint_total(spending_amount: str, total_amount: str) -> None:
    await interact(
        trezorui2.confirm_joint_total(
            spending_amount=spending_amount,
            total_amount=total_amount,
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
) -> None:
    await _placeholder_confirm(
        br_type,
        title.upper(),
        description=content.format(param),
        hold=hold,
        br_code=br_code,
    )


async def confirm_replacement(description: str, txid: str) -> None:
    await confirm_value(
        description.upper(),
        txid,
        "Transaction ID:",
        "confirm_replacement",
        ButtonRequestType.SignTx,
        verb="CONTINUE",
    )


async def confirm_modify_output(
    address: str,
    sign: int,
    amount_change: str,
    amount_new: str,
) -> None:
    await interact(
        trezorui2.confirm_modify_output(
            address=address,
            sign=sign,
            amount_change=amount_change,
            amount_new=amount_new,
        ),
        "modify_output",
        ButtonRequestType.ConfirmOutput,
    )


async def confirm_modify_fee(
    title: str,
    sign: int,
    user_fee_change: str,
    total_fee_new: str,
    fee_rate_amount: str | None = None,
) -> None:
    await interact(
        trezorui2.confirm_modify_fee(
            title=title,
            sign=sign,
            user_fee_change=user_fee_change,
            total_fee_new=total_fee_new,
            fee_rate_amount=fee_rate_amount,
        ),
        "modify_fee",
        ButtonRequestType.SignTx,
    )


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
    text = ""
    if challenge_visual:
        text += f"{challenge_visual}\n\n"
    text += identity

    await _placeholder_confirm(
        "confirm_sign_identity",
        f"Sign {proto}".upper(),
        text,
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
    br_type = "verify_message" if verify else "sign_message"

    # Allowing to go back from the second screen
    while True:
        await confirm_blob(
            br_type,
            "SIGNING ADDRESS",
            address,
            verb="CONTINUE",
            br_code=BR_TYPE_OTHER,
        )

        try:
            await confirm_blob(
                br_type,
                "CONFIRM MESSAGE",
                message,
                verb_cancel="^",
                br_code=BR_TYPE_OTHER,
                ask_pagination=True,
            )
        except ActionCancelled:
            continue
        else:
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
    if button:
        raise NotImplementedError("Button not implemented")

    description = description.format(description_param)
    if subtitle:
        description = f"{subtitle}\n{description}"
    return trezorui2.show_info(
        title=title,
        description=description,
        time_ms=timeout_ms,
    )


def request_passphrase_on_host() -> None:
    draw_simple(trezorui2.show_passphrase())


async def request_passphrase_on_device(max_len: int) -> str:
    result = await interact(
        trezorui2.request_passphrase(
            prompt="ENTER PASSPHRASE",
            max_len=max_len,
        ),
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
    from trezor import wire

    # Not showing the prompt in case user did not enter it badly yet
    # (has full 16 attempts left)
    if attempts_remaining is None or attempts_remaining == 16:
        subprompt = ""
    elif attempts_remaining == 1:
        subprompt = "Last attempt"
    else:
        subprompt = f"{attempts_remaining} tries left"

    result = await interact(
        trezorui2.request_pin(
            prompt=prompt.upper(),
            subprompt=subprompt,
            allow_cancel=allow_cancel,
            wrong_pin=wrong_pin,
        ),
        "pin_device",
        ButtonRequestType.PinEntry,
        raise_on_cancel=wire.PinCancelled,
    )

    assert isinstance(result, str)
    return result


def confirm_reenter_pin(
    is_wipe_code: bool = False,
) -> Awaitable[ui.UiResult]:
    br_type = "reenter_wipe_code" if is_wipe_code else "reenter_pin"
    title = "CHECK WIPE CODE" if is_wipe_code else "CHECK PIN"
    description = "wipe code" if is_wipe_code else "PIN"
    return confirm_action(
        br_type,
        title,
        description=f"Please re-enter {description} to confirm.",
        verb="CONTINUE",
        verb_cancel=None,
        br_code=BR_TYPE_OTHER,
    )


def confirm_multiple_pages_texts(
    br_type: str,
    title: str,
    items: list[str],
    verb: str,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> Awaitable[ui.UiResult]:
    return interact(
        trezorui2.multiple_pages_texts(
            title=title,
            verb=verb,
            items=items,
        ),
        br_type,
        br_code,
    )


def pin_mismatch_popup(is_wipe_code: bool = False) -> Awaitable[ui.UiResult]:
    description = "wipe codes" if is_wipe_code else "PINs"
    br_code = "wipe_code_mismatch" if is_wipe_code else "pin_mismatch"
    return show_warning(
        br_code,
        f"Entered {description} do not match!",
        "Please check again.",
        "CHECK AGAIN",
        BR_TYPE_OTHER,
    )


def wipe_code_same_as_pin_popup() -> Awaitable[trezorui2.UiResult]:
    return confirm_action(
        "wipe_code_same_as_pin",
        "INVALID WIPE CODE",
        description="The wipe code must be different from your PIN.\nPlease try again.",
        verb="TRY AGAIN",
        verb_cancel=None,
        br_code=BR_TYPE_OTHER,
    )


async def confirm_set_new_pin(
    br_type: str,
    title: str,
    description: str,
    information: str,
    br_code: ButtonRequestType = BR_TYPE_OTHER,
) -> None:
    question = f"Turn on {description} protection?"
    await confirm_multiple_pages_texts(
        br_type,
        title.upper(),
        [question, information],
        "TURN ON",
        br_code,
    )

    # Not showing extra info for wipe code
    if "wipe_code" in br_type:
        return

    # Additional information for the user to know about PIN
    next_info = [
        "PIN should be 4-50 digits long.",
        "Position of the cursor will change between entries for enhanced security.",
    ]
    await confirm_multiple_pages_texts(
        br_type,
        title.upper(),
        next_info,
        "CONTINUE",
        br_code,
    )


def confirm_firmware_update(
    description: str, fingerprint: str
) -> Awaitable[ui.UiResult]:
    return interact(
        trezorui2.confirm_firmware_update(
            description=description, fingerprint=fingerprint
        ),
        "firmware_update",
        BR_TYPE_OTHER,
    )
