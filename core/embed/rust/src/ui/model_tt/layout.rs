use core::{cmp::Ordering, convert::TryInto};

use super::{
    component::{
        AddressDetails, Bip39Input, Button, ButtonMsg, ButtonPage, ButtonStyleSheet,
        CancelConfirmMsg, CancelInfoConfirmMsg, CoinJoinProgress, Dialog, DialogMsg, FidoConfirm,
        FidoMsg, Frame, FrameMsg, Homescreen, HomescreenMsg, IconDialog, Lockscreen, MnemonicInput,
        MnemonicKeyboard, MnemonicKeyboardMsg, NumberInputDialog, NumberInputDialogMsg,
        PassphraseKeyboard, PassphraseKeyboardMsg, PinKeyboard, PinKeyboardMsg, Progress,
        SelectWordCount, SelectWordCountMsg, SelectWordMsg, SetBrightnessDialog, SimplePage,
        Slip39Input,
    },
    theme,
};
use crate::{
    error::{value_error, Error},
    io::BinaryData,
    micropython::{
        gc::Gc,
        iter::IterBuf,
        list::List,
        macros::{obj_fn_1, obj_fn_kw, obj_module},
        map::Map,
        module::Module,
        obj::Obj,
        qstr::Qstr,
        util,
    },
    strutil::TString,
    translations::TR,
    trezorhal::model,
    ui::{
        component::{
            base::ComponentExt,
            connect::Connect,
            image::BlendedImage,
            jpeg::Jpeg,
            paginated::{PageMsg, Paginate},
            placed::GridPlaced,
            text::{
                op::OpTextLayout,
                paragraphs::{
                    Checklist, Paragraph, ParagraphSource, ParagraphVecLong, ParagraphVecShort,
                    Paragraphs, VecExt,
                },
                TextStyle,
            },
            Border, Component, Empty, FormattedText, Label, Never, Timeout,
        },
        geometry,
        layout::{
            obj::{ComponentMsgObj, LayoutObj},
            result::{CANCELLED, CONFIRMED, INFO},
            util::{ConfirmBlob, PropsList, RecoveryType},
        },
        model_tt::component::check_homescreen_format,
    },
};

impl TryFrom<CancelConfirmMsg> for Obj {
    type Error = Error;

    fn try_from(value: CancelConfirmMsg) -> Result<Self, Self::Error> {
        match value {
            CancelConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
            CancelConfirmMsg::Confirmed => Ok(CONFIRMED.as_obj()),
        }
    }
}

impl TryFrom<CancelInfoConfirmMsg> for Obj {
    type Error = Error;

    fn try_from(value: CancelInfoConfirmMsg) -> Result<Self, Self::Error> {
        match value {
            CancelInfoConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
            CancelInfoConfirmMsg::Info => Ok(INFO.as_obj()),
            CancelInfoConfirmMsg::Confirmed => Ok(CONFIRMED.as_obj()),
        }
    }
}

impl TryFrom<SelectWordMsg> for Obj {
    type Error = Error;

    fn try_from(value: SelectWordMsg) -> Result<Self, Self::Error> {
        match value {
            SelectWordMsg::Selected(i) => i.try_into(),
        }
    }
}

impl TryFrom<SelectWordCountMsg> for Obj {
    type Error = Error;

    fn try_from(value: SelectWordCountMsg) -> Result<Self, Self::Error> {
        match value {
            SelectWordCountMsg::Selected(i) => i.try_into(),
        }
    }
}

impl<F, U> ComponentMsgObj for FidoConfirm<F, U>
where
    F: Fn(usize) -> TString<'static>,
    U: Component<Msg = CancelConfirmMsg>,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            FidoMsg::Confirmed(page) => Ok((page as u8).into()),
            FidoMsg::Cancelled => Ok(CANCELLED.as_obj()),
        }
    }
}

impl<T, U> ComponentMsgObj for Dialog<T, U>
where
    T: ComponentMsgObj,
    U: Component,
    <U as Component>::Msg: TryInto<Obj, Error = Error>,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            DialogMsg::Content(c) => Ok(self.inner().msg_try_into_obj(c)?),
            DialogMsg::Controls(msg) => msg.try_into(),
        }
    }
}

impl<U> ComponentMsgObj for IconDialog<U>
where
    U: Component,
    <U as Component>::Msg: TryInto<Obj, Error = Error>,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            DialogMsg::Controls(msg) => msg.try_into(),
            _ => unreachable!(),
        }
    }
}

impl ComponentMsgObj for PinKeyboard<'_> {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            PinKeyboardMsg::Confirmed => self.pin().try_into(),
            PinKeyboardMsg::Cancelled => Ok(CANCELLED.as_obj()),
        }
    }
}

impl ComponentMsgObj for PassphraseKeyboard {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            PassphraseKeyboardMsg::Confirmed => self.passphrase().try_into(),
            PassphraseKeyboardMsg::Cancelled => Ok(CANCELLED.as_obj()),
        }
    }
}

impl<T> ComponentMsgObj for MnemonicKeyboard<T>
where
    T: MnemonicInput,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            MnemonicKeyboardMsg::Confirmed => {
                if let Some(word) = self.mnemonic() {
                    word.try_into()
                } else {
                    fatal_error!("Invalid mnemonic")
                }
            }
            MnemonicKeyboardMsg::Previous => "".try_into(),
        }
    }
}

impl<T> ComponentMsgObj for Frame<T>
where
    T: ComponentMsgObj,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            FrameMsg::Content(c) => self.inner().msg_try_into_obj(c),
            FrameMsg::Button(b) => b.try_into(),
        }
    }
}

impl<T> ComponentMsgObj for ButtonPage<T>
where
    T: Component + Paginate,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            PageMsg::Content(_) => Err(Error::TypeError),
            PageMsg::Confirmed => Ok(CONFIRMED.as_obj()),
            PageMsg::Cancelled => Ok(CANCELLED.as_obj()),
            PageMsg::Info => Ok(INFO.as_obj()),
            PageMsg::SwipeLeft => Ok(INFO.as_obj()),
            PageMsg::SwipeRight => Ok(CANCELLED.as_obj()),
        }
    }
}

// Clippy/compiler complains about conflicting implementations
// TODO move the common impls to a common module
#[cfg(not(feature = "clippy"))]
impl<'a, T> ComponentMsgObj for Paragraphs<T>
where
    T: ParagraphSource<'a>,
{
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!()
    }
}

impl<F> ComponentMsgObj for NumberInputDialog<F>
where
    F: Fn(u32) -> TString<'static>,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        let value = self.value().try_into()?;
        match msg {
            NumberInputDialogMsg::Selected => Ok((CONFIRMED.as_obj(), value).try_into()?),
            NumberInputDialogMsg::InfoRequested => Ok((INFO.as_obj(), value).try_into()?),
        }
    }
}

impl ComponentMsgObj for SetBrightnessDialog {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            CancelConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
            CancelConfirmMsg::Confirmed => Ok(CONFIRMED.as_obj()),
        }
    }
}

impl ComponentMsgObj for Progress {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!()
    }
}

impl ComponentMsgObj for Homescreen {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            HomescreenMsg::Dismissed => Ok(CANCELLED.as_obj()),
        }
    }
}

impl ComponentMsgObj for Lockscreen<'_> {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            HomescreenMsg::Dismissed => Ok(CANCELLED.as_obj()),
        }
    }
}

impl<'a, T> ComponentMsgObj for (GridPlaced<Paragraphs<T>>, GridPlaced<FormattedText>)
where
    T: ParagraphSource<'a>,
{
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!()
    }
}

// Clippy/compiler complains about conflicting implementations
#[cfg(not(feature = "clippy"))]
impl<T> ComponentMsgObj for (Timeout, T)
where
    T: Component<Msg = ()>,
{
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        Ok(CANCELLED.as_obj())
    }
}

impl<T> ComponentMsgObj for SimplePage<T>
where
    T: ComponentMsgObj + Paginate,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            PageMsg::Content(inner_msg) => Ok(self.inner().msg_try_into_obj(inner_msg)?),
            PageMsg::Cancelled => Ok(CANCELLED.as_obj()),
            _ => Err(Error::TypeError),
        }
    }
}

impl ComponentMsgObj for AddressDetails {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        Ok(CANCELLED.as_obj())
    }
}

impl<U> ComponentMsgObj for CoinJoinProgress<U>
where
    U: Component<Msg = Never>,
{
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!();
    }
}

impl ComponentMsgObj for super::component::bl_confirm::Confirm<'_> {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            super::component::bl_confirm::ConfirmMsg::Cancel => Ok(CANCELLED.as_obj()),
            super::component::bl_confirm::ConfirmMsg::Confirm => Ok(CONFIRMED.as_obj()),
        }
    }
}

extern "C" fn new_confirm_emphasized(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let verb: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_verb)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;
        let mut ops = OpTextLayout::new(theme::TEXT_NORMAL);
        for item in IterBuf::new().try_iterate(items)? {
            if item.is_str() {
                ops = ops.text_normal(TString::try_from(item)?)
            } else {
                let [emphasis, text]: [Obj; 2] = util::iter_into_array(item)?;
                let text: TString = text.try_into()?;
                if emphasis.try_into()? {
                    ops = ops.text_demibold(text);
                } else {
                    ops = ops.text_normal(text);
                }
            }
        }

        let obj = LayoutObj::new(Frame::left_aligned(
            theme::label_title(),
            title,
            ButtonPage::new(FormattedText::new(ops).vertically_centered(), theme::BG)
                .with_cancel_confirm(None, verb),
        ))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_address(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let description: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_description)?.try_into_option()?;
        let verb: TString = kwargs.get_or(Qstr::MP_QSTR_verb, TR::buttons__confirm.into())?;
        let extra: Option<TString> = kwargs.get(Qstr::MP_QSTR_extra)?.try_into_option()?;
        let data: Obj = kwargs.get(Qstr::MP_QSTR_data)?;
        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;

        let data_style = if chunkify {
            let address: TString = data.try_into()?;
            theme::get_chunkified_text_style(address.len())
        } else {
            &theme::TEXT_MONO
        };

        let paragraphs = ConfirmBlob {
            description: description.unwrap_or("".into()),
            extra: extra.unwrap_or("".into()),
            data: data.try_into()?,
            description_font: &theme::TEXT_NORMAL,
            extra_font: &theme::TEXT_DEMIBOLD,
            data_font: data_style,
        }
        .into_paragraphs();

        let obj = LayoutObj::new(
            Frame::left_aligned(
                theme::label_title(),
                title,
                ButtonPage::new(paragraphs, theme::BG)
                    .with_swipe_left()
                    .with_cancel_confirm(None, Some(verb)),
            )
            .with_info_button(),
        )?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_properties(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let hold: bool = kwargs.get_or(Qstr::MP_QSTR_hold, false)?;
        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;

        let paragraphs = PropsList::new(
            items,
            &theme::TEXT_NORMAL,
            &theme::TEXT_MONO,
            &theme::TEXT_MONO,
        )?;
        let page = if hold {
            ButtonPage::new(paragraphs.into_paragraphs(), theme::BG).with_hold()?
        } else {
            ButtonPage::new(paragraphs.into_paragraphs(), theme::BG)
                .with_cancel_confirm(None, Some(TR::buttons__confirm.into()))
        };
        let obj = LayoutObj::new(Frame::left_aligned(theme::label_title(), title, page))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_address_details(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let qr_title: TString<'static> = kwargs.get(Qstr::MP_QSTR_qr_title)?.try_into()?;
        let details_title: TString = kwargs.get(Qstr::MP_QSTR_details_title)?.try_into()?;
        let address: TString = kwargs.get(Qstr::MP_QSTR_address)?.try_into()?;
        let case_sensitive: bool = kwargs.get(Qstr::MP_QSTR_case_sensitive)?.try_into()?;
        let account: Option<TString> = kwargs.get(Qstr::MP_QSTR_account)?.try_into_option()?;
        let path: Option<TString> = kwargs.get(Qstr::MP_QSTR_path)?.try_into_option()?;

        let xpubs: Obj = kwargs.get(Qstr::MP_QSTR_xpubs)?;

        let mut ad = AddressDetails::new(
            qr_title,
            address,
            case_sensitive,
            details_title,
            account,
            path,
        )?;

        for i in IterBuf::new().try_iterate(xpubs)? {
            let [xtitle, text]: [TString; 2] = util::iter_into_array(i)?;
            ad.add_xpub(xtitle, text)?;
        }

        let obj =
            LayoutObj::new(SimplePage::horizontal(ad, theme::BG).with_swipe_right_to_go_back())?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_summary(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let amount: TString = kwargs.get(Qstr::MP_QSTR_amount)?.try_into()?;
        let amount_label: TString = kwargs.get(Qstr::MP_QSTR_amount_label)?.try_into()?;
        let fee: TString = kwargs.get(Qstr::MP_QSTR_fee)?.try_into()?;
        let fee_label: TString = kwargs.get(Qstr::MP_QSTR_fee_label)?.try_into()?;
        let title: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_title)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let account_items: Option<Obj> = kwargs
            .get(Qstr::MP_QSTR_account_items)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let extra_items: Option<Obj> = kwargs
            .get(Qstr::MP_QSTR_extra_items)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let _extra_title: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_extra_title)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let verb_cancel: Option<TString<'static>> = kwargs
            .get(Qstr::MP_QSTR_verb_cancel)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let info_button: bool = account_items.is_some() || extra_items.is_some();
        let paragraphs = ParagraphVecShort::from_iter([
            Paragraph::new(&theme::TEXT_NORMAL, amount_label).no_break(),
            Paragraph::new(&theme::TEXT_MONO, amount),
            Paragraph::new(&theme::TEXT_NORMAL, fee_label).no_break(),
            Paragraph::new(&theme::TEXT_MONO, fee),
        ]);

        let mut page = ButtonPage::new(paragraphs.into_paragraphs(), theme::BG)
            .with_hold()?
            .with_cancel_button(verb_cancel);
        if info_button {
            page = page.with_swipe_left();
        }
        let mut frame = Frame::left_aligned(
            theme::label_title(),
            title.unwrap_or(TString::empty()),
            page,
        );
        if info_button {
            frame = frame.with_info_button();
        }
        let obj = LayoutObj::new(frame)?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_more(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let button: TString = kwargs.get(Qstr::MP_QSTR_button)?.try_into()?;
        let button_style_confirm: bool =
            kwargs.get_or(Qstr::MP_QSTR_button_style_confirm, false)?;
        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;

        let mut paragraphs = ParagraphVecLong::new();

        for para in IterBuf::new().try_iterate(items)? {
            let [font, text]: [Obj; 2] = util::iter_into_array(para)?;
            let style: &TextStyle = theme::textstyle_number(font.try_into()?);
            let text: TString = text.try_into()?;
            paragraphs.add(Paragraph::new(style, text));
        }

        let obj = LayoutObj::new(Frame::left_aligned(
            theme::label_title(),
            title,
            ButtonPage::new(paragraphs.into_paragraphs(), theme::BG)
                .with_cancel_confirm(None, Some(button))
                .with_confirm_style(if button_style_confirm {
                    theme::button_confirm()
                } else {
                    theme::button_default()
                })
                .with_back_button(),
        ))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[no_mangle]
pub static mp_module_trezorui2: Module = obj_module! {
    /// from trezor import utils
    /// from trezorui_api import *
    ///

    /// def confirm_emphasized(
    ///     *,
    ///     title: str,
    ///     items: Iterable[str | tuple[bool, str]],
    ///     verb: str | None = None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm formatted text that has been pre-split in python. For tuples
    ///     the first component is a bool indicating whether this part is emphasized."""
    Qstr::MP_QSTR_confirm_emphasized => obj_fn_kw!(0, new_confirm_emphasized).as_obj(),

    /// def confirm_address(
    ///     *,
    ///     title: str,
    ///     data: str | bytes,
    ///     description: str | None,
    ///     verb: str | None = "CONFIRM",
    ///     extra: str | None,
    ///     chunkify: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm address. Similar to `confirm_blob` but has corner info button
    ///     and allows left swipe which does the same thing as the button."""
    Qstr::MP_QSTR_confirm_address => obj_fn_kw!(0, new_confirm_address).as_obj(),

    /// def confirm_properties(
    ///     *,
    ///     title: str,
    ///     items: list[tuple[str | None, str | bytes | None, bool]],
    ///     hold: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm list of key-value pairs. The third component in the tuple should be True if
    ///     the value is to be rendered as binary with monospace font, False otherwise."""
    Qstr::MP_QSTR_confirm_properties => obj_fn_kw!(0, new_confirm_properties).as_obj(),

    /// def show_address_details(
    ///     *,
    ///     qr_title: str,
    ///     address: str,
    ///     case_sensitive: bool,
    ///     details_title: str,
    ///     account: str | None,
    ///     path: str | None,
    ///     xpubs: list[tuple[str, str]],
    /// ) -> LayoutObj[UiResult]:
    ///     """Show address details - QR code, account, path, cosigner xpubs."""
    Qstr::MP_QSTR_show_address_details => obj_fn_kw!(0, new_show_address_details).as_obj(),

    /// def confirm_summary(
    ///     *,
    ///     amount: str,
    ///     amount_label: str,
    ///     fee: str,
    ///     fee_label: str,
    ///     title: str | None = None,
    ///     account_items: Iterable[tuple[str, str]] | None = None,
    ///     extra_items: Iterable[tuple[str, str]] | None = None,
    ///     extra_title: str | None = None,
    ///     verb_cancel: str | None = None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm summary of a transaction."""
    Qstr::MP_QSTR_confirm_summary => obj_fn_kw!(0, new_confirm_summary).as_obj(),

    /// def confirm_more(
    ///     *,
    ///     title: str,
    ///     button: str,
    ///     button_style_confirm: bool = False,
    ///     items: Iterable[tuple[int, str | bytes]],
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm long content with the possibility to go back from any page.
    ///     Meant to be used with confirm_with_info."""
    Qstr::MP_QSTR_confirm_more => obj_fn_kw!(0, new_confirm_more).as_obj(),
};

#[cfg(test)]
mod tests {
    use serde_json;

    use crate::{
        trace::tests::trace,
        ui::{component::text::op::OpTextLayout, geometry::Rect, model_tt::constant},
    };

    use super::*;

    const SCREEN: Rect = constant::screen().inset(theme::borders());

    #[test]
    fn trace_example_layout() {
        let buttons = Button::cancel_confirm(
            Button::with_text("Left".into()),
            Button::with_text("Right".into()),
            false,
        );

        let ops = OpTextLayout::new(theme::TEXT_NORMAL)
            .text_normal("Testing text layout, with some text, and some more text. And ")
            .text_bold_upper("parameters!");
        let formatted = FormattedText::new(ops);
        let mut layout = Dialog::new(formatted, buttons);
        layout.place(SCREEN);

        let expected = serde_json::json!({
            "component": "Dialog",
            "content": {
                "component": "FormattedText",
                "text": ["Testing text layout, with", "\n", "some text, and some", "\n",
                "more text. And ", "parame", "-", "\n", "ters!"],
                "fits": true,
            },
            "controls": {
                "component": "FixedHeightBar",
                "inner": {
                    "component": "Split",
                    "first": {
                        "component": "Button",
                        "text": "Left",
                    },
                    "second": {
                        "component": "Button",
                        "text": "Right",
                    },
                },
            },
        });

        assert_eq!(trace(&layout), expected);
    }
}
