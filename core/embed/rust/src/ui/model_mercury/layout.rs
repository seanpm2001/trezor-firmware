use core::{cmp::Ordering, convert::TryInto};
use heapless::Vec;

use super::{
    component::{
        AddressDetails, Bip39Input, CoinJoinProgress, Frame, FrameMsg, Homescreen, HomescreenMsg,
        Lockscreen, MnemonicInput, MnemonicKeyboard, MnemonicKeyboardMsg, PinKeyboard,
        PinKeyboardMsg, Progress, PromptScreen, SelectWordCount, SelectWordCountMsg, Slip39Input,
        StatusScreen, SwipeUpScreen, SwipeUpScreenMsg, VerticalMenu, VerticalMenuChoiceMsg,
    },
    flow::{self},
    theme,
};
use crate::{
    error::{value_error, Error},
    io::BinaryData,
    micropython::{
        iter::IterBuf,
        macros::{obj_fn_0, obj_fn_1, obj_fn_kw, obj_module},
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
        backlight::BACKLIGHT_LEVELS_OBJ,
        component::{
            base::ComponentExt,
            connect::Connect,
            swipe_detect::SwipeSettings,
            text::{
                op::OpTextLayout,
                paragraphs::{
                    Checklist, Paragraph, ParagraphSource, ParagraphVecLong, ParagraphVecShort,
                    Paragraphs, VecExt,
                },
                TextStyle,
            },
            Border, CachedJpeg, Component, FormattedText, Never, Timeout,
        },
        flow::Swipable,
        geometry::{self, Direction},
        layout::{
            base::LAYOUT_STATE,
            obj::{ComponentMsgObj, LayoutObj, ATTACH_TYPE_OBJ},
            result::{CANCELLED, CONFIRMED, INFO},
            util::{upy_disable_animation, PropsList, RecoveryType},
        },
        model_mercury::{
            component::{check_homescreen_format, SwipeContent},
            flow::{
                new_confirm_action_simple,
                util::{ConfirmBlobParams, ShowInfoParams},
                ConfirmActionExtra, ConfirmActionMenuStrings, ConfirmActionStrings,
            },
            theme::ICON_BULLET_CHECKMARK,
        },
    },
};

const CONFIRM_BLOB_INTRO_MARGIN: usize = 24;

impl TryFrom<SelectWordCountMsg> for Obj {
    type Error = Error;

    fn try_from(value: SelectWordCountMsg) -> Result<Self, Self::Error> {
        match value {
            SelectWordCountMsg::Selected(i) => i.try_into(),
        }
    }
}

impl TryFrom<VerticalMenuChoiceMsg> for Obj {
    type Error = Error;

    fn try_from(value: VerticalMenuChoiceMsg) -> Result<Self, Self::Error> {
        match value {
            VerticalMenuChoiceMsg::Selected(i) => i.try_into(),
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

impl ComponentMsgObj for SelectWordCount {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            SelectWordCountMsg::Selected(n) => n.try_into(),
        }
    }
}

impl ComponentMsgObj for VerticalMenu {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            VerticalMenuChoiceMsg::Selected(i) => i.try_into(),
        }
    }
}

impl ComponentMsgObj for StatusScreen {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        Ok(CONFIRMED.as_obj())
    }
}

impl ComponentMsgObj for PromptScreen {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        Ok(CONFIRMED.as_obj())
    }
}

impl<T: Component + ComponentMsgObj> ComponentMsgObj for SwipeContent<T> {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        self.inner().msg_try_into_obj(msg)
    }
}

impl<T: Component + ComponentMsgObj + Swipable> ComponentMsgObj for SwipeUpScreen<T> {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            SwipeUpScreenMsg::Content(c) => self.inner().msg_try_into_obj(c),
            SwipeUpScreenMsg::Swiped => Ok(CONFIRMED.as_obj()),
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

impl ComponentMsgObj for Lockscreen {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            HomescreenMsg::Dismissed => Ok(CANCELLED.as_obj()),
        }
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

extern "C" fn new_confirm_blob_intro(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let data: Obj = kwargs.get(Qstr::MP_QSTR_data)?;
        let subtitle: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_subtitle)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let verb: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_verb)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let verb_cancel: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_verb_cancel)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;

        ConfirmBlobParams::new(title, data, Some(TR::instructions__view_all_data.into()))
            .with_verb(verb)
            .with_verb_info(Some(TR::buttons__view_all_data.into()))
            .with_description_font(&theme::TEXT_SUB_GREEN_LIME)
            .with_subtitle(subtitle)
            .with_verb_cancel(verb_cancel)
            .with_footer_description(Some(
                TR::buttons__confirm.into(), /* or words__confirm?? */
            ))
            .with_chunkify(chunkify)
            .with_page_limit(Some(1))
            .with_frame_margin(CONFIRM_BLOB_INTRO_MARGIN)
            .into_flow()
            .and_then(LayoutObj::new_root)
            .map(Into::into)
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_set_new_pin(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;

        let flow = flow::confirm_set_new_pin::new_set_new_pin(title, description)?;
        Ok(LayoutObj::new_root(flow)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_output(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: Option<TString> = kwargs.get(Qstr::MP_QSTR_title)?.try_into_option()?;
        let subtitle: Option<TString> = kwargs.get(Qstr::MP_QSTR_subtitle)?.try_into_option()?;

        let account: Option<TString> = kwargs.get(Qstr::MP_QSTR_account)?.try_into_option()?;
        let account_path: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_account_path)?.try_into_option()?;

        let br_name: TString = kwargs.get(Qstr::MP_QSTR_br_name)?.try_into()?;
        let br_code: u16 = kwargs.get(Qstr::MP_QSTR_br_code)?.try_into()?;

        let message: Obj = kwargs.get(Qstr::MP_QSTR_message)?;
        let amount: Option<Obj> = kwargs.get(Qstr::MP_QSTR_amount)?.try_into_option()?;

        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;
        let text_mono: bool = kwargs.get_or(Qstr::MP_QSTR_text_mono, true)?;

        let address: Option<Obj> = kwargs.get(Qstr::MP_QSTR_address)?.try_into_option()?;
        let address_title: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_address_title)?.try_into_option()?;

        let summary_items: Option<Obj> =
            kwargs.get(Qstr::MP_QSTR_summary_items)?.try_into_option()?;
        let fee_items: Option<Obj> = kwargs.get(Qstr::MP_QSTR_fee_items)?.try_into_option()?;

        let summary_title: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_summary_title)?.try_into_option()?;
        let summary_br_name: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_summary_br_name)?
            .try_into_option()?;
        let summary_br_code: Option<u16> = kwargs
            .get(Qstr::MP_QSTR_summary_br_code)?
            .try_into_option()?;

        let address_title = address_title.unwrap_or(TR::words__address.into());
        let cancel_text: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_cancel_text)?.try_into_option()?;

        let main_params = ConfirmBlobParams::new(title.unwrap_or(TString::empty()), message, None)
            .with_subtitle(subtitle)
            .with_menu_button()
            .with_footer(TR::instructions__swipe_up.into(), None)
            .with_chunkify(chunkify)
            .with_text_mono(text_mono)
            .with_swipe_up();

        let content_amount_params = amount.map(|amount| {
            ConfirmBlobParams::new(TR::words__amount.into(), amount, None)
                .with_subtitle(subtitle)
                .with_menu_button()
                .with_footer(TR::instructions__swipe_up.into(), None)
                .with_text_mono(text_mono)
                .with_swipe_up()
                .with_swipe_down()
        });

        let address_params = address.map(|address| {
            ConfirmBlobParams::new(address_title, address, None)
                .with_cancel_button()
                .with_chunkify(true)
                .with_text_mono(true)
                .with_swipe_right()
        });

        let mut fee_items_params =
            ShowInfoParams::new(TR::confirm_total__title_fee.into()).with_cancel_button();
        if fee_items.is_some() {
            for pair in IterBuf::new().try_iterate(fee_items.unwrap())? {
                let [label, value]: [TString; 2] = util::iter_into_array(pair)?;
                fee_items_params = unwrap!(fee_items_params.add(label, value));
            }
        }

        let summary_items_params: Option<ShowInfoParams> = if summary_items.is_some() {
            let mut summary =
                ShowInfoParams::new(summary_title.unwrap_or(TR::words__title_summary.into()))
                    .with_menu_button()
                    .with_footer(TR::instructions__swipe_up.into(), None)
                    .with_swipe_up()
                    .with_swipe_down();
            for pair in IterBuf::new().try_iterate(summary_items.unwrap())? {
                let [label, value]: [TString; 2] = util::iter_into_array(pair)?;
                summary = unwrap!(summary.add(label, value));
            }
            Some(summary)
        } else {
            None
        };

        let flow = flow::confirm_output::new_confirm_output(
            main_params,
            account,
            account_path,
            br_name,
            br_code,
            content_amount_params,
            address_params,
            address_title,
            summary_items_params,
            fee_items_params,
            summary_br_name,
            summary_br_code,
            cancel_text,
        )?;
        Ok(LayoutObj::new_root(flow)?.into())
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
        let extra_title: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_extra_title)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let verb_cancel: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_verb_cancel)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let mut summary_params = ShowInfoParams::new(title.unwrap_or(TString::empty()))
            .with_menu_button()
            .with_footer(TR::instructions__swipe_up.into(), None)
            .with_swipe_up();
        summary_params = unwrap!(summary_params.add(amount_label, amount));
        summary_params = unwrap!(summary_params.add(fee_label, fee));

        // collect available info
        let account_params = if let Some(items) = account_items {
            let mut account_params =
                ShowInfoParams::new(TR::send__send_from.into()).with_cancel_button();
            for pair in IterBuf::new().try_iterate(items)? {
                let [label, value]: [TString; 2] = util::iter_into_array(pair)?;
                account_params = unwrap!(account_params.add(label, value));
            }
            Some(account_params)
        } else {
            None
        };
        let extra_params = if let Some(items) = extra_items {
            let extra_title = extra_title.unwrap_or(TR::buttons__more_info.into());
            let mut extra_params = ShowInfoParams::new(extra_title).with_cancel_button();
            for pair in IterBuf::new().try_iterate(items)? {
                let [label, value]: [TString; 2] = util::iter_into_array(pair)?;
                extra_params = unwrap!(extra_params.add(label, value));
            }
            Some(extra_params)
        } else {
            None
        };

        let flow = flow::new_confirm_summary(
            summary_params,
            account_params,
            extra_params,
            extra_title,
            verb_cancel,
        )?;
        Ok(LayoutObj::new_root(flow)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_get_address(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let description: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_description)?.try_into_option()?;
        let extra: Option<TString> = kwargs.get(Qstr::MP_QSTR_extra)?.try_into_option()?;
        let address: Obj = kwargs.get(Qstr::MP_QSTR_address)?;
        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;
        let address_qr: TString = kwargs.get(Qstr::MP_QSTR_address_qr)?.try_into()?;
        let case_sensitive: bool = kwargs.get(Qstr::MP_QSTR_case_sensitive)?.try_into()?;
        let account: Option<TString> = kwargs.get(Qstr::MP_QSTR_account)?.try_into_option()?;
        let path: Option<TString> = kwargs.get(Qstr::MP_QSTR_path)?.try_into_option()?;
        let xpubs: Obj = kwargs.get(Qstr::MP_QSTR_xpubs)?;
        let br_name: TString = kwargs.get(Qstr::MP_QSTR_br_name)?.try_into()?;
        let br_code: u16 = kwargs.get(Qstr::MP_QSTR_br_code)?.try_into()?;

        let flow = flow::get_address::new_get_address(
            title,
            description,
            extra,
            address,
            chunkify,
            address_qr,
            case_sensitive,
            account,
            path,
            xpubs,
            br_code,
            br_name,
        )?;
        Ok(LayoutObj::new_root(flow)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[no_mangle]
pub static mp_module_trezorui2: Module = obj_module! {
    /// from trezor import utils
    /// from trezorui_api import *
    ///
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorui2.to_obj(),

    /// def confirm_blob_intro(
    ///     *,
    ///     title: str,
    ///     data: str | bytes,
    ///     subtitle: str | None = None,
    ///     verb: str | None = None,
    ///     verb_cancel: str | None = None,
    ///     chunkify: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm byte sequence data by showing only the first page of the data
    ///     and instructing the user to access the menu in order to view all the data,
    ///     which can then be confirmed using confirm_blob."""
    Qstr::MP_QSTR_confirm_blob_intro => obj_fn_kw!(0, new_confirm_blob_intro).as_obj(),

    // TODO: supply more arguments for Wipe code setting when figma done
    /// def flow_confirm_set_new_pin(
    ///     *,
    ///     title: str,
    ///     description: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm new PIN setup with an option to cancel action."""
    Qstr::MP_QSTR_flow_confirm_set_new_pin => obj_fn_kw!(0, new_confirm_set_new_pin).as_obj(),

    /// def flow_get_address(
    ///     *,
    ///     address: str | bytes,
    ///     title: str,
    ///     description: str | None,
    ///     extra: str | None,
    ///     chunkify: bool,
    ///     address_qr: str | None,
    ///     case_sensitive: bool,
    ///     account: str | None,
    ///     path: str | None,
    ///     xpubs: list[tuple[str, str]],
    ///     title_success: str,
    ///     br_code: ButtonRequestType,
    ///     br_name: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Get address / receive funds."""
    Qstr::MP_QSTR_flow_get_address => obj_fn_kw!(0, new_get_address).as_obj(),

    /// def flow_confirm_output(
    ///     *,
    ///     title: str | None,
    ///     subtitle: str | None,
    ///     message: str,
    ///     amount: str | None,
    ///     chunkify: bool,
    ///     text_mono: bool,
    ///     account: str | None,
    ///     account_path: str | None,
    ///     br_code: ButtonRequestType,
    ///     br_name: str,
    ///     address: str | None,
    ///     address_title: str | None,
    ///     summary_items: Iterable[tuple[str, str]] | None = None,
    ///     fee_items: Iterable[tuple[str, str]] | None = None,
    ///     summary_title: str | None = None,
    ///     summary_br_code: ButtonRequestType | None = None,
    ///     summary_br_name: str | None = None,
    ///     cancel_text: str | None = None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm the recipient, (optionally) confirm the amount and (optionally) confirm the summary and present a Hold to Sign page."""
    Qstr::MP_QSTR_flow_confirm_output => obj_fn_kw!(0, new_confirm_output).as_obj(),

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
};
