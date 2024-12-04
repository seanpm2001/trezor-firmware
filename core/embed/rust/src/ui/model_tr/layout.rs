use core::{cmp::Ordering, convert::TryInto};

use heapless::Vec;

use super::{
    component::{
        AddressDetails, ButtonActions, ButtonDetails, ButtonLayout, ButtonPage, CancelConfirmMsg,
        CancelInfoConfirmMsg, CoinJoinProgress, ConfirmHomescreen, Flow, FlowPages, Frame,
        Homescreen, Lockscreen, NumberInput, Page, PassphraseEntry, PinEntry, Progress,
        ScrollableContent, ScrollableFrame, ShareWords, ShowMore, SimpleChoice, WordlistEntry,
        WordlistType,
    },
    constant, theme,
};
use crate::{
    error::Error,
    maybe_trace::MaybeTrace,
    micropython::{
        gc::Gc,
        iter::IterBuf,
        list::List,
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
        component::{
            base::Component,
            connect::Connect,
            paginated::{PageMsg, Paginate},
            text::{
                op::OpTextLayout,
                paragraphs::{
                    Checklist, Paragraph, ParagraphSource, ParagraphVecLong, ParagraphVecShort,
                    Paragraphs, VecExt,
                },
                TextStyle,
            },
            ComponentExt, FormattedText, Label, LineBreaking, Never, Timeout,
        },
        display::Font,
        geometry,
        layout::{
            obj::{ComponentMsgObj, LayoutObj},
            result::{CANCELLED, CONFIRMED, INFO},
            util::{ConfirmBlob, RecoveryType},
        },
    },
};

impl From<CancelConfirmMsg> for Obj {
    fn from(value: CancelConfirmMsg) -> Self {
        match value {
            CancelConfirmMsg::Cancelled => CANCELLED.as_obj(),
            CancelConfirmMsg::Confirmed => CONFIRMED.as_obj(),
        }
    }
}

impl<T> ComponentMsgObj for ShowMore<T>
where
    T: Component<Msg = Never>,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            CancelInfoConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
            CancelInfoConfirmMsg::Info => Ok(INFO.as_obj()),
            CancelInfoConfirmMsg::Confirmed => Ok(CONFIRMED.as_obj()),
        }
    }
}

impl<'a, T> ComponentMsgObj for Paragraphs<T>
where
    T: ParagraphSource<'a>,
{
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!()
    }
}

impl<T> ComponentMsgObj for ButtonPage<T>
where
    T: Component + Paginate,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            PageMsg::Confirmed => Ok(CONFIRMED.as_obj()),
            PageMsg::Cancelled => Ok(CANCELLED.as_obj()),
            _ => Err(Error::TypeError),
        }
    }
}

impl<F> ComponentMsgObj for Flow<F>
where
    F: Fn(usize) -> Page,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            CancelInfoConfirmMsg::Confirmed => {
                if let Some(index) = self.confirmed_index() {
                    index.try_into()
                } else {
                    Ok(CONFIRMED.as_obj())
                }
            }
            CancelInfoConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
            CancelInfoConfirmMsg::Info => Ok(INFO.as_obj()),
        }
    }
}

impl ComponentMsgObj for PinEntry<'_> {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            CancelConfirmMsg::Confirmed => self.pin().try_into(),
            CancelConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
        }
    }
}

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

impl ComponentMsgObj for CoinJoinProgress {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!();
    }
}

impl ComponentMsgObj for NumberInput {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        (CONFIRMED.as_obj(), msg.try_into()?).try_into()
    }
}

impl ComponentMsgObj for SimpleChoice {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        if self.return_index {
            msg.try_into()
        } else {
            let text = self.result_by_index(msg);
            text.try_into()
        }
    }
}

impl ComponentMsgObj for WordlistEntry {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        msg.try_into()
    }
}

impl ComponentMsgObj for PassphraseEntry {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            CancelConfirmMsg::Confirmed => self.passphrase().try_into(),
            CancelConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
        }
    }
}

impl<T> ComponentMsgObj for Frame<T>
where
    T: ComponentMsgObj,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        self.inner().msg_try_into_obj(msg)
    }
}

impl<T> ComponentMsgObj for ScrollableFrame<T>
where
    T: ComponentMsgObj + ScrollableContent,
{
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        self.inner().msg_try_into_obj(msg)
    }
}

impl ComponentMsgObj for Progress {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        unreachable!()
    }
}

impl ComponentMsgObj for Homescreen {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        Ok(CANCELLED.as_obj())
    }
}

impl<'a> ComponentMsgObj for Lockscreen<'a> {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, Error> {
        Ok(CANCELLED.as_obj())
    }
}

impl ComponentMsgObj for ConfirmHomescreen {
    fn msg_try_into_obj(&self, msg: Self::Msg) -> Result<Obj, Error> {
        match msg {
            CancelConfirmMsg::Confirmed => Ok(CONFIRMED.as_obj()),
            CancelConfirmMsg::Cancelled => Ok(CANCELLED.as_obj()),
        }
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

/// Function to create and call a `ButtonPage` dialog based on paginable content
/// (e.g. `Paragraphs` or `FormattedText`).
/// Has optional title (supply empty `TString` for that) and hold-to-confirm
/// functionality.
fn content_in_button_page<T: Component + Paginate + MaybeTrace + 'static>(
    title: TString<'static>,
    content: T,
    verb: TString<'static>,
    verb_cancel: Option<TString<'static>>,
    hold: bool,
) -> Result<Obj, Error> {
    // Left button - icon, text or nothing.
    let cancel_btn = verb_cancel.map(ButtonDetails::from_text_possible_icon);

    // Right button - text or nothing.
    // Optional HoldToConfirm
    let mut confirm_btn = if !verb.is_empty() {
        Some(ButtonDetails::text(verb))
    } else {
        None
    };
    if hold {
        confirm_btn = confirm_btn.map(|btn| btn.with_default_duration());
    }

    let content = ButtonPage::new(content, theme::BG)
        .with_cancel_btn(cancel_btn)
        .with_confirm_btn(confirm_btn);

    let mut frame = ScrollableFrame::new(content);
    if !title.is_empty() {
        frame = frame.with_title(title);
    }
    let obj = LayoutObj::new(frame)?;

    Ok(obj.into())
}

extern "C" fn new_confirm_joint_total(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let spending_amount: TString = kwargs.get(Qstr::MP_QSTR_spending_amount)?.try_into()?;
        let total_amount: TString = kwargs.get(Qstr::MP_QSTR_total_amount)?.try_into()?;

        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_BOLD, TR::joint__you_are_contributing),
            Paragraph::new(&theme::TEXT_MONO, spending_amount),
            Paragraph::new(&theme::TEXT_BOLD, TR::joint__to_the_total_amount),
            Paragraph::new(&theme::TEXT_MONO, total_amount),
        ]);

        content_in_button_page(
            TR::joint__title.into(),
            paragraphs,
            TR::buttons__hold_to_confirm.into(),
            Some("".into()),
            true,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_output_address(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let address: TString = kwargs.get(Qstr::MP_QSTR_address)?.try_into()?;
        let address_label: TString = kwargs.get(Qstr::MP_QSTR_address_label)?.try_into()?;
        let address_title: TString = kwargs.get(Qstr::MP_QSTR_address_title)?.try_into()?;
        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;

        let get_page = move |page_index| {
            assert!(page_index == 0);
            // RECIPIENT + address
            let btn_layout = ButtonLayout::cancel_none_text(TR::buttons__continue.into());
            let btn_actions = ButtonActions::cancel_none_confirm();
            // Not putting hyphens in the address.
            // Potentially adding address label in different font.
            let mut ops = OpTextLayout::new(theme::TEXT_MONO_DATA);
            if !address_label.is_empty() {
                // NOTE: need to explicitly turn off the chunkification before rendering the
                // address label (for some reason it does not help to turn it off after
                // rendering the chunks)
                if chunkify {
                    ops = ops.chunkify_text(None);
                }
                ops = ops.text_normal(address_label).newline();
            }
            if chunkify {
                // Chunkifying the address into smaller pieces when requested
                ops = ops.chunkify_text(Some((theme::MONO_CHUNKS, 2)));
            }
            ops = ops.text_mono(address);
            let formatted = FormattedText::new(ops).vertically_centered();
            Page::new(btn_layout, btn_actions, formatted).with_title(address_title)
        };
        let pages = FlowPages::new(get_page, 1);

        let obj = LayoutObj::new(Flow::new(pages))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_output_amount(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let amount: TString = kwargs.get(Qstr::MP_QSTR_amount)?.try_into()?;
        let amount_title: TString = kwargs.get(Qstr::MP_QSTR_amount_title)?.try_into()?;

        let get_page = move |page_index| {
            assert!(page_index == 0);
            // AMOUNT + amount
            let btn_layout = ButtonLayout::up_arrow_none_text(TR::buttons__confirm.into());
            let btn_actions = ButtonActions::cancel_none_confirm();
            let ops = OpTextLayout::new(theme::TEXT_MONO).text_mono(amount);
            let formatted = FormattedText::new(ops).vertically_centered();
            Page::new(btn_layout, btn_actions, formatted).with_title(amount_title)
        };
        let pages = FlowPages::new(get_page, 1);

        let obj = LayoutObj::new(Flow::new(pages))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_multiple_pages_texts(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let verb: TString = kwargs.get(Qstr::MP_QSTR_verb)?.try_into()?;
        let items: Gc<List> = kwargs.get(Qstr::MP_QSTR_items)?.try_into()?;

        // Cache the page count so that we can move `items` into the closure.
        let page_count = items.len();

        // Closure to lazy-load the information on given page index.
        // Done like this to allow arbitrarily many pages without
        // the need of any allocation here in Rust.
        let get_page = move |page_index| {
            let item_obj = unwrap!(items.get(page_index));
            let text = unwrap!(TString::try_from(item_obj));

            let (btn_layout, btn_actions) = if page_count == 1 {
                // There is only one page
                (
                    ButtonLayout::cancel_none_text(verb),
                    ButtonActions::cancel_none_confirm(),
                )
            } else if page_index == 0 {
                // First page
                (
                    ButtonLayout::cancel_none_arrow_wide(),
                    ButtonActions::cancel_none_next(),
                )
            } else if page_index == page_count - 1 {
                // Last page
                (
                    ButtonLayout::up_arrow_none_text(verb),
                    ButtonActions::prev_none_confirm(),
                )
            } else {
                // Page in the middle
                (
                    ButtonLayout::up_arrow_none_arrow_wide(),
                    ButtonActions::prev_none_next(),
                )
            };

            let ops = OpTextLayout::new(theme::TEXT_NORMAL).text_normal(text);
            let formatted = FormattedText::new(ops).vertically_centered();

            Page::new(btn_layout, btn_actions, formatted)
        };

        let pages = FlowPages::new(get_page, page_count);
        let obj = LayoutObj::new(Flow::new(pages).with_common_title(title))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[no_mangle]
pub static mp_module_trezorui2: Module = obj_module! {
    /// from trezor import utils
    /// from trezorui_api import *
    ///
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorui2.to_obj(),

    /// def confirm_joint_total(
    ///     *,
    ///     spending_amount: str,
    ///     total_amount: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm total if there are external inputs."""
    Qstr::MP_QSTR_confirm_joint_total => obj_fn_kw!(0, new_confirm_joint_total).as_obj(),

    /// def confirm_output_address(
    ///     *,
    ///     address: str,
    ///     address_label: str,
    ///     address_title: str,
    ///     chunkify: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm output address."""
    Qstr::MP_QSTR_confirm_output_address => obj_fn_kw!(0, new_confirm_output_address).as_obj(),

    /// def confirm_output_amount(
    ///     *,
    ///     amount: str,
    ///     amount_title: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm output amount."""
    Qstr::MP_QSTR_confirm_output_amount => obj_fn_kw!(0, new_confirm_output_amount).as_obj(),

    /// def multiple_pages_texts(
    ///     *,
    ///     title: str,
    ///     verb: str,
    ///     items: list[str],
    /// ) -> LayoutObj[UiResult]:
    ///     """Show multiple texts, each on its own page."""
    Qstr::MP_QSTR_multiple_pages_texts => obj_fn_kw!(0, new_multiple_pages_texts).as_obj(),
};
