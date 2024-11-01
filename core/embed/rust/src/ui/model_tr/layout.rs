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

extern "C" fn new_confirm_blob(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let data: Obj = kwargs.get(Qstr::MP_QSTR_data)?;
        let description: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_description)?.try_into_option()?;
        let extra: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_extra)
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
        let hold: bool = kwargs.get_or(Qstr::MP_QSTR_hold, false)?;
        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;

        let style = if chunkify {
            // Chunkifying the address into smaller pieces when requested
            &theme::TEXT_MONO_ADDRESS_CHUNKS
        } else {
            &theme::TEXT_MONO_DATA
        };

        let paragraphs = ConfirmBlob {
            description: description.unwrap_or("".into()),
            extra: extra.unwrap_or("".into()),
            data: data.try_into()?,
            description_font: &theme::TEXT_BOLD,
            extra_font: &theme::TEXT_NORMAL,
            data_font: style,
        }
        .into_paragraphs();

        content_in_button_page(
            title,
            paragraphs,
            verb.unwrap_or(TR::buttons__confirm.into()),
            verb_cancel,
            hold,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_properties(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let hold: bool = kwargs.get_or(Qstr::MP_QSTR_hold, false)?;
        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;

        let mut paragraphs = ParagraphVecLong::new();

        for para in IterBuf::new().try_iterate(items)? {
            let [key, value, is_data]: [Obj; 3] = util::iter_into_array(para)?;
            let key = key.try_into_option::<TString>()?;
            let value = value.try_into_option::<TString>()?;
            let is_data: bool = is_data.try_into()?;

            if let Some(key) = key {
                if value.is_some() {
                    // Decreasing the margin between key and value (default is 5 px, we use 2 px)
                    // (this enables 4 lines - 2 key:value pairs - on the same screen)
                    paragraphs.add(
                        Paragraph::new(&theme::TEXT_BOLD, key)
                            .no_break()
                            .with_bottom_padding(2),
                    );
                } else {
                    paragraphs.add(Paragraph::new(&theme::TEXT_BOLD, key));
                }
            }
            if let Some(value) = value {
                let style = if is_data {
                    &theme::TEXT_MONO_DATA
                } else {
                    &theme::TEXT_MONO
                };
                paragraphs.add(Paragraph::new(style, value));
            }
        }
        let button_text = if hold {
            TR::buttons__hold_to_confirm.into()
        } else {
            TR::buttons__confirm.into()
        };

        content_in_button_page(
            title,
            paragraphs.into_paragraphs(),
            button_text,
            Some("".into()),
            hold,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_backup(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], _kwargs: &Map| {
        let get_page = move |page_index| match page_index {
            0 => {
                let btn_layout = ButtonLayout::text_none_arrow_wide(TR::buttons__skip.into());
                let btn_actions = ButtonActions::cancel_none_next();
                let ops = OpTextLayout::new(theme::TEXT_NORMAL)
                    .text_normal(TR::backup__new_wallet_created)
                    .newline()
                    .text_normal(TR::backup__it_should_be_backed_up_now);
                let formatted = FormattedText::new(ops).vertically_centered();
                Page::new(btn_layout, btn_actions, formatted)
                    .with_title(TR::words__title_success.into())
            }
            1 => {
                let btn_layout = ButtonLayout::up_arrow_none_text(TR::buttons__back_up.into());
                let btn_actions = ButtonActions::prev_none_confirm();
                let ops =
                    OpTextLayout::new(theme::TEXT_NORMAL).text_normal(TR::backup__recover_anytime);
                let formatted = FormattedText::new(ops).vertically_centered();
                Page::new(btn_layout, btn_actions, formatted)
                    .with_title(TR::backup__title_backup_wallet.into())
            }
            _ => unreachable!(),
        };
        let pages = FlowPages::new(get_page, 2);

        let obj = LayoutObj::new(Flow::new(pages))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_address_details(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let address: TString = kwargs.get(Qstr::MP_QSTR_address)?.try_into()?;
        let case_sensitive: bool = kwargs.get(Qstr::MP_QSTR_case_sensitive)?.try_into()?;
        let account: Option<TString> = kwargs.get(Qstr::MP_QSTR_account)?.try_into_option()?;
        let path: Option<TString> = kwargs.get(Qstr::MP_QSTR_path)?.try_into_option()?;

        let xpubs: Obj = kwargs.get(Qstr::MP_QSTR_xpubs)?;

        let mut ad = AddressDetails::new(address, case_sensitive, account, path)?;

        for i in IterBuf::new().try_iterate(xpubs)? {
            let [xtitle, text]: [TString; 2] = util::iter_into_array(i)?;
            ad.add_xpub(xtitle, text)?;
        }

        let obj = LayoutObj::new(ad)?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_value(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;
        let value: TString = kwargs.get(Qstr::MP_QSTR_value)?.try_into()?;

        let verb: Option<TString<'static>> = kwargs
            .get(Qstr::MP_QSTR_verb)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let hold: bool = kwargs.get_or(Qstr::MP_QSTR_hold, false)?;

        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_BOLD, description),
            Paragraph::new(&theme::TEXT_MONO, value),
        ]);

        content_in_button_page(
            title,
            paragraphs,
            verb.unwrap_or(TR::buttons__confirm.into()),
            Some("".into()),
            hold,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
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

extern "C" fn new_confirm_modify_output(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let sign: i32 = kwargs.get(Qstr::MP_QSTR_sign)?.try_into()?;
        let amount_change: TString = kwargs.get(Qstr::MP_QSTR_amount_change)?.try_into()?;
        let amount_new: TString = kwargs.get(Qstr::MP_QSTR_amount_new)?.try_into()?;

        let description = if sign < 0 {
            TR::modify_amount__decrease_amount
        } else {
            TR::modify_amount__increase_amount
        };

        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_NORMAL, description),
            Paragraph::new(&theme::TEXT_MONO, amount_change).break_after(),
            Paragraph::new(&theme::TEXT_BOLD, TR::modify_amount__new_amount),
            Paragraph::new(&theme::TEXT_MONO, amount_new),
        ]);

        content_in_button_page(
            TR::modify_amount__title.into(),
            paragraphs,
            TR::buttons__confirm.into(),
            Some("".into()),
            false,
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

extern "C" fn new_confirm_summary(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let amount: TString = kwargs.get(Qstr::MP_QSTR_amount)?.try_into()?;
        let amount_label: TString = kwargs.get(Qstr::MP_QSTR_amount_label)?.try_into()?;
        let fee: TString = kwargs.get(Qstr::MP_QSTR_fee)?.try_into()?;
        let fee_label: TString = kwargs.get(Qstr::MP_QSTR_fee_label)?.try_into()?;
        let _title: Option<TString> = kwargs
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
        let verb_cancel: Option<TString<'static>> = kwargs
            .get(Qstr::MP_QSTR_verb_cancel)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        // collect available info pages
        let mut info_pages: Vec<(TString, Obj), 2> = Vec::new();
        if let Some(info) = extra_items {
            // put extra items first as it's typically used for fee info
            let extra_title = extra_title.unwrap_or(TR::words__title_information.into());
            unwrap!(info_pages.push((extra_title, info)));
        }
        if let Some(info) = account_items {
            unwrap!(info_pages.push((TR::confirm_total__title_sending_from.into(), info)));
        }

        // button layouts and actions
        let verb_cancel: TString = verb_cancel.unwrap_or(TString::empty());
        let btns_summary_page = move |has_pages_after: bool| -> (ButtonLayout, ButtonActions) {
            // if there are no info pages, the right button is not needed
            // if verb_cancel is "^", the left button is an arrow pointing up
            let left_btn = Some(ButtonDetails::from_text_possible_icon(verb_cancel));
            let right_btn = has_pages_after.then(|| {
                ButtonDetails::text("i".into())
                    .with_fixed_width(theme::BUTTON_ICON_WIDTH)
                    .with_font(Font::NORMAL)
            });
            let middle_btn = Some(ButtonDetails::armed_text(TR::buttons__confirm.into()));

            (
                ButtonLayout::new(left_btn, middle_btn, right_btn),
                if has_pages_after {
                    ButtonActions::cancel_confirm_next()
                } else {
                    ButtonActions::cancel_confirm_none()
                },
            )
        };
        let btns_info_page = |is_last: bool| -> (ButtonLayout, ButtonActions) {
            // on the last info page, the right button is not needed
            if is_last {
                (
                    ButtonLayout::arrow_none_none(),
                    ButtonActions::prev_none_none(),
                )
            } else {
                (
                    ButtonLayout::arrow_none_arrow(),
                    ButtonActions::prev_none_next(),
                )
            }
        };

        let total_pages = 1 + info_pages.len();
        let get_page = move |page_index| {
            match page_index {
                0 => {
                    // Total amount + fee
                    let (btn_layout, btn_actions) = btns_summary_page(!info_pages.is_empty());

                    let ops = OpTextLayout::new(theme::TEXT_MONO)
                        .text_bold(amount_label)
                        .newline()
                        .text_mono(amount)
                        .newline()
                        .newline()
                        .text_bold(fee_label)
                        .newline()
                        .text_mono(fee);

                    let formatted = FormattedText::new(ops);
                    Page::new(btn_layout, btn_actions, formatted)
                }
                i => {
                    // Other info pages as provided
                    let (title, info_obj) = &info_pages[i - 1];
                    let is_last = i == total_pages - 1;
                    let (btn_layout, btn_actions) = btns_info_page(is_last);

                    let mut ops = OpTextLayout::new(theme::TEXT_MONO);
                    for item in unwrap!(IterBuf::new().try_iterate(*info_obj)) {
                        let [key, value]: [Obj; 2] = unwrap!(util::iter_into_array(item));
                        if !ops.is_empty() {
                            // Each key-value pair is on its own page
                            ops = ops.next_page();
                        }
                        ops = ops
                            .text_bold(unwrap!(TString::try_from(key)))
                            .newline()
                            .text_mono(unwrap!(TString::try_from(value)));
                    }

                    let formatted = FormattedText::new(ops).vertically_centered();
                    Page::new(btn_layout, btn_actions, formatted)
                        .with_slim_arrows()
                        .with_title(*title)
                }
            }
        };
        let pages = FlowPages::new(get_page, total_pages);

        let obj = LayoutObj::new(Flow::new(pages).with_scrollbar(false))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_address(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let address: TString = kwargs.get(Qstr::MP_QSTR_data)?.try_into()?;
        let verb: TString<'static> =
            kwargs.get_or(Qstr::MP_QSTR_verb, TR::buttons__confirm.into())?;
        let chunkify: bool = kwargs.get_or(Qstr::MP_QSTR_chunkify, false)?;

        let get_page = move |page_index| {
            assert!(page_index == 0);

            let btn_layout = ButtonLayout::cancel_armed_info(verb);
            let btn_actions = ButtonActions::cancel_confirm_info();
            let style = if chunkify {
                // Chunkifying the address into smaller pieces when requested
                theme::TEXT_MONO_ADDRESS_CHUNKS
            } else {
                theme::TEXT_MONO_DATA
            };
            let ops = OpTextLayout::new(style).text_mono(address);
            let formatted = FormattedText::new(ops).vertically_centered();
            Page::new(btn_layout, btn_actions, formatted).with_title(title)
        };
        let pages = FlowPages::new(get_page, 1);

        let obj = LayoutObj::new(Flow::new(pages))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_modify_fee(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let sign: i32 = kwargs.get(Qstr::MP_QSTR_sign)?.try_into()?;
        let user_fee_change: TString = kwargs.get(Qstr::MP_QSTR_user_fee_change)?.try_into()?;
        let total_fee_new: TString = kwargs.get(Qstr::MP_QSTR_total_fee_new)?.try_into()?;
        let fee_rate_amount: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_fee_rate_amount)?
            .try_into_option()?;

        let (description, change) = match sign {
            s if s < 0 => (TR::modify_fee__decrease_fee, user_fee_change),
            s if s > 0 => (TR::modify_fee__increase_fee, user_fee_change),
            _ => (TR::modify_fee__no_change, "".into()),
        };

        let mut paragraphs_vec = ParagraphVecShort::new();
        paragraphs_vec
            .add(Paragraph::new(&theme::TEXT_BOLD, description))
            .add(Paragraph::new(&theme::TEXT_MONO, change))
            .add(Paragraph::new(&theme::TEXT_BOLD, TR::modify_fee__transaction_fee).no_break())
            .add(Paragraph::new(&theme::TEXT_MONO, total_fee_new));

        if let Some(fee_rate_amount) = fee_rate_amount {
            paragraphs_vec
                .add(Paragraph::new(&theme::TEXT_BOLD, TR::modify_fee__fee_rate).no_break())
                .add(Paragraph::new(&theme::TEXT_MONO, fee_rate_amount));
        }

        content_in_button_page(
            TR::modify_fee__title.into(),
            paragraphs_vec.into_paragraphs(),
            TR::buttons__confirm.into(),
            Some("".into()),
            false,
        )
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

extern "C" fn new_confirm_fido(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let app_name: TString = kwargs.get(Qstr::MP_QSTR_app_name)?.try_into()?;
        let accounts: Gc<List> = kwargs.get(Qstr::MP_QSTR_accounts)?.try_into()?;

        // Cache the page count so that we can move `accounts` into the closure.
        let page_count = accounts.len();

        // Closure to lazy-load the information on given page index.
        // Done like this to allow arbitrarily many pages without
        // the need of any allocation here in Rust.
        let get_page = move |page_index| {
            let account_obj = unwrap!(accounts.get(page_index));
            let account = TString::try_from(account_obj).unwrap_or_else(|_| TString::empty());

            let (btn_layout, btn_actions) = if page_count == 1 {
                // There is only one page
                (
                    ButtonLayout::cancel_none_text(TR::buttons__confirm.into()),
                    ButtonActions::cancel_none_confirm(),
                )
            } else if page_index == 0 {
                // First page
                (
                    ButtonLayout::cancel_armed_arrow(TR::buttons__select.into()),
                    ButtonActions::cancel_confirm_next(),
                )
            } else if page_index == page_count - 1 {
                // Last page
                (
                    ButtonLayout::arrow_armed_none(TR::buttons__select.into()),
                    ButtonActions::prev_confirm_none(),
                )
            } else {
                // Page in the middle
                (
                    ButtonLayout::arrow_armed_arrow(TR::buttons__select.into()),
                    ButtonActions::prev_confirm_next(),
                )
            };

            let ops = OpTextLayout::new(theme::TEXT_NORMAL)
                .newline()
                .text_normal(app_name)
                .newline()
                .text_bold(account);
            let formatted = FormattedText::new(ops);

            Page::new(btn_layout, btn_actions, formatted)
        };

        let pages = FlowPages::new(get_page, page_count);
        // Returning the page index in case of confirmation.
        let obj = LayoutObj::new(
            Flow::new(pages)
                .with_common_title(title)
                .with_return_confirmed_index(),
        )?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_warning(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let button: TString<'static> = kwargs.get(Qstr::MP_QSTR_button)?.try_into()?;
        let warning: TString = kwargs.get(Qstr::MP_QSTR_warning)?.try_into()?;
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;

        let get_page = move |page_index| {
            assert!(page_index == 0);

            let btn_layout = ButtonLayout::none_armed_none(button);
            let btn_actions = ButtonActions::none_confirm_none();
            let mut ops = OpTextLayout::new(theme::TEXT_NORMAL);
            ops = ops.alignment(geometry::Alignment::Center);
            if !warning.is_empty() {
                ops = ops.text_bold_upper(warning);
                if !description.is_empty() {
                    ops = ops.newline();
                }
            }
            if !description.is_empty() {
                ops = ops.text_normal(description);
            }
            let formatted = FormattedText::new(ops).vertically_centered();
            Page::new(btn_layout, btn_actions, formatted)
        };
        let pages = FlowPages::new(get_page, 1);
        let obj = LayoutObj::new(Flow::new(pages))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_passphrase() -> Obj {
    let block = move || {
        let text: TString = TR::passphrase__please_enter.into();
        let paragraph = Paragraph::new(&theme::TEXT_NORMAL, text).centered();
        let content = Paragraphs::new([paragraph]);
        let obj = LayoutObj::new(content)?;
        Ok(obj.into())
    };
    unsafe { util::try_or_raise(block) }
}

extern "C" fn new_show_waiting_text(message: Obj) -> Obj {
    let block = || {
        let text: TString = message.try_into()?;
        let paragraph = Paragraph::new(&theme::TEXT_NORMAL, text).centered();
        let content = Paragraphs::new([paragraph]);
        let obj = LayoutObj::new(content)?;
        Ok(obj.into())
    };
    unsafe { util::try_or_raise(block) }
}

extern "C" fn new_confirm_with_info(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let button: TString<'static> = kwargs.get(Qstr::MP_QSTR_button)?.try_into()?;
        let verb_cancel: Option<TString<'static>> = kwargs
            .get(Qstr::MP_QSTR_verb_cancel)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;

        let mut paragraphs = ParagraphVecShort::new();

        for para in IterBuf::new().try_iterate(items)? {
            let [font, text]: [Obj; 2] = util::iter_into_array(para)?;
            let style: &TextStyle = theme::textstyle_number(font.try_into()?);
            let text: TString = text.try_into()?;
            paragraphs.add(Paragraph::new(style, text));
            if paragraphs.is_full() {
                break;
            }
        }

        let obj = LayoutObj::new(Frame::new(
            title,
            ShowMore::<Paragraphs<ParagraphVecShort>>::new(
                paragraphs.into_paragraphs(),
                verb_cancel,
                button,
            ),
        ))?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_more(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let button: TString<'static> = kwargs.get(Qstr::MP_QSTR_button)?.try_into()?;
        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;

        let mut paragraphs = ParagraphVecLong::new();

        for para in IterBuf::new().try_iterate(items)? {
            let [font, text]: [Obj; 2] = util::iter_into_array(para)?;
            let style: &TextStyle = theme::textstyle_number(font.try_into()?);
            let text: TString = text.try_into()?;
            paragraphs.add(Paragraph::new(style, text));
        }

        content_in_button_page(
            title,
            paragraphs.into_paragraphs(),
            button,
            Some("<".into()),
            false,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_coinjoin(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let max_rounds: TString = kwargs.get(Qstr::MP_QSTR_max_rounds)?.try_into()?;
        let max_feerate: TString = kwargs.get(Qstr::MP_QSTR_max_feerate)?.try_into()?;

        // Decreasing bottom padding between paragraphs to fit one screen
        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_BOLD, TR::coinjoin__max_rounds).with_bottom_padding(2),
            Paragraph::new(&theme::TEXT_MONO, max_rounds),
            Paragraph::new(&theme::TEXT_BOLD, TR::coinjoin__max_mining_fee)
                .with_bottom_padding(2)
                .no_break(),
            Paragraph::new(&theme::TEXT_MONO, max_feerate).with_bottom_padding(2),
        ]);

        content_in_button_page(
            TR::coinjoin__title.into(),
            paragraphs,
            TR::buttons__hold_to_confirm.into(),
            None,
            true,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_share_words(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let share_words_obj: Obj = kwargs.get(Qstr::MP_QSTR_share_words)?;
        let share_words: Vec<TString, 33> = util::iter_into_vec(share_words_obj)?;

        let cancel_btn = Some(ButtonDetails::up_arrow_icon());
        let confirm_btn =
            Some(ButtonDetails::text(TR::buttons__hold_to_confirm.into()).with_default_duration());

        let obj = LayoutObj::new(
            ButtonPage::new(ShareWords::new(share_words), theme::BG)
                .with_cancel_btn(cancel_btn)
                .with_confirm_btn(confirm_btn),
        )?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_recovery(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;
        let button: TString<'static> = kwargs.get(Qstr::MP_QSTR_button)?.try_into()?;
        let recovery_type: RecoveryType = kwargs.get(Qstr::MP_QSTR_recovery_type)?.try_into()?;
        let show_instructions: bool = kwargs.get(Qstr::MP_QSTR_show_instructions)?.try_into()?;

        let mut paragraphs = ParagraphVecShort::new();
        paragraphs.add(Paragraph::new(&theme::TEXT_NORMAL, description));
        if show_instructions {
            paragraphs
                .add(Paragraph::new(
                    &theme::TEXT_NORMAL,
                    TR::recovery__enter_each_word,
                ))
                .add(Paragraph::new(
                    &theme::TEXT_NORMAL,
                    TR::recovery__cursor_will_change,
                ));
        }

        let title = match recovery_type {
            RecoveryType::DryRun => TR::recovery__title_dry_run,
            RecoveryType::UnlockRepeatedBackup => TR::recovery__title_dry_run,
            _ => TR::recovery__title,
        };

        content_in_button_page(
            title.into(),
            paragraphs.into_paragraphs(),
            button,
            Some("".into()),
            false,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_group_share_success(
    n_args: usize,
    args: *const Obj,
    kwargs: *mut Map,
) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let lines_iterable: Obj = kwargs.get(Qstr::MP_QSTR_lines)?;
        let lines: [TString; 4] = util::iter_into_array(lines_iterable)?;

        let [l0, l1, l2, l3] = lines;

        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_MONO, l0),
            Paragraph::new(&theme::TEXT_BOLD, l1),
            Paragraph::new(&theme::TEXT_MONO, l2),
            Paragraph::new(&theme::TEXT_BOLD, l3),
        ]);

        content_in_button_page(
            "".into(),
            paragraphs,
            TR::buttons__continue.into(),
            None,
            false,
        )
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[no_mangle]
pub static mp_module_trezorui2: Module = obj_module! {
    /// from trezor import utils
    /// from trezorui_api import *
    ///
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorui2.to_obj(),

    /// def confirm_blob(
    ///     *,
    ///     title: str,
    ///     data: str | bytes,
    ///     description: str | None,
    ///     text_mono: bool = True,
    ///     extra: str | None = None,
    ///     subtitle: str | None = None,
    ///     verb: str = "CONFIRM",
    ///     verb_cancel: str | None = None,
    ///     verb_info: str | None = None,
    ///     info: bool = True,
    ///     hold: bool = False,
    ///     chunkify: bool = False,
    ///     page_counter: bool = False,
    ///     prompt_screen: bool = False,
    ///     cancel: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm byte sequence data."""
    Qstr::MP_QSTR_confirm_blob => obj_fn_kw!(0, new_confirm_blob).as_obj(),

    /// def confirm_address(
    ///     *,
    ///     title: str,
    ///     data: str,
    ///     description: str | None,  # unused on TR
    ///     extra: str | None,  # unused on TR
    ///     verb: str = "CONFIRM",
    ///     chunkify: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm address."""
    Qstr::MP_QSTR_confirm_address => obj_fn_kw!(0, new_confirm_address).as_obj(),


    /// def confirm_properties(
    ///     *,
    ///     title: str,
    ///     items: list[tuple[str | None, str | bytes | None, bool]],
    ///     hold: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm list of key-value pairs. The third component in the tuple should be True if
    ///     the value is to be rendered as binary with monospace font, False otherwise.
    ///     This only concerns the text style, you need to decode the value to UTF-8 in python."""
    Qstr::MP_QSTR_confirm_properties => obj_fn_kw!(0, new_confirm_properties).as_obj(),

    /// def confirm_backup() -> LayoutObj[UiResult]:
    ///     """Strongly recommend user to do backup."""
    Qstr::MP_QSTR_confirm_backup => obj_fn_kw!(0, new_confirm_backup).as_obj(),

    /// def show_address_details(
    ///     *,
    ///     address: str,
    ///     case_sensitive: bool,
    ///     account: str | None,
    ///     path: str | None,
    ///     xpubs: list[tuple[str, str]],
    /// ) -> LayoutObj[UiResult]:
    ///     """Show address details - QR code, account, path, cosigner xpubs."""
    Qstr::MP_QSTR_show_address_details => obj_fn_kw!(0, new_show_address_details).as_obj(),

    /// def confirm_value(
    ///     *,
    ///     title: str,
    ///     description: str,
    ///     value: str,
    ///     verb: str | None = None,
    ///     verb_info: str | None = None,
    ///     hold: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm value."""
    Qstr::MP_QSTR_confirm_value => obj_fn_kw!(0, new_confirm_value).as_obj(),

    /// def confirm_joint_total(
    ///     *,
    ///     spending_amount: str,
    ///     total_amount: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm total if there are external inputs."""
    Qstr::MP_QSTR_confirm_joint_total => obj_fn_kw!(0, new_confirm_joint_total).as_obj(),

    /// def confirm_modify_output(
    ///     *,
    ///     sign: int,
    ///     amount_change: str,
    ///     amount_new: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Decrease or increase output amount."""
    Qstr::MP_QSTR_confirm_modify_output => obj_fn_kw!(0, new_confirm_modify_output).as_obj(),

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

    /// def confirm_modify_fee(
    ///     *,
    ///     title: str,  # ignored
    ///     sign: int,
    ///     user_fee_change: str,
    ///     total_fee_new: str,
    ///     fee_rate_amount: str | None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Decrease or increase transaction fee."""
    Qstr::MP_QSTR_confirm_modify_fee => obj_fn_kw!(0, new_confirm_modify_fee).as_obj(),

    /// def confirm_fido(
    ///     *,
    ///     title: str,
    ///     app_name: str,
    ///     icon_name: str | None,  # unused on TR
    ///     accounts: list[str | None],
    /// ) -> LayoutObj[int | UiResult]:
    ///     """FIDO confirmation.
    ///
    ///     Returns page index in case of confirmation and CANCELLED otherwise.
    ///     """
    Qstr::MP_QSTR_confirm_fido => obj_fn_kw!(0, new_confirm_fido).as_obj(),

    /// def multiple_pages_texts(
    ///     *,
    ///     title: str,
    ///     verb: str,
    ///     items: list[str],
    /// ) -> LayoutObj[UiResult]:
    ///     """Show multiple texts, each on its own page."""
    Qstr::MP_QSTR_multiple_pages_texts => obj_fn_kw!(0, new_multiple_pages_texts).as_obj(),

    /// def show_warning(
    ///     *,
    ///     button: str,
    ///     warning: str,
    ///     description: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Warning modal with middle button and centered text."""
    Qstr::MP_QSTR_show_warning => obj_fn_kw!(0, new_show_warning).as_obj(),

    /// def show_passphrase() -> LayoutObj[UiResult]:
    ///     """Show passphrase on host dialog."""
    Qstr::MP_QSTR_show_passphrase => obj_fn_0!(new_show_passphrase).as_obj(),

    /// def confirm_with_info(
    ///     *,
    ///     title: str,
    ///     button: str,
    ///     info_button: str,  # unused on TR
    ///     items: Iterable[Tuple[int, str | bytes]],
    ///     verb_cancel: str | None = None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm given items but with third button. Always single page
    ///     without scrolling."""
    Qstr::MP_QSTR_confirm_with_info => obj_fn_kw!(0, new_confirm_with_info).as_obj(),

    /// def confirm_more(
    ///     *,
    ///     title: str,
    ///     button: str,
    ///     items: Iterable[tuple[int, str | bytes]],
    /// ) -> object:
    ///     """Confirm long content with the possibility to go back from any page.
    ///     Meant to be used with confirm_with_info."""
    Qstr::MP_QSTR_confirm_more => obj_fn_kw!(0, new_confirm_more).as_obj(),

    /// def confirm_coinjoin(
    ///     *,
    ///     max_rounds: str,
    ///     max_feerate: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm coinjoin authorization."""
    Qstr::MP_QSTR_confirm_coinjoin => obj_fn_kw!(0, new_confirm_coinjoin).as_obj(),

    /// def show_share_words(
    ///     *,
    ///     share_words: Iterable[str],
    /// ) -> LayoutObj[UiResult]:
    ///     """Shows a backup seed."""
    Qstr::MP_QSTR_show_share_words => obj_fn_kw!(0, new_show_share_words).as_obj(),

    /// def confirm_recovery(
    ///     *,
    ///     title: str,  # unused on TR
    ///     description: str,
    ///     button: str,
    ///     recovery_type: RecoveryType,
    ///     info_button: bool,  # unused on TR
    ///     show_instructions: bool,
    /// ) -> LayoutObj[UiResult]:
    ///     """Device recovery homescreen."""
    Qstr::MP_QSTR_confirm_recovery => obj_fn_kw!(0, new_confirm_recovery).as_obj(),

    /// def show_group_share_success(
    ///     *,
    ///     lines: Iterable[str],
    /// ) -> LayoutObj[int]:
    ///     """Shown after successfully finishing a group."""
    Qstr::MP_QSTR_show_group_share_success => obj_fn_kw!(0, new_show_group_share_success).as_obj(),
};
