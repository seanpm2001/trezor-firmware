use core::cmp::Ordering;

use crate::{
    error::Error,
    io::BinaryData,
    maybe_trace::MaybeTrace,
    micropython::gc::Gc,
    strutil::TString,
    translations::TR,
    ui::{
        component::{
            connect::Connect,
            text::{
                op::OpTextLayout,
                paragraphs::{
                    Checklist, Paragraph, ParagraphSource, ParagraphVecLong, ParagraphVecShort,
                    Paragraphs, VecExt,
                },
            },
            Component, ComponentExt, Empty, FormattedText, Label, LineBreaking, Paginate, Timeout,
        },
        layout::{
            obj::{LayoutMaybeTrace, LayoutObj, RootComponent},
            util::RecoveryType,
        },
        model_tr::{
            component::{ButtonActions, ButtonLayout, Page},
            constant,
        },
        ui_features_fw::UIFeaturesFirmware,
    },
};

use super::{
    component::{
        ButtonDetails, ButtonPage, CoinJoinProgress, ConfirmHomescreen, Flow, FlowPages, Frame,
        Homescreen, Lockscreen, NumberInput, PassphraseEntry, PinEntry, Progress, ScrollableFrame,
        SimpleChoice, WordlistEntry, WordlistType,
    },
    theme, ModelTRFeatures,
};

use heapless::Vec;

impl UIFeaturesFirmware for ModelTRFeatures {
    fn confirm_action(
        title: TString<'static>,
        action: Option<TString<'static>>,
        description: Option<TString<'static>>,
        subtitle: Option<TString<'static>>,
        verb: Option<TString<'static>>,
        verb_cancel: Option<TString<'static>>,
        hold: bool,
        hold_danger: bool,
        reverse: bool,
        prompt_screen: bool,
        prompt_title: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let paragraphs = {
            let action = action.unwrap_or("".into());
            let description = description.unwrap_or("".into());
            let mut paragraphs = ParagraphVecShort::new();
            if !reverse {
                paragraphs
                    .add(Paragraph::new(&theme::TEXT_BOLD, action))
                    .add(Paragraph::new(&theme::TEXT_NORMAL, description));
            } else {
                paragraphs
                    .add(Paragraph::new(&theme::TEXT_NORMAL, description))
                    .add(Paragraph::new(&theme::TEXT_BOLD, action));
            }
            paragraphs.into_paragraphs()
        };

        content_in_button_page(
            title,
            paragraphs,
            verb.unwrap_or(TString::empty()),
            verb_cancel,
            hold,
        )
    }

    fn confirm_homescreen(
        title: TString<'static>,
        image: BinaryData<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(ConfirmHomescreen::new(title, image));
        Ok(layout)
    }

    fn confirm_coinjoin(
        max_rounds: TString<'static>,
        max_feerate: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
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
    }

    fn confirm_firmware_update(
        description: TString<'static>,
        fingerprint: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        use super::component::bl_confirm::Confirm;
        let title = TR::firmware_update__title;
        let message = Label::left_aligned(description, theme::TEXT_NORMAL).vertically_centered();
        let fingerprint = Label::left_aligned(
            fingerprint,
            theme::TEXT_NORMAL.with_line_breaking(LineBreaking::BreakWordsNoHyphen),
        )
        .vertically_centered();

        let layout = RootComponent::new(
            Confirm::new(
                theme::BG,
                title.into(),
                message,
                None,
                TR::buttons__install.as_tstring(),
                false,
            )
            .with_info_screen(
                TR::firmware_update__title_fingerprint.as_tstring(),
                fingerprint,
            ),
        );
        Ok(layout)
    }

    fn confirm_reset_device(recovery: bool) -> Result<impl LayoutMaybeTrace, Error> {
        let (title, button) = if recovery {
            (
                TR::recovery__title_recover.into(),
                TR::reset__button_recover.into(),
            )
        } else {
            (
                TR::reset__title_create_wallet.into(),
                TR::reset__button_create.into(),
            )
        };
        let ops = OpTextLayout::new(theme::TEXT_NORMAL)
            .text_normal(TR::reset__by_continuing)
            .next_page()
            .text_normal(TR::reset__more_info_at)
            .newline()
            .text_bold(TR::reset__tos_link);
        let formatted = FormattedText::new(ops).vertically_centered();

        content_in_button_page(title, formatted, button, Some("".into()), false)
    }

    fn check_homescreen_format(image: BinaryData, _accept_toif: bool) -> bool {
        super::component::check_homescreen_format(image)
    }

    fn request_bip39(
        prompt: TString<'static>,
        prefill_word: TString<'static>,
        can_go_back: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(
            Frame::new(
                prompt,
                prefill_word
                    .map(|s| WordlistEntry::prefilled_word(s, WordlistType::Bip39, can_go_back)),
            )
            .with_title_centered(),
        );
        Ok(layout)
    }

    fn request_slip39(
        prompt: TString<'static>,
        prefill_word: TString<'static>,
        can_go_back: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(
            Frame::new(
                prompt,
                prefill_word
                    .map(|s| WordlistEntry::prefilled_word(s, WordlistType::Slip39, can_go_back)),
            )
            .with_title_centered(),
        );
        Ok(layout)
    }

    fn request_number(
        title: TString<'static>,
        count: u32,
        min_count: u32,
        max_count: u32,
        _description: Option<TString<'static>>,
        _more_info_callback: Option<impl Fn(u32) -> TString<'static> + 'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(
            Frame::new(title, NumberInput::new(min_count, max_count, count)).with_title_centered(),
        );
        Ok(layout)
    }

    fn request_pin(
        prompt: TString<'static>,
        subprompt: TString<'static>,
        allow_cancel: bool,
        warning: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(PinEntry::new(prompt, subprompt));
        Ok(layout)
    }

    fn request_passphrase(
        prompt: TString<'static>,
        max_len: u32,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout =
            RootComponent::new(Frame::new(prompt, PassphraseEntry::new()).with_title_centered());
        Ok(layout)
    }

    fn select_word(
        title: TString<'static>,
        description: TString<'static>,
        words: [TString<'static>; 3],
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let words: Vec<TString<'static>, 5> = Vec::from_iter(words);
        // Returning the index of the selected word, not the word itself
        let layout = RootComponent::new(
            Frame::new(
                description,
                SimpleChoice::new(words, false)
                    .with_show_incomplete()
                    .with_return_index(),
            )
            .with_title_centered(),
        );
        Ok(layout)
    }

    fn select_word_count(recovery_type: RecoveryType) -> Result<impl LayoutMaybeTrace, Error> {
        let title: TString = TR::word_count__title.into();
        let choices: Vec<TString<'static>, 5> = {
            let nums: &[&str] = if matches!(recovery_type, RecoveryType::UnlockRepeatedBackup) {
                &["20", "33"]
            } else {
                &["12", "18", "20", "24", "33"]
            };

            nums.iter().map(|&num| num.into()).collect()
        };

        let layout = RootComponent::new(
            Frame::new(title, SimpleChoice::new(choices, false)).with_title_centered(),
        );
        Ok(layout)
    }

    fn set_brightness(current_brightness: Option<u8>) -> Result<impl LayoutMaybeTrace, Error> {
        Err::<RootComponent<Empty, ModelTRFeatures>, Error>(Error::ValueError(
            c"setting brightness not supported",
        ))
    }

    fn show_checklist(
        title: TString<'static>,
        button: TString<'static>,
        active: usize,
        items: [TString<'static>; 3],
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let mut paragraphs = ParagraphVecLong::new();
        for (i, item) in items.into_iter().enumerate() {
            let style = match i.cmp(&active) {
                Ordering::Less => &theme::TEXT_NORMAL,
                Ordering::Equal => &theme::TEXT_BOLD,
                Ordering::Greater => &theme::TEXT_NORMAL,
            };
            paragraphs.add(Paragraph::new(style, item));
        }
        let confirm_btn = Some(ButtonDetails::text(button));

        let layout = RootComponent::new(
            ButtonPage::new(
                Checklist::from_paragraphs(
                    theme::ICON_ARROW_RIGHT_FAT,
                    theme::ICON_TICK_FAT,
                    active,
                    paragraphs
                        .into_paragraphs()
                        .with_spacing(theme::CHECKLIST_SPACING),
                )
                .with_check_width(theme::CHECKLIST_CHECK_WIDTH)
                .with_current_offset(theme::CHECKLIST_CURRENT_OFFSET),
                theme::BG,
            )
            .with_confirm_btn(confirm_btn),
        );
        Ok(layout)
    }

    fn show_homescreen(
        label: TString<'static>,
        hold: bool,
        notification: Option<TString<'static>>,
        notification_level: u8,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let notification = notification.map(|w| (w, notification_level));
        let loader_description = hold.then_some("Locking the device...".into());
        let layout = RootComponent::new(Homescreen::new(label, notification, loader_description));
        Ok(layout)
    }

    fn show_info(
        title: TString<'static>,
        description: TString<'static>,
        _button: TString<'static>,
        time_ms: u32,
    ) -> Result<Gc<LayoutObj>, Error> {
        let content = Frame::new(
            title,
            Paragraphs::new([Paragraph::new(&theme::TEXT_NORMAL, description)]),
        );
        let obj = if time_ms == 0 {
            // No timer, used when we only want to draw the dialog once and
            // then throw away the layout object.
            LayoutObj::new(content)?
        } else {
            // Timeout.
            let timeout = Timeout::new(time_ms);
            LayoutObj::new((timeout, content.map(|_| None)))?
        };
        Ok(obj)
    }

    fn show_lockscreen(
        label: TString<'static>,
        bootscreen: bool,
        coinjoin_authorized: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(Lockscreen::new(label, bootscreen, coinjoin_authorized));
        Ok(layout)
    }

    fn show_mismatch(title: TString<'static>) -> Result<impl LayoutMaybeTrace, Error> {
        let get_page = move |page_index| {
            assert!(page_index == 0);

            let btn_layout = ButtonLayout::arrow_none_text(TR::buttons__quit.into());
            let btn_actions = ButtonActions::cancel_none_confirm();
            let ops = OpTextLayout::new(theme::TEXT_NORMAL)
                .text_bold_upper(title)
                .newline()
                .newline_half()
                .text_normal(TR::addr_mismatch__contact_support_at)
                .newline()
                .text_bold(TR::addr_mismatch__support_url);
            let formatted = FormattedText::new(ops);
            Page::new(btn_layout, btn_actions, formatted)
        };
        let pages = FlowPages::new(get_page, 1);

        let obj = RootComponent::new(Flow::new(pages));
        Ok(obj)
    }

    fn show_progress(
        description: TString<'static>,
        indeterminate: bool,
        title: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let mut progress = Progress::new(indeterminate, description);
        if let Some(title) = title {
            progress = progress.with_title(title);
        };

        let layout = RootComponent::new(progress);
        Ok(layout)
    }

    fn show_progress_coinjoin(
        title: TString<'static>,
        indeterminate: bool,
        time_ms: u32,
        skip_first_paint: bool,
    ) -> Result<Gc<LayoutObj>, Error> {
        let progress = CoinJoinProgress::new(title, indeterminate);
        let obj = if time_ms > 0 && indeterminate {
            let timeout = Timeout::new(time_ms);
            LayoutObj::new((timeout, progress.map(|_msg| None)))?
        } else {
            LayoutObj::new(progress)?
        };
        if skip_first_paint {
            obj.skip_first_paint();
        }
        Ok(obj)
    }

    fn show_wait_text(text: TString<'static>) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(Connect::new(text, theme::FG, theme::BG));
        Ok(layout)
    }

    fn tutorial() -> Result<impl LayoutMaybeTrace, Error> {
        const PAGE_COUNT: usize = 7;

        let get_page = move |page_index| {
            // Lazy-loaded list of screens to show, with custom content,
            // buttons and actions triggered by these buttons.
            // Cancelling the first screen will point to the last one,
            // which asks for confirmation whether user wants to
            // really cancel the tutorial.
            match page_index {
                // title, text, btn_layout, btn_actions
                0 => tutorial_screen(
                    TR::tutorial__title_hello.into(),
                    TR::tutorial__welcome_press_right,
                    ButtonLayout::cancel_none_arrow(),
                    ButtonActions::last_none_next(),
                ),
                1 => tutorial_screen(
                    "".into(),
                    TR::tutorial__use_trezor,
                    ButtonLayout::arrow_none_arrow(),
                    ButtonActions::prev_none_next(),
                ),
                2 => tutorial_screen(
                    TR::buttons__hold_to_confirm.into(),
                    TR::tutorial__press_and_hold,
                    ButtonLayout::arrow_none_htc(TR::buttons__hold_to_confirm.into()),
                    ButtonActions::prev_none_next(),
                ),
                3 => tutorial_screen(
                    TR::tutorial__title_screen_scroll.into(),
                    TR::tutorial__scroll_down,
                    ButtonLayout::arrow_none_text(TR::buttons__continue.into()),
                    ButtonActions::prev_none_next(),
                ),
                4 => tutorial_screen(
                    TR::buttons__confirm.into(),
                    TR::tutorial__middle_click,
                    ButtonLayout::none_armed_none(TR::buttons__confirm.into()),
                    ButtonActions::none_next_none(),
                ),
                5 => tutorial_screen(
                    TR::tutorial__title_tutorial_complete.into(),
                    TR::tutorial__ready_to_use,
                    ButtonLayout::text_none_text(
                        TR::buttons__again.into(),
                        TR::buttons__continue.into(),
                    ),
                    ButtonActions::beginning_none_confirm(),
                ),
                6 => tutorial_screen(
                    TR::tutorial__title_skip.into(),
                    TR::tutorial__sure_you_want_skip,
                    ButtonLayout::arrow_none_text(TR::buttons__skip.into()),
                    ButtonActions::beginning_none_cancel(),
                ),
                _ => unreachable!(),
            }
        };

        let pages = FlowPages::new(get_page, PAGE_COUNT);

        // Setting the ignore-second-button to mimic all the Choice pages, to teach user
        // that they should really press both buttons at the same time to achieve
        // middle-click.
        let layout = RootComponent::new(
            Flow::new(pages)
                .with_scrollbar(false)
                .with_ignore_second_button_ms(constant::IGNORE_OTHER_BTN_MS),
        );
        Ok(layout)
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
) -> Result<impl LayoutMaybeTrace, Error> {
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

    Ok(RootComponent::new(frame))
}

/// General pattern of most tutorial screens.
/// (title, text, btn_layout, btn_actions, text_y_offset)
fn tutorial_screen(
    title: TString<'static>,
    text: TR,
    btn_layout: ButtonLayout,
    btn_actions: ButtonActions,
) -> Page {
    let ops = OpTextLayout::new(theme::TEXT_NORMAL).text_normal(text);
    let formatted = FormattedText::new(ops).vertically_centered();
    Page::new(btn_layout, btn_actions, formatted).with_title(title)
}
