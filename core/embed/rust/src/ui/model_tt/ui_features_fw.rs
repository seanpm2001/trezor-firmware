use core::cmp::Ordering;

use crate::{
    error::{value_error, Error},
    io::BinaryData,
    micropython::gc::Gc,
    strutil::TString,
    translations::TR,
    ui::{
        component::{
            connect::Connect,
            image::BlendedImage,
            text::paragraphs::{
                Checklist, Paragraph, ParagraphSource, ParagraphVecLong, ParagraphVecShort,
                Paragraphs, VecExt,
            },
            ComponentExt, Empty, Jpeg, Label, Never, Timeout,
        },
        layout::{
            obj::{LayoutMaybeTrace, LayoutObj, RootComponent},
            util::RecoveryType,
        },
        ui_features_fw::UIFeaturesFirmware,
    },
};

use super::{
    component::{
        check_homescreen_format, Bip39Input, Button, ButtonMsg, ButtonPage, ButtonStyleSheet,
        CancelConfirmMsg, CoinJoinProgress, Dialog, Frame, Homescreen, IconDialog, Lockscreen,
        MnemonicKeyboard, NumberInputDialog, PassphraseKeyboard, PinKeyboard, Progress,
        SelectWordCount, SetBrightnessDialog, Slip39Input,
    },
    theme, ModelTTFeatures,
};

impl UIFeaturesFirmware for ModelTTFeatures {
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
                    .add(Paragraph::new(&theme::TEXT_DEMIBOLD, action))
                    .add(Paragraph::new(&theme::TEXT_NORMAL, description));
            } else {
                paragraphs
                    .add(Paragraph::new(&theme::TEXT_NORMAL, description))
                    .add(Paragraph::new(&theme::TEXT_DEMIBOLD, action));
            }
            paragraphs.into_paragraphs()
        };

        let mut page = if hold {
            ButtonPage::new(paragraphs, theme::BG).with_hold()?
        } else {
            ButtonPage::new(paragraphs, theme::BG).with_cancel_confirm(verb_cancel, verb)
        };
        if hold && hold_danger {
            page = page.with_confirm_style(theme::button_danger())
        }
        let layout = RootComponent::new(Frame::left_aligned(theme::label_title(), title, page));
        Ok(layout)
    }

    fn confirm_homescreen(
        title: TString<'static>,
        mut image: BinaryData<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        if image.is_empty() {
            // Incoming data may be empty, meaning we should
            // display default homescreen image.
            image = theme::IMAGE_HOMESCREEN.into();
        }

        if !check_homescreen_format(image, false) {
            return Err(value_error!(c"Invalid image."));
        };

        let buttons = Button::cancel_confirm_text(None, Some(TR::buttons__change.into()));
        let layout = RootComponent::new(Frame::centered(
            theme::label_title(),
            title,
            Dialog::new(Jpeg::new(image, 1), buttons),
        ));
        Ok(layout)
    }

    fn confirm_coinjoin(
        max_rounds: TString<'static>,
        max_feerate: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_NORMAL, TR::coinjoin__max_rounds),
            Paragraph::new(&theme::TEXT_MONO, max_rounds),
            Paragraph::new(&theme::TEXT_NORMAL, TR::coinjoin__max_mining_fee),
            Paragraph::new(&theme::TEXT_MONO, max_feerate),
        ]);

        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            TR::coinjoin__title.into(),
            ButtonPage::new(paragraphs, theme::BG).with_hold()?,
        ));
        Ok(layout)
    }

    fn confirm_firmware_update(
        description: TString<'static>,
        fingerprint: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        use super::component::bl_confirm::{Confirm, ConfirmTitle};

        let title_str = TR::firmware_update__title.into();
        let title = Label::left_aligned(title_str, theme::TEXT_BOLD).vertically_centered();
        let msg = Label::left_aligned(description, theme::TEXT_NORMAL);

        let left = Button::with_text(TR::buttons__cancel.into()).styled(theme::button_default());
        let right = Button::with_text(TR::buttons__install.into()).styled(theme::button_confirm());

        let layout = RootComponent::new(
            Confirm::new(theme::BG, left, right, ConfirmTitle::Text(title), msg).with_info(
                TR::firmware_update__title_fingerprint.into(),
                fingerprint,
                theme::button_moreinfo(),
            ),
        );
        Ok(layout)
    }

    fn confirm_modify_fee(
        title: TString<'static>,
        sign: i32,
        user_fee_change: TString<'static>,
        total_fee_new: TString<'static>,
        fee_rate_amount: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let (description, change, total_label) = match sign {
            s if s < 0 => (
                TR::modify_fee__decrease_fee,
                user_fee_change,
                TR::modify_fee__new_transaction_fee,
            ),
            s if s > 0 => (
                TR::modify_fee__increase_fee,
                user_fee_change,
                TR::modify_fee__new_transaction_fee,
            ),
            _ => (
                TR::modify_fee__no_change,
                "".into(),
                TR::modify_fee__transaction_fee,
            ),
        };

        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_NORMAL, description),
            Paragraph::new(&theme::TEXT_MONO, change),
            Paragraph::new(&theme::TEXT_NORMAL, total_label),
            Paragraph::new(&theme::TEXT_MONO, total_fee_new),
        ]);

        let layout = RootComponent::new(
            Frame::left_aligned(
                theme::label_title(),
                title,
                ButtonPage::new(paragraphs, theme::BG)
                    .with_hold()?
                    .with_swipe_left(),
            )
            .with_info_button(),
        );
        Ok(layout)
    }

    fn confirm_modify_output(
        sign: i32,
        amount_change: TString<'static>,
        amount_new: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let description = if sign < 0 {
            TR::modify_amount__decrease_amount
        } else {
            TR::modify_amount__increase_amount
        };

        let paragraphs = Paragraphs::new([
            Paragraph::new(&theme::TEXT_NORMAL, description),
            Paragraph::new(&theme::TEXT_MONO, amount_change),
            Paragraph::new(&theme::TEXT_NORMAL, TR::modify_amount__new_amount),
            Paragraph::new(&theme::TEXT_MONO, amount_new),
        ]);

        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            TR::modify_amount__title.into(),
            ButtonPage::new(paragraphs, theme::BG)
                .with_cancel_confirm(Some("^".into()), Some(TR::buttons__continue.into())),
        ));
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
        let par_array: [Paragraph<'static>; 3] = [
            Paragraph::new(&theme::TEXT_NORMAL, TR::reset__by_continuing).with_bottom_padding(17), /* simulating a carriage return */
            Paragraph::new(&theme::TEXT_NORMAL, TR::reset__more_info_at),
            Paragraph::new(&theme::TEXT_DEMIBOLD, TR::reset__tos_link),
        ];
        let paragraphs = Paragraphs::new(par_array);
        let buttons = Button::cancel_confirm(
            Button::with_icon(theme::ICON_CANCEL),
            Button::with_text(button).styled(theme::button_confirm()),
            true,
        );
        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            title,
            Dialog::new(paragraphs, buttons),
        ));
        Ok(layout)
    }

    fn check_homescreen_format(image: BinaryData, accept_toif: bool) -> bool {
        super::component::check_homescreen_format(image, false)
    }

    fn request_bip39(
        prompt: TString<'static>,
        prefill_word: TString<'static>,
        can_go_back: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(MnemonicKeyboard::new(
            prefill_word.map(Bip39Input::prefilled_word),
            prompt,
            can_go_back,
        ));
        Ok(layout)
    }

    fn request_slip39(
        prompt: TString<'static>,
        prefill_word: TString<'static>,
        can_go_back: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(MnemonicKeyboard::new(
            prefill_word.map(Slip39Input::prefilled_word),
            prompt,
            can_go_back,
        ));

        Ok(layout)
    }

    fn request_number(
        title: TString<'static>,
        count: u32,
        min_count: u32,
        max_count: u32,
        _description: Option<TString<'static>>,
        more_info_callback: Option<impl Fn(u32) -> TString<'static> + 'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        debug_assert!(more_info_callback.is_some());
        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            title,
            NumberInputDialog::new(min_count, max_count, count, more_info_callback.unwrap())?,
        ));
        Ok(layout)
    }

    fn request_pin(
        prompt: TString<'static>,
        subprompt: TString<'static>,
        allow_cancel: bool,
        warning: bool,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let warning = if warning {
            Some(TR::pin__wrong_pin.into())
        } else {
            None
        };
        let layout = RootComponent::new(PinKeyboard::new(prompt, subprompt, warning, allow_cancel));
        Ok(layout)
    }

    fn request_passphrase(
        prompt: TString<'static>,
        max_len: u32,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(PassphraseKeyboard::new());
        Ok(layout)
    }

    fn select_word(
        title: TString<'static>,
        description: TString<'static>,
        words: [TString<'static>; 3],
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let paragraphs = Paragraphs::new([Paragraph::new(&theme::TEXT_DEMIBOLD, description)]);
        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            title,
            Dialog::new(paragraphs, Button::select_word(words)),
        ));
        Ok(layout)
    }

    fn select_word_count(recovery_type: RecoveryType) -> Result<impl LayoutMaybeTrace, Error> {
        let title: TString = match recovery_type {
            RecoveryType::DryRun => TR::recovery__title_dry_run.into(),
            RecoveryType::UnlockRepeatedBackup => TR::recovery__title_dry_run.into(),
            _ => TR::recovery__title.into(),
        };

        let paragraphs = Paragraphs::new(Paragraph::new(
            &theme::TEXT_DEMIBOLD,
            TR::recovery__num_of_words,
        ));

        let content = if matches!(recovery_type, RecoveryType::UnlockRepeatedBackup) {
            SelectWordCount::new_multishare()
        } else {
            SelectWordCount::new_all()
        };

        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            title,
            Dialog::new(paragraphs, content),
        ));
        Ok(layout)
    }

    fn set_brightness(current_brightness: Option<u8>) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(Frame::centered(
            theme::label_title(),
            TR::brightness__title.into(),
            SetBrightnessDialog::new(
                current_brightness.unwrap_or(theme::backlight::get_backlight_normal()),
            ),
        ));

        Ok(layout)
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
                Ordering::Less => &theme::TEXT_CHECKLIST_DONE,
                Ordering::Equal => &theme::TEXT_CHECKLIST_SELECTED,
                Ordering::Greater => &theme::TEXT_CHECKLIST_DEFAULT,
            };
            paragraphs.add(Paragraph::new(style, item));
        }

        let layout = RootComponent::new(Frame::left_aligned(
            theme::label_title(),
            title,
            Dialog::new(
                Checklist::from_paragraphs(
                    theme::ICON_LIST_CURRENT,
                    theme::ICON_LIST_CHECK,
                    active,
                    paragraphs
                        .into_paragraphs()
                        .with_spacing(theme::CHECKLIST_SPACING),
                )
                .with_check_width(theme::CHECKLIST_CHECK_WIDTH)
                .with_current_offset(theme::CHECKLIST_CURRENT_OFFSET)
                .with_done_offset(theme::CHECKLIST_DONE_OFFSET),
                theme::button_bar(Button::with_text(button).map(|msg| {
                    (matches!(msg, ButtonMsg::Clicked)).then(|| CancelConfirmMsg::Confirmed)
                })),
            ),
        ));
        Ok(layout)
    }

    fn show_homescreen(
        label: TString<'static>,
        hold: bool,
        notification: Option<TString<'static>>,
        notification_level: u8,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let notification = notification.map(|w| (w, notification_level));
        let layout = RootComponent::new(Homescreen::new(label, notification, hold));
        Ok(layout)
    }

    fn show_info(
        title: TString<'static>,
        description: TString<'static>,
        button: TString<'static>,
        time_ms: u32,
    ) -> Result<Gc<LayoutObj>, Error> {
        assert!(
            !button.is_empty() || time_ms > 0,
            "either button or timeout must be set"
        );

        let icon = BlendedImage::new(
            theme::IMAGE_BG_CIRCLE,
            theme::IMAGE_FG_INFO,
            theme::INFO_COLOR,
            theme::FG,
            theme::BG,
        );
        let obj = new_show_modal(
            title,
            TString::empty(),
            description,
            button,
            false,
            time_ms,
            icon,
            theme::button_info(),
        )?;
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
        let description: TString = TR::addr_mismatch__contact_support_at.into();
        let url: TString = TR::addr_mismatch__support_url.into();
        let button: TString = TR::buttons__quit.into();

        let icon = BlendedImage::new(
            theme::IMAGE_BG_OCTAGON,
            theme::IMAGE_FG_WARN,
            theme::WARN_COLOR,
            theme::FG,
            theme::BG,
        );
        let layout = RootComponent::new(
            IconDialog::new(
                icon,
                title,
                Button::cancel_confirm(
                    Button::with_icon(theme::ICON_BACK),
                    Button::with_text(button).styled(theme::button_reset()),
                    true,
                ),
            )
            .with_paragraph(
                Paragraph::new(&theme::TEXT_NORMAL, description)
                    .centered()
                    .with_bottom_padding(
                        theme::TEXT_NORMAL.text_font.text_height()
                            - theme::TEXT_DEMIBOLD.text_font.text_height(),
                    ),
            )
            .with_text(&theme::TEXT_DEMIBOLD, url),
        );

        Ok(layout)
    }

    fn show_progress(
        description: TString<'static>,
        indeterminate: bool,
        title: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let (title, description) = if let Some(title) = title {
            (title, description)
        } else {
            (description, "".into())
        };

        let layout = RootComponent::new(Progress::new(title, indeterminate, description));
        Ok(layout)
    }

    fn show_progress_coinjoin(
        title: TString<'static>,
        indeterminate: bool,
        time_ms: u32,
        skip_first_paint: bool,
    ) -> Result<Gc<LayoutObj>, Error> {
        let progress = CoinJoinProgress::<Never>::new(title, indeterminate)?;
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
        Err::<RootComponent<Empty, ModelTTFeatures>, Error>(Error::ValueError(
            c"tutorial not supported",
        ))
    }
}

fn new_show_modal(
    title: TString<'static>,
    value: TString<'static>,
    description: TString<'static>,
    button: TString<'static>,
    allow_cancel: bool,
    time_ms: u32,
    icon: BlendedImage,
    button_style: ButtonStyleSheet,
) -> Result<Gc<LayoutObj>, Error> {
    let no_buttons = button.is_empty();
    let obj = if no_buttons && time_ms == 0 {
        // No buttons and no timer, used when we only want to draw the dialog once and
        // then throw away the layout object.
        LayoutObj::new(
            IconDialog::new(icon, title, Empty)
                .with_value(value)
                .with_description(description),
        )?
    } else if no_buttons && time_ms > 0 {
        // Timeout, no buttons.
        LayoutObj::new(
            IconDialog::new(
                icon,
                title,
                Timeout::new(time_ms).map(|_| Some(CancelConfirmMsg::Confirmed)),
            )
            .with_value(value)
            .with_description(description),
        )?
    } else if allow_cancel {
        // Two buttons.
        LayoutObj::new(
            IconDialog::new(
                icon,
                title,
                Button::cancel_confirm(
                    Button::with_icon(theme::ICON_CANCEL),
                    Button::with_text(button).styled(button_style),
                    false,
                ),
            )
            .with_value(value)
            .with_description(description),
        )?
    } else {
        // Single button.
        LayoutObj::new(
            IconDialog::new(
                icon,
                title,
                theme::button_bar(Button::with_text(button).styled(button_style).map(|msg| {
                    (matches!(msg, ButtonMsg::Clicked)).then(|| CancelConfirmMsg::Confirmed)
                })),
            )
            .with_value(value)
            .with_description(description),
        )?
    };

    Ok(obj)
}
