use core::cmp::Ordering;

use crate::{
    error::{value_error, Error},
    io::BinaryData,
    micropython::gc::Gc,
    strutil::TString,
    translations::TR,
    ui::{
        component::{
            connect::Connect, swipe_detect::SwipeSettings, text::paragraphs::{
                Checklist, Paragraph, ParagraphSource, ParagraphVecLong, ParagraphVecShort,
                Paragraphs, VecExt,
            }, CachedJpeg, ComponentExt, Empty, Never, Timeout
        },
        geometry::{self, Direction},
        layout::{
            obj::{LayoutMaybeTrace, LayoutObj, RootComponent},
            util::RecoveryType,
        },
        ui_features_fw::UIFeaturesFirmware,
    },
};

use super::{
    component::{
        check_homescreen_format, Bip39Input, CoinJoinProgress, Frame, Homescreen, Lockscreen,
        MnemonicKeyboard, PinKeyboard, Progress, SelectWordCount, Slip39Input, SwipeContent,
        SwipeUpScreen, VerticalMenu,
    },
    flow::{
        self, new_confirm_action_simple, ConfirmActionExtra, ConfirmActionMenu,
        ConfirmActionMenuStrings, ConfirmActionStrings,
    },
    theme, ModelMercuryFeatures,
};

impl UIFeaturesFirmware for ModelMercuryFeatures {
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
        let flow = flow::confirm_action::new_confirm_action(
            title,
            action,
            description,
            subtitle,
            verb_cancel,
            reverse,
            hold,
            prompt_screen,
            prompt_title.unwrap_or(TString::empty()),
        )?;
        Ok(flow)
    }

    fn confirm_homescreen(
        title: TString<'static>,
        image: BinaryData<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = if image.is_empty() {
            // Incoming data may be empty, meaning we should
            // display default homescreen message.
            let paragraphs = ParagraphVecShort::from_iter([Paragraph::new(
                &theme::TEXT_DEMIBOLD,
                TR::homescreen__set_default,
            )])
            .into_paragraphs();

            new_confirm_action_simple(
                paragraphs,
                ConfirmActionExtra::Menu(ConfirmActionMenuStrings::new()),
                ConfirmActionStrings::new(
                    TR::homescreen__settings_title.into(),
                    Some(TR::homescreen__settings_subtitle.into()),
                    None,
                    Some(TR::homescreen__settings_title.into()),
                ),
                false,
                None,
                0,
                false,
            )?
        } else {
            if !check_homescreen_format(image) {
                return Err(value_error!(c"Invalid image."));
            };

            flow::confirm_homescreen::new_confirm_homescreen(title, CachedJpeg::new(image, 1))?
        };
        Ok(layout)
    }

    fn confirm_coinjoin(
        max_rounds: TString<'static>,
        max_feerate: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let paragraphs = ParagraphVecShort::from_iter([
            Paragraph::new(&theme::TEXT_NORMAL, TR::coinjoin__max_rounds),
            Paragraph::new(&theme::TEXT_MONO, max_rounds),
            Paragraph::new(&theme::TEXT_NORMAL, TR::coinjoin__max_mining_fee),
            Paragraph::new(&theme::TEXT_MONO, max_feerate),
        ])
        .into_paragraphs();

        let flow = flow::new_confirm_action_simple(
            paragraphs,
            ConfirmActionExtra::Menu(ConfirmActionMenuStrings::new()),
            ConfirmActionStrings::new(
                TR::coinjoin__title.into(),
                None,
                None,
                Some(TR::coinjoin__title.into()),
            ),
            true,
            None,
            0,
            false,
        )?;
        Ok(flow)
    }

    fn confirm_firmware_update(
        description: TString<'static>,
        fingerprint: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let flow =
            flow::confirm_firmware_update::new_confirm_firmware_update(description, fingerprint)?;
        Ok(flow)
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

        let paragraphs = ParagraphVecShort::from_iter([
            Paragraph::new(&theme::TEXT_SUB_GREY, description),
            Paragraph::new(&theme::TEXT_MONO, change),
            Paragraph::new(&theme::TEXT_SUB_GREY, total_label),
            Paragraph::new(&theme::TEXT_MONO, total_fee_new),
        ]);

        let flow = flow::new_confirm_action_simple(
            paragraphs.into_paragraphs(),
            ConfirmActionExtra::Menu(
                ConfirmActionMenuStrings::new()
                    .with_verb_info(Some(TR::words__title_information.into())),
            ),
            ConfirmActionStrings::new(title, None, None, Some(title)),
            true,
            None,
            0,
            false,
        )?;
        Ok(flow)
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

        let paragraphs = ParagraphVecShort::from_iter([
            Paragraph::new(&theme::TEXT_NORMAL, description),
            Paragraph::new(&theme::TEXT_MONO, amount_change),
            Paragraph::new(&theme::TEXT_NORMAL, TR::modify_amount__new_amount),
            Paragraph::new(&theme::TEXT_MONO, amount_new),
        ])
        .into_paragraphs();

        let layout = RootComponent::new(SwipeUpScreen::new(
            Frame::left_aligned(TR::modify_amount__title.into(), paragraphs)
                .with_cancel_button()
                .with_footer(TR::instructions__swipe_up.into(), None)
                .with_swipe(Direction::Up, SwipeSettings::default()),
        ));
        Ok(layout)
    }

    fn confirm_reset_device(recovery: bool) -> Result<impl LayoutMaybeTrace, Error> {
        let flow = flow::confirm_reset::new_confirm_reset(recovery)?;
        Ok(flow)
    }

    fn check_homescreen_format(image: BinaryData, __accept_toif: bool) -> bool {
        super::component::check_homescreen_format(image)
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
        description: Option<TString<'static>>,
        more_info_callback: Option<impl Fn(u32) -> TString<'static> + 'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        debug_assert!(
            description.is_some(),
            "Description is required for request_number"
        );
        debug_assert!(
            more_info_callback.is_some(),
            "More info callback is required for request_number"
        );
        let flow = flow::request_number::new_request_number(
            title,
            count,
            min_count,
            max_count,
            description.unwrap(),
            more_info_callback.unwrap(),
        )?;
        Ok(flow)
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
        let flow = flow::request_passphrase::new_request_passphrase()?;
        Ok(flow)
    }

    fn select_word(
        title: TString<'static>,
        description: TString<'static>,
        words: [TString<'static>; 3],
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let content = VerticalMenu::select_word(words);
        let layout =
            RootComponent::new(Frame::left_aligned(title, content).with_subtitle(description));
        Ok(layout)
    }

    fn select_word_count(recovery_type: RecoveryType) -> Result<impl LayoutMaybeTrace, Error> {
        let content = if matches!(recovery_type, RecoveryType::UnlockRepeatedBackup) {
            SelectWordCount::new_multishare()
        } else {
            SelectWordCount::new_all()
        };
        let layout = RootComponent::new(Frame::left_aligned(
            TR::recovery__num_of_words.into(),
            content,
        ));
        Ok(layout)
    }

    fn set_brightness(current_brightness: Option<u8>) -> Result<impl LayoutMaybeTrace, Error> {
        let flow = flow::set_brightness::new_set_brightness(current_brightness)?;
        Ok(flow)
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

        let checklist_content = Checklist::from_paragraphs(
            theme::ICON_CHEVRON_RIGHT,
            theme::ICON_BULLET_CHECKMARK,
            active,
            paragraphs
                .into_paragraphs()
                .with_spacing(theme::CHECKLIST_SPACING),
        )
        .with_check_width(theme::CHECKLIST_CHECK_WIDTH)
        .with_numerals()
        .with_icon_done_color(theme::GREEN)
        .with_done_offset(theme::CHECKLIST_DONE_OFFSET);

        let layout = RootComponent::new(SwipeUpScreen::new(
            Frame::left_aligned(title, SwipeContent::new(checklist_content))
                .with_footer(TR::instructions__swipe_up.into(), None)
                .with_swipe(Direction::Up, SwipeSettings::default()),
        ));
        Ok(layout)
    }

    fn show_group_share_success(
        lines: [TString<'static>; 4],
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let paragraphs = ParagraphVecShort::from_iter([
            Paragraph::new(&theme::TEXT_NORMAL_GREY_EXTRA_LIGHT, lines[0]).centered(),
            Paragraph::new(&theme::TEXT_DEMIBOLD, lines[1]).centered(),
            Paragraph::new(&theme::TEXT_NORMAL_GREY_EXTRA_LIGHT, lines[2]).centered(),
            Paragraph::new(&theme::TEXT_DEMIBOLD, lines[3]).centered(),
        ])
        .into_paragraphs()
        .with_placement(geometry::LinearPlacement::vertical().align_at_center());

        let layout = RootComponent::new(SwipeUpScreen::new(
            Frame::left_aligned("".into(), SwipeContent::new(paragraphs))
                .with_footer(TR::instructions__swipe_up.into(), None)
                .with_swipe(Direction::Up, SwipeSettings::default()),
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
        _button: TString<'static>,
        _time_ms: u32,
    ) -> Result<Gc<LayoutObj>, Error> {
        let content = Paragraphs::new(Paragraph::new(&theme::TEXT_MAIN_GREY_LIGHT, description));
        let obj = LayoutObj::new(SwipeUpScreen::new(
            Frame::left_aligned(title, SwipeContent::new(content))
                .with_footer(TR::instructions__swipe_up.into(), None)
                .with_swipe(Direction::Up, SwipeSettings::default()),
        ))?;
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

        let paragraphs = ParagraphVecShort::from_iter([
            Paragraph::new(&theme::TEXT_NORMAL, description).centered(),
            Paragraph::new(&theme::TEXT_DEMIBOLD, url).centered(),
        ])
        .into_paragraphs();

        let layout = RootComponent::new(SwipeUpScreen::new(
            Frame::left_aligned(title, SwipeContent::new(paragraphs))
                .with_cancel_button()
                .with_footer(TR::instructions__swipe_up.into(), Some(button))
                .with_swipe(Direction::Up, SwipeSettings::default()),
        ));

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

    fn show_remaining_shares(
        pages_iterable: crate::micropython::obj::Obj, // TODO: replace Obj
    ) -> Result<impl LayoutMaybeTrace, Error> {
        // Mercury: remaining shares is a part of `continue_recovery` flow
        Err::<RootComponent<Empty, ModelMercuryFeatures>, Error>(Error::ValueError(
            c"show remaining shares not supported",
        ))
    }

    fn show_wait_text(text: TString<'static>) -> Result<impl LayoutMaybeTrace, Error> {
        let layout = RootComponent::new(Connect::new(text, theme::FG, theme::BG));
        Ok(layout)
    }

    fn tutorial() -> Result<impl LayoutMaybeTrace, Error> {
        let flow = flow::show_tutorial::new_show_tutorial()?;
        Ok(flow)
    }
}
