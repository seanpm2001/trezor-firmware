use crate::{
    error::Error,
    io::BinaryData,
    micropython::gc::Gc,
    strutil::TString,
    translations::TR,
    ui::{
        component::{
            swipe_detect::SwipeSettings,
            text::paragraphs::{Paragraph, Paragraphs},
        },
        geometry::Direction,
        layout::{
            obj::{LayoutMaybeTrace, LayoutObj, RootComponent},
            util::RecoveryType,
        },
        ui_features_fw::UIFeaturesFirmware,
    },
};

use super::{
    component::{
        Bip39Input, Frame, MnemonicKeyboard, PinKeyboard, SelectWordCount, Slip39Input,
        SwipeContent, SwipeUpScreen, VerticalMenu,
    },
    flow, theme, ModelMercuryFeatures,
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

    fn confirm_firmware_update(
        description: TString<'static>,
        fingerprint: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error> {
        let flow =
            flow::confirm_firmware_update::new_confirm_firmware_update(description, fingerprint)?;
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
}
