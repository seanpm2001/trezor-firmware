use crate::{
    error::Error,
    io::BinaryData,
    micropython::gc::Gc,
    strutil::TString,
    translations::TR,
    ui::{
        component::{image::BlendedImage, ComponentExt, Empty, Timeout},
        layout::obj::{LayoutMaybeTrace, LayoutObj, RootComponent},
        ui_features_fw::UIFeaturesFirmware,
    },
};

use super::{
    component::{
        Bip39Input, Button, ButtonMsg, ButtonStyleSheet, CancelConfirmMsg, IconDialog,
        MnemonicKeyboard, PassphraseKeyboard, PinKeyboard, Slip39Input,
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
