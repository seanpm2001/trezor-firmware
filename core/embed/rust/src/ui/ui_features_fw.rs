use crate::{
    error::Error,
    io::BinaryData,
    micropython::{gc::Gc, list::List, obj::Obj},
    strutil::TString,
};

use super::layout::{
    obj::{LayoutMaybeTrace, LayoutObj},
    util::RecoveryType,
};

pub trait UIFeaturesFirmware {
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
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_homescreen(
        title: TString<'static>,
        image: BinaryData<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_coinjoin(
        max_rounds: TString<'static>,
        max_feerate: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_fido(
        title: TString<'static>,
        app_name: TString<'static>,
        icon: Option<TString<'static>>,
        accounts: Gc<List>, // TODO: replace Gc<List>
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_firmware_update(
        description: TString<'static>,
        fingerprint: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_modify_fee(
        title: TString<'static>,
        sign: i32,
        user_fee_change: TString<'static>,
        total_fee_new: TString<'static>,
        fee_rate_amount: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_modify_output(
        sign: i32,
        amount_change: TString<'static>,
        amount_new: TString<'static>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn confirm_reset_device(recovery: bool) -> Result<impl LayoutMaybeTrace, Error>;

    fn continue_recovery_homepage(
        text: TString<'static>,
        subtext: Option<TString<'static>>,
        button: Option<TString<'static>>,
        recovery_type: RecoveryType,
        show_instructions: bool,
        remaining_shares: Option<Obj>, // TODO: replace Obj
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn check_homescreen_format(image: BinaryData, accept_toif: bool) -> bool;

    fn request_bip39(
        prompt: TString<'static>,
        prefill_word: TString<'static>,
        can_go_back: bool,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn request_slip39(
        prompt: TString<'static>,
        prefill_word: TString<'static>,
        can_go_back: bool,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn request_number(
        title: TString<'static>,
        count: u32,
        min_count: u32,
        max_count: u32,
        description: Option<TString<'static>>,
        more_info_callback: Option<impl Fn(u32) -> TString<'static> + 'static>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn request_pin(
        prompt: TString<'static>,
        subprompt: TString<'static>,
        allow_cancel: bool,
        warning: bool,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn request_passphrase(
        prompt: TString<'static>,
        max_len: u32,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn select_word(
        title: TString<'static>,
        description: TString<'static>,
        words: [TString<'static>; 3],
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn select_word_count(recovery_type: RecoveryType) -> Result<impl LayoutMaybeTrace, Error>;

    fn set_brightness(current_brightness: Option<u8>) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_checklist(
        title: TString<'static>,
        button: TString<'static>,
        active: usize,
        items: [TString<'static>; 3],
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_danger(
        title: TString<'static>,
        description: TString<'static>,
        value: TString<'static>,
        verb_cancel: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_error(
        title: TString<'static>,
        button: TString<'static>,
        description: TString<'static>,
        allow_cancel: bool,
        time_ms: u32,
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn show_group_share_success(
        lines: [TString<'static>; 4],
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_homescreen(
        label: TString<'static>,
        hold: bool,
        notification: Option<TString<'static>>,
        notification_level: u8,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_info(
        title: TString<'static>,
        description: TString<'static>,
        button: TString<'static>,
        time_ms: u32,
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn show_lockscreen(
        label: TString<'static>,
        bootscreen: bool,
        coinjoin_authorized: bool,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_mismatch(title: TString<'static>) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_progress(
        description: TString<'static>,
        indeterminate: bool,
        title: Option<TString<'static>>,
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_progress_coinjoin(
        title: TString<'static>,
        indeterminate: bool,
        time_ms: u32,
        skip_first_paint: bool,
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn show_remaining_shares(
        pages_iterable: Obj, // TODO: replace Obj
    ) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_simple(
        text: TString<'static>,
        title: Option<TString<'static>>,
        button: Option<TString<'static>>,
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn show_success(
        title: TString<'static>,
        button: TString<'static>,
        description: TString<'static>,
        allow_cancel: bool,
        time_ms: u32,
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn show_wait_text(text: TString<'static>) -> Result<impl LayoutMaybeTrace, Error>;

    fn show_warning(
        title: TString<'static>,
        button: TString<'static>,
        value: TString<'static>,
        description: TString<'static>,
        allow_cancel: bool,
        time_ms: u32,
        danger: bool,
    ) -> Result<Gc<LayoutObj>, Error>; // TODO: return LayoutMaybeTrace

    fn tutorial() -> Result<impl LayoutMaybeTrace, Error>;
}
