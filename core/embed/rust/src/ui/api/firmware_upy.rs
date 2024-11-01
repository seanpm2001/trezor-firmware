use crate::{
    io::BinaryData,
    micropython::{
        macros::{obj_fn_1, obj_fn_kw, obj_module},
        map::Map,
        module::Module,
        obj::Obj,
        qstr::Qstr,
        util,
    },
    strutil::TString,
    trezorhal::model,
    ui::{
        backlight::BACKLIGHT_LEVELS_OBJ,
        component::Empty,
        layout::{
            base::LAYOUT_STATE,
            obj::{ComponentMsgObj, LayoutObj, ATTACH_TYPE_OBJ},
            result::{CANCELLED, CONFIRMED, INFO},
            util::{upy_disable_animation, RecoveryType},
        },
        ui_features::ModelUI,
        ui_features_fw::UIFeaturesFirmware,
    },
};

/// Dummy implementation so that we can use `Empty` in a return type of unimplemented trait
/// function
impl ComponentMsgObj for Empty {
    fn msg_try_into_obj(&self, _msg: Self::Msg) -> Result<Obj, crate::error::Error> {
        Ok(Obj::const_none())
    }
}

// free-standing functions exported to MicroPython mirror `trait
// UIFeaturesFirmware`
// NOTE: `disable_animation` not a part of trait UiFeaturesFirmware

extern "C" fn new_confirm_action(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let action: Option<TString> = kwargs.get(Qstr::MP_QSTR_action)?.try_into_option()?;
        let description: Option<TString> =
            kwargs.get(Qstr::MP_QSTR_description)?.try_into_option()?;
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
        let hold: bool = kwargs.get_or(Qstr::MP_QSTR_hold, false)?;
        let hold_danger: bool = kwargs.get_or(Qstr::MP_QSTR_hold_danger, false)?;
        let reverse: bool = kwargs.get_or(Qstr::MP_QSTR_reverse, false)?;
        let prompt_screen: bool = kwargs.get_or(Qstr::MP_QSTR_prompt_screen, false)?;
        let prompt_title: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_prompt_title)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let layout = ModelUI::confirm_action(
            title,
            action,
            description,
            subtitle,
            verb,
            verb_cancel,
            hold,
            hold_danger,
            reverse,
            prompt_screen,
            prompt_title,
        )?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}
// TODO: there was `no_mangle` attribute in TT, should we apply it?
extern "C" fn new_confirm_firmware_update(
    n_args: usize,
    args: *const Obj,
    kwargs: *mut Map,
) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;
        let fingerprint: TString = kwargs.get(Qstr::MP_QSTR_fingerprint)?.try_into()?;

        let layout = ModelUI::confirm_firmware_update(description, fingerprint)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_homescreen(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let image: Obj = kwargs.get(Qstr::MP_QSTR_image)?;

        let jpeg: BinaryData = image.try_into()?;

        let layout = ModelUI::confirm_homescreen(title, jpeg)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };

    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_confirm_reset_device(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let recovery: bool = kwargs.get(Qstr::MP_QSTR_recovery)?.try_into()?;

        let layout = ModelUI::confirm_reset_device(recovery)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_request_bip39(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let prompt: TString = kwargs.get(Qstr::MP_QSTR_prompt)?.try_into()?;
        let prefill_word: TString = kwargs.get(Qstr::MP_QSTR_prefill_word)?.try_into()?;
        let can_go_back: bool = kwargs.get(Qstr::MP_QSTR_can_go_back)?.try_into()?;

        let layout = ModelUI::request_bip39(prompt, prefill_word, can_go_back)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_request_slip39(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let prompt: TString = kwargs.get(Qstr::MP_QSTR_prompt)?.try_into()?;
        let prefill_word: TString = kwargs.get(Qstr::MP_QSTR_prefill_word)?.try_into()?;
        let can_go_back: bool = kwargs.get(Qstr::MP_QSTR_can_go_back)?.try_into()?;

        let layout = ModelUI::request_slip39(prompt, prefill_word, can_go_back)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_request_number(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let count: u32 = kwargs.get(Qstr::MP_QSTR_count)?.try_into()?;
        let min_count: u32 = kwargs.get(Qstr::MP_QSTR_min_count)?.try_into()?;
        let max_count: u32 = kwargs.get(Qstr::MP_QSTR_max_count)?.try_into()?;
        let description: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_description)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;
        let more_info_callback: Option<Obj> = kwargs
            .get(Qstr::MP_QSTR_more_info_callback)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let more_info_cb = more_info_callback.and_then(|callback| {
            let cb = move |n: u32| {
                let text = callback.call_with_n_args(&[n.try_into().unwrap()]).unwrap();
                TString::try_from(text).unwrap()
            };
            Some(cb)
        });

        let layout = ModelUI::request_number(
            title,
            count,
            min_count,
            max_count,
            description,
            more_info_cb,
        )?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_request_pin(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let prompt: TString = kwargs.get(Qstr::MP_QSTR_prompt)?.try_into()?;
        let subprompt: TString = kwargs.get(Qstr::MP_QSTR_subprompt)?.try_into()?;
        let allow_cancel: bool = kwargs.get_or(Qstr::MP_QSTR_allow_cancel, true)?;
        let warning: bool = kwargs.get_or(Qstr::MP_QSTR_wrong_pin, false)?;

        let layout = ModelUI::request_pin(prompt, subprompt, allow_cancel, warning)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_request_passphrase(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let prompt: TString = kwargs.get(Qstr::MP_QSTR_prompt)?.try_into()?;
        let max_len: u32 = kwargs.get(Qstr::MP_QSTR_max_len)?.try_into()?;

        let layout = ModelUI::request_passphrase(prompt, max_len)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_select_word(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;
        let words_iterable: Obj = kwargs.get(Qstr::MP_QSTR_words)?;
        let words: [TString<'static>; 3] = util::iter_into_array(words_iterable)?;

        let layout = ModelUI::select_word(title, description, words)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_select_word_count(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let recovery_type: RecoveryType = kwargs.get(Qstr::MP_QSTR_recovery_type)?.try_into()?;

        let layout = ModelUI::select_word_count(recovery_type)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_set_brightness(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let current: Option<u8> = kwargs.get(Qstr::MP_QSTR_current)?.try_into_option()?;

        let layout = ModelUI::set_brightness(current)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_checklist(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let button: TString = kwargs.get(Qstr::MP_QSTR_button)?.try_into()?;
        let active: usize = kwargs.get(Qstr::MP_QSTR_active)?.try_into()?;
        let items: Obj = kwargs.get(Qstr::MP_QSTR_items)?;

        let items: [TString<'static>; 3] = util::iter_into_array(items)?;

        let layout = ModelUI::show_checklist(title, button, active, items)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_homescreen(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let label: TString<'static> = kwargs
            .get(Qstr::MP_QSTR_label)?
            .try_into_option()?
            .unwrap_or_else(|| model::FULL_NAME.into());
        let notification: Option<TString<'static>> =
            kwargs.get(Qstr::MP_QSTR_notification)?.try_into_option()?;
        let notification_level: u8 = kwargs.get_or(Qstr::MP_QSTR_notification_level, 0)?;
        let hold: bool = kwargs.get(Qstr::MP_QSTR_hold)?.try_into()?;
        let skip_first_paint: bool = kwargs.get(Qstr::MP_QSTR_skip_first_paint)?.try_into()?;

        let layout = ModelUI::show_homescreen(label, hold, notification, notification_level)?;
        let layout_obj = LayoutObj::new_root(layout)?;
        if skip_first_paint {
            layout_obj.skip_first_paint();
        }
        Ok(layout_obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_info(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;
        let button: TString = kwargs
            .get_or(Qstr::MP_QSTR_button, TString::empty())?
            .try_into()?;
        let time_ms: u32 = kwargs.get_or(Qstr::MP_QSTR_time_ms, 0)?.try_into()?;

        let obj = ModelUI::show_info(title, description, button, time_ms)?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_lockscreen(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let label: TString<'static> = kwargs
            .get(Qstr::MP_QSTR_label)?
            .try_into_option()?
            .unwrap_or_else(|| model::FULL_NAME.into());
        let bootscreen: bool = kwargs.get(Qstr::MP_QSTR_bootscreen)?.try_into()?;
        let coinjoin_authorized: bool = kwargs.get_or(Qstr::MP_QSTR_coinjoin_authorized, false)?;
        let skip_first_paint: bool = kwargs.get(Qstr::MP_QSTR_skip_first_paint)?.try_into()?;

        let layout = ModelUI::show_lockscreen(label, bootscreen, coinjoin_authorized)?;
        let layout_obj = LayoutObj::new_root(layout)?;
        if skip_first_paint {
            layout_obj.skip_first_paint();
        }
        Ok(layout_obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_mismatch(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;

        let layout = ModelUI::show_mismatch(title)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_progress(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let description: TString = kwargs.get(Qstr::MP_QSTR_description)?.try_into()?;
        let indeterminate: bool = kwargs.get_or(Qstr::MP_QSTR_indeterminate, false)?;
        let title: Option<TString> = kwargs
            .get(Qstr::MP_QSTR_title)
            .and_then(Obj::try_into_option)
            .unwrap_or(None);

        let layout = ModelUI::show_progress(description, indeterminate, title)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_progress_coinjoin(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = move |_args: &[Obj], kwargs: &Map| {
        let title: TString = kwargs.get(Qstr::MP_QSTR_title)?.try_into()?;
        let indeterminate: bool = kwargs.get_or(Qstr::MP_QSTR_indeterminate, false)?;
        let time_ms: u32 = kwargs.get_or(Qstr::MP_QSTR_time_ms, 0)?;
        let skip_first_paint: bool = kwargs.get_or(Qstr::MP_QSTR_skip_first_paint, false)?;

        let obj = ModelUI::show_progress_coinjoin(title, indeterminate, time_ms, skip_first_paint)?;
        Ok(obj.into())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

extern "C" fn new_show_wait_text(message: Obj) -> Obj {
    let block = || {
        let message: TString<'static> = message.try_into()?;

        let layout = ModelUI::show_wait_text(message)?;
        Ok(LayoutObj::new_root(layout)?.into())
    };

    unsafe { util::try_or_raise(block) }
}

pub extern "C" fn upy_check_homescreen_format(data: Obj) -> Obj {
    let block = || {
        let buffer = data.try_into()?;
        Ok(ModelUI::check_homescreen_format(buffer, false).into())
    };

    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
pub static mp_module_trezorui_api: Module = obj_module! {
    /// from trezor import utils
    ///
    /// T = TypeVar("T")
    ///
    /// class LayoutObj(Generic[T]):
    ///     """Representation of a Rust-based layout object.
    ///     see `trezor::ui::layout::obj::LayoutObj`.
    ///     """
    ///
    ///     def attach_timer_fn(self, fn: Callable[[int, int], None], attach_type: AttachType | None) -> LayoutState | None:
    ///         """Attach a timer setter function.
    ///
    ///         The layout object can call the timer setter with two arguments,
    ///         `token` and `duration_ms`. When `duration_ms` elapses, the layout object
    ///         expects a callback to `self.timer(token)`.
    ///         """
    ///
    ///     if utils.USE_TOUCH:
    ///         def touch_event(self, event: int, x: int, y: int) -> LayoutState | None:
    ///             """Receive a touch event `event` at coordinates `x`, `y`."""
    ///
    ///     if utils.USE_BUTTON:
    ///         def button_event(self, event: int, button: int) -> LayoutState | None:
    ///             """Receive a button event `event` for button `button`."""
    ///
    ///     def progress_event(self, value: int, description: str) -> LayoutState | None:
    ///         """Receive a progress event."""
    ///
    ///     def usb_event(self, connected: bool) -> LayoutState | None:
    ///         """Receive a USB connect/disconnect event."""
    ///
    ///     def timer(self, token: int) -> LayoutState | None:
    ///         """Callback for the timer set by `attach_timer_fn`.
    ///
    ///         This function should be called by the executor after the corresponding
    ///         duration elapses.
    ///         """
    ///
    ///     def paint(self) -> bool:
    ///         """Paint the layout object on screen.
    ///
    ///         Will only paint updated parts of the layout as required.
    ///         Returns True if any painting actually happened.
    ///         """
    ///
    ///     def request_complete_repaint(self) -> None:
    ///         """Request a complete repaint of the screen.
    ///
    ///         Does not repaint the screen, a subsequent call to `paint()` is required.
    ///         """
    ///
    ///     if __debug__:
    ///         def trace(self, tracer: Callable[[str], None]) -> None:
    ///             """Generate a JSON trace of the layout object.
    ///
    ///             The JSON can be emitted as a sequence of calls to `tracer`, each of
    ///             which is not necessarily a valid JSON chunk. The caller must
    ///             reassemble the chunks to get a sensible result.
    ///             """
    ///
    ///         def bounds(self) -> None:
    ///             """Paint bounds of individual components on screen."""
    ///
    ///     def page_count(self) -> int:
    ///         """Return the number of pages in the layout object."""
    ///
    ///     def button_request(self) -> tuple[int, str] | None:
    ///         """Return (code, type) of button request made during the last event or timer pass."""
    ///
    ///     def get_transition_out(self) -> AttachType:
    ///         """Return the transition type."""
    ///
    ///     def return_value(self) -> T:
    ///         """Retrieve the return value of the layout object."""
    ///
    ///     def __del__(self) -> None:
    ///         """Calls drop on contents of the root component."""
    ///
    /// class UiResult:
    ///    """Result of a UI operation."""
    ///    pass
    ///
    /// mock:global
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorui_api.to_obj(),

    /// CONFIRMED: UiResult
    Qstr::MP_QSTR_CONFIRMED => CONFIRMED.as_obj(),

    /// CANCELLED: UiResult
    Qstr::MP_QSTR_CANCELLED => CANCELLED.as_obj(),

    /// INFO: UiResult
    Qstr::MP_QSTR_INFO => INFO.as_obj(),

    /// def check_homescreen_format(data: bytes) -> bool:
    ///     """Check homescreen format and dimensions."""
    Qstr::MP_QSTR_check_homescreen_format => obj_fn_1!(upy_check_homescreen_format).as_obj(),

    /// def disable_animation(disable: bool) -> None:
    ///     """Disable animations, debug builds only."""
    Qstr::MP_QSTR_disable_animation => obj_fn_1!(upy_disable_animation).as_obj(),

    /// def confirm_action(
    ///     *,
    ///     title: str,
    ///     action: str | None,
    ///     description: str | None,
    ///     subtitle: str | None = None,
    ///     verb: str | None = None,
    ///     verb_cancel: str | None = None,
    ///     hold: bool = False,
    ///     hold_danger: bool = False,
    ///     reverse: bool = False,
    ///     prompt_screen: bool = False,
    ///     prompt_title: str | None = None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm action."""
    Qstr::MP_QSTR_confirm_action => obj_fn_kw!(0, new_confirm_action).as_obj(),

    /// def confirm_firmware_update(
    ///     *,
    ///     description: str,
    ///     fingerprint: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Ask whether to update firmware, optionally show fingerprint."""
    Qstr::MP_QSTR_confirm_firmware_update => obj_fn_kw!(0, new_confirm_firmware_update).as_obj(),

    /// def confirm_homescreen(
    ///     *,
    ///     title: str,
    ///     image: bytes,
    /// ) -> LayoutObj[UiResult]:
    ///     """Confirm homescreen."""
    Qstr::MP_QSTR_confirm_homescreen => obj_fn_kw!(0, new_confirm_homescreen).as_obj(),

    /// def confirm_reset_device(recovery: bool) -> LayoutObj[UiResult]:
    ///     """Confirm TOS before creating wallet creation or wallet recovery."""
    Qstr::MP_QSTR_confirm_reset_device => obj_fn_kw!(0, new_confirm_reset_device).as_obj(),

    /// def request_bip39(
    ///     *,
    ///     prompt: str,
    ///     prefill_word: str,
    ///     can_go_back: bool,
    /// ) -> LayoutObj[str]:
    ///     """BIP39 word input keyboard."""
    Qstr::MP_QSTR_request_bip39 => obj_fn_kw!(0, new_request_bip39).as_obj(),

    /// def request_slip39(
    ///     *,
    ///     prompt: str,
    ///     prefill_word: str,
    ///     can_go_back: bool,
    /// ) -> LayoutObj[str]:
    ///    """SLIP39 word input keyboard."""
    Qstr::MP_QSTR_request_slip39 => obj_fn_kw!(0, new_request_slip39).as_obj(),

    /// def request_number(
    ///     *,
    ///     title: str,
    ///     count: int,
    ///     min_count: int,
    ///     max_count: int,
    ///     description: str | None = None,
    ///     more_info_callback: Callable[[int], str] | None = None,
    /// ) -> LayoutObj[tuple[UiResult, int]]:
    ///     """Number input with + and - buttons, optional static description and optional dynamic
    ///     description."""
    Qstr::MP_QSTR_request_number => obj_fn_kw!(0, new_request_number).as_obj(),

    /// def request_pin(
    ///     *,
    ///     prompt: str,
    ///     subprompt: str,
    ///     allow_cancel: bool = True,
    ///     wrong_pin: bool = False,
    /// ) -> LayoutObj[str | UiResult]:
    ///     """Request pin on device."""
    Qstr::MP_QSTR_request_pin => obj_fn_kw!(0, new_request_pin).as_obj(),

    /// def request_passphrase(
    ///     *,
    ///     prompt: str,
    ///     max_len: int,
    /// ) -> LayoutObj[str | UiResult]:
    ///     """Passphrase input keyboard."""
    Qstr::MP_QSTR_request_passphrase => obj_fn_kw!(0, new_request_passphrase).as_obj(),

    /// def select_word(
    ///     *,
    ///     title: str,
    ///     description: str,
    ///     words: Iterable[str],
    /// ) -> LayoutObj[int]:
    ///     """Select mnemonic word from three possibilities - seed check after backup. The
    ///    iterable must be of exact size. Returns index in range `0..3`."""
    Qstr::MP_QSTR_select_word => obj_fn_kw!(0, new_select_word).as_obj(),

    /// def select_word_count(
    ///     *,
    ///     recovery_type: RecoveryType,
    /// ) -> LayoutObj[int | str]:  # TR returns str
    ///     """Select a mnemonic word count from the options: 12, 18, 20, 24, or 33.
    ///     For unlocking a repeated backup, select from 20 or 33."""
    Qstr::MP_QSTR_select_word_count => obj_fn_kw!(0, new_select_word_count).as_obj(),

    /// def set_brightness(
    ///     *,
    ///     current: int | None = None
    /// ) -> LayoutObj[UiResult]:
    ///     """Show the brightness configuration dialog."""
    Qstr::MP_QSTR_set_brightness => obj_fn_kw!(0, new_set_brightness).as_obj(),

    /// def show_checklist(
    ///     *,
    ///     title: str,
    ///     items: Iterable[str],
    ///     active: int,
    ///     button: str,
    /// ) -> LayoutObj[UiResult]:
    ///     """Checklist of backup steps. Active index is highlighted, previous items have check
    ///    mark next to them. Limited to 3 items."""
    Qstr::MP_QSTR_show_checklist => obj_fn_kw!(0, new_show_checklist).as_obj(),

    /// def show_homescreen(
    ///     *,
    ///     label: str | None,
    ///     hold: bool,
    ///     notification: str | None,
    ///     notification_level: int = 0,
    ///     skip_first_paint: bool,
    /// ) -> LayoutObj[UiResult]:
    ///     """Idle homescreen."""
    Qstr::MP_QSTR_show_homescreen => obj_fn_kw!(0, new_show_homescreen).as_obj(),

    /// def show_info(
    ///     *,
    ///     title: str,
    ///     description: str = "",
    ///     button: str = "",
    ///     time_ms: int = 0,
    /// ) -> LayoutObj[UiResult]:
    ///     """Info screen."""
    Qstr::MP_QSTR_show_info => obj_fn_kw!(0, new_show_info).as_obj(),

    /// def show_lockscreen(
    ///     *,
    ///     label: str | None,
    ///     bootscreen: bool,
    ///     skip_first_paint: bool,
    ///     coinjoin_authorized: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Homescreen for locked device."""
    Qstr::MP_QSTR_show_lockscreen => obj_fn_kw!(0, new_show_lockscreen).as_obj(),

    /// def show_mismatch(*, title: str) -> LayoutObj[UiResult]:
    ///     """Warning of receiving address mismatch."""
    Qstr::MP_QSTR_show_mismatch => obj_fn_kw!(0, new_show_mismatch).as_obj(),

    /// def show_progress(
    ///     *,
    ///     description: str,
    ///     indeterminate: bool = False,
    ///     title: str | None = None,
    /// ) -> LayoutObj[UiResult]:
    ///     """Show progress loader. Please note that the number of lines reserved on screen for
    ///    description is determined at construction time. If you want multiline descriptions
    ///    make sure the initial description has at least that amount of lines."""
    Qstr::MP_QSTR_show_progress => obj_fn_kw!(0, new_show_progress).as_obj(),

    /// def show_progress_coinjoin(
    ///     *,
    ///     title: str,
    ///     indeterminate: bool = False,
    ///     time_ms: int = 0,
    ///     skip_first_paint: bool = False,
    /// ) -> LayoutObj[UiResult]:
    ///     """Show progress loader for coinjoin. Returns CANCELLED after a specified time when
    ///    time_ms timeout is passed."""
    Qstr::MP_QSTR_show_progress_coinjoin => obj_fn_kw!(0, new_show_progress_coinjoin).as_obj(),

    /// def show_wait_text(message: str, /) -> LayoutObj[None]:
    ///     """Show single-line text in the middle of the screen."""
    Qstr::MP_QSTR_show_wait_text => obj_fn_1!(new_show_wait_text).as_obj(),

    /// class BacklightLevels:
    ///     """Backlight levels. Values dynamically update based on user settings."""
    ///     MAX: ClassVar[int]
    ///     NORMAL: ClassVar[int]
    ///     LOW: ClassVar[int]
    ///     DIM: ClassVar[int]
    ///     NONE: ClassVar[int]
    ///
    /// mock:global
    Qstr::MP_QSTR_BacklightLevels => BACKLIGHT_LEVELS_OBJ.as_obj(),

    /// class AttachType:
    ///     INITIAL: ClassVar[int]
    ///     RESUME: ClassVar[int]
    ///     SWIPE_UP: ClassVar[int]
    ///     SWIPE_DOWN: ClassVar[int]
    ///     SWIPE_LEFT: ClassVar[int]
    ///     SWIPE_RIGHT: ClassVar[int]
    Qstr::MP_QSTR_AttachType => ATTACH_TYPE_OBJ.as_obj(),

    /// class LayoutState:
    ///     """Layout state."""
    ///     INITIAL: "ClassVar[LayoutState]"
    ///     ATTACHED: "ClassVar[LayoutState]"
    ///     TRANSITIONING: "ClassVar[LayoutState]"
    ///     DONE: "ClassVar[LayoutState]"
    Qstr::MP_QSTR_LayoutState => LAYOUT_STATE.as_obj(),

};
