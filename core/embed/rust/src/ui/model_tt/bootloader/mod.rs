use heapless::String;

use crate::{
    strutil::hexlify,
    trezorhal::secbool::secbool,
    ui::{
        component::{connect::Connect, Label},
        constant::HEIGHT,
        display::{self, Color, Font, Icon},
        geometry::Point,
        util::{from_c_array, from_c_str},
    },
};

use super::{
    bootloader::welcome::Welcome,
    component::{
        bl_confirm::{Confirm, ConfirmTitle},
        Button, ResultScreen, WelcomeScreen,
    },
    constant,
    theme::{
        bootloader::{
            button_bld, button_bld_menu, button_confirm, button_wipe_cancel, button_wipe_confirm,
            BLD_BG, BLD_FG, BLD_TITLE_COLOR, BLD_WIPE_COLOR, CHECK24, CHECK40, DOWNLOAD32, FIRE32,
            FIRE40, RESULT_FW_INSTALL, RESULT_INITIAL, RESULT_WIPE, TEXT_BOLD, TEXT_NORMAL,
            TEXT_WIPE_BOLD, TEXT_WIPE_NORMAL, WARNING40, WELCOME_COLOR, X24,
        },
        BACKLIGHT_NORMAL, BLACK, FG, WHITE,
    },
};

use crate::ui::layout::simplified::{fadein, fadeout, run, show};
use intro::Intro;
use menu::Menu;

pub mod intro;
pub mod menu;
pub mod welcome;

pub type BootloaderString = String<128>;

const RECONNECT_MESSAGE: &str = "PLEASE RECONNECT\nTHE DEVICE";

#[no_mangle]
extern "C" fn screen_install_confirm(
    vendor_str: *const cty::c_char,
    vendor_str_len: u8,
    version: *const cty::c_char,
    fingerprint: *const cty::uint8_t,
    should_keep_seed: bool,
    is_newvendor: bool,
    version_cmp: cty::c_int,
) -> u32 {
    let text = unwrap!(unsafe { from_c_array(vendor_str, vendor_str_len as usize) });
    let version = unwrap!(unsafe { from_c_str(version) });

    let mut fingerprint_buffer: [u8; 64] = [0; 64];
    let fingerprint_str = unsafe {
        let fingerprint_slice = core::slice::from_raw_parts(fingerprint, 32);
        hexlify(fingerprint_slice, &mut fingerprint_buffer);
        core::str::from_utf8_unchecked(fingerprint_buffer.as_ref())
    };

    let mut version_str: BootloaderString = String::new();
    unwrap!(version_str.push_str("Firmware version "));
    unwrap!(version_str.push_str(version));
    unwrap!(version_str.push_str("\nby "));
    unwrap!(version_str.push_str(text));

    let title_str = if is_newvendor {
        "CHANGE FW\nVENDOR"
    } else if version_cmp > 0 {
        "UPDATE FIRMWARE"
    } else if version_cmp == 0 {
        "REINSTALL FW"
    } else {
        "DOWNGRADE FW"
    };
    let title = Label::left_aligned(title_str.into(), TEXT_BOLD).vertically_centered();
    let msg = Label::left_aligned(version_str.as_str().into(), TEXT_NORMAL);
    let alert = (!should_keep_seed).then_some(Label::left_aligned(
        "SEED WILL BE ERASED!".into(),
        TEXT_BOLD,
    ));

    let (left, right) = if should_keep_seed {
        let l = Button::with_text("CANCEL".into()).styled(button_bld());
        let r = Button::with_text("INSTALL".into()).styled(button_confirm());
        (l, r)
    } else {
        let l = Button::with_icon(Icon::new(X24)).styled(button_bld());
        let r = Button::with_icon(Icon::new(CHECK24)).styled(button_confirm());
        (l, r)
    };

    let mut frame = Confirm::new(BLD_BG, left, right, ConfirmTitle::Text(title), msg).with_info(
        "FW FINGERPRINT".into(),
        fingerprint_str.into(),
        button_bld_menu(),
    );

    if let Some(alert) = alert {
        frame = frame.with_alert(alert);
    }

    run(&mut frame)
}

#[no_mangle]
extern "C" fn screen_wipe_confirm() -> u32 {
    let icon = Icon::new(FIRE40);

    let msg = Label::centered(
        "Are you sure you want to factory reset the device?".into(),
        TEXT_WIPE_NORMAL,
    );
    let alert = Label::centered("SEED AND FIRMWARE\nWILL BE ERASED!".into(), TEXT_WIPE_BOLD);

    let right = Button::with_text("RESET".into()).styled(button_wipe_confirm());
    let left = Button::with_text("CANCEL".into()).styled(button_wipe_cancel());

    let mut frame =
        Confirm::new(BLD_WIPE_COLOR, left, right, ConfirmTitle::Icon(icon), msg).with_alert(alert);

    run(&mut frame)
}

#[no_mangle]
extern "C" fn screen_menu(firmware_present: secbool) -> u32 {
    run(&mut Menu::new(firmware_present))
}

#[no_mangle]
extern "C" fn screen_intro(
    bld_version: *const cty::c_char,
    vendor_str: *const cty::c_char,
    vendor_str_len: u8,
    version: *const cty::c_char,
    fw_ok: bool,
) -> u32 {
    let vendor = unwrap!(unsafe { from_c_array(vendor_str, vendor_str_len as usize) });
    let version = unwrap!(unsafe { from_c_str(version) });
    let bld_version = unwrap!(unsafe { from_c_str(bld_version) });

    let mut title_str: BootloaderString = String::new();
    unwrap!(title_str.push_str("BOOTLOADER "));
    unwrap!(title_str.push_str(bld_version));

    let mut version_str: BootloaderString = String::new();
    unwrap!(version_str.push_str("Firmware version "));
    unwrap!(version_str.push_str(version));
    unwrap!(version_str.push_str("\nby "));
    unwrap!(version_str.push_str(vendor));

    let mut frame = Intro::new(
        title_str.as_str().into(),
        version_str.as_str().into(),
        fw_ok,
    );

    run(&mut frame)
}

fn screen_progress(
    text: &str,
    progress: u16,
    initialize: bool,
    fg_color: Color,
    bg_color: Color,
    icon: Option<(Icon, Color)>,
) {
    if initialize {
        fadeout();
        display::rect_fill(constant::screen(), bg_color);
    }

    display::text_center(
        Point::new(constant::WIDTH / 2, HEIGHT - 45),
        text,
        Font::NORMAL,
        fg_color,
        bg_color,
    );
    display::loader(progress, -20, fg_color, bg_color, icon);
    display::refresh();
    if initialize {
        fadein();
    }
}

#[no_mangle]
extern "C" fn screen_install_progress(progress: u16, initialize: bool, initial_setup: bool) {
    let bg_color = if initial_setup { WELCOME_COLOR } else { BLD_BG };
    let fg_color = if initial_setup { FG } else { BLD_FG };

    screen_progress(
        "Installing firmware",
        progress,
        initialize,
        fg_color,
        bg_color,
        Some((Icon::new(DOWNLOAD32), fg_color)),
    )
}

#[no_mangle]
extern "C" fn screen_wipe_progress(progress: u16, initialize: bool) {
    screen_progress(
        "Resetting Trezor",
        progress,
        initialize,
        BLD_FG,
        BLD_WIPE_COLOR,
        Some((Icon::new(FIRE32), BLD_FG)),
    )
}

#[no_mangle]
extern "C" fn screen_connect(initial_setup: bool) {
    let bg = if initial_setup { WELCOME_COLOR } else { BLD_BG };
    let mut frame = Connect::new("Waiting for host...", BLD_TITLE_COLOR, bg);
    show(&mut frame, true);
}

#[no_mangle]
extern "C" fn screen_wipe_success() {
    let mut frame = ResultScreen::new(
        &RESULT_WIPE,
        Icon::new(CHECK40),
        "Trezor reset\nsuccessfully".into(),
        Label::centered(RECONNECT_MESSAGE.into(), RESULT_WIPE.title_style()).vertically_centered(),
        true,
    );
    show(&mut frame, true);
}

#[no_mangle]
extern "C" fn screen_wipe_fail() {
    let mut frame = ResultScreen::new(
        &RESULT_WIPE,
        Icon::new(WARNING40),
        "Trezor reset was\nnot successful".into(),
        Label::centered(RECONNECT_MESSAGE.into(), RESULT_WIPE.title_style()).vertically_centered(),
        true,
    );
    show(&mut frame, true);
}

#[no_mangle]
extern "C" fn screen_boot_empty(fading: bool) {
    if fading {
        fadeout();
    }

    display::rect_fill(constant::screen(), BLACK);

    let mut frame = WelcomeScreen::new(true);
    show(&mut frame, false);

    if fading {
        fadein();
    } else {
        display::set_backlight(BACKLIGHT_NORMAL);
    }
    display::refresh();
}

#[no_mangle]
extern "C" fn screen_install_fail() {
    let mut frame = ResultScreen::new(
        &RESULT_FW_INSTALL,
        Icon::new(WARNING40),
        "Firmware installation was not successful".into(),
        Label::centered(RECONNECT_MESSAGE.into(), RESULT_FW_INSTALL.title_style())
            .vertically_centered(),
        true,
    );
    show(&mut frame, true);
}

fn screen_install_success_bld(msg: &str, complete_draw: bool) {
    let mut frame = ResultScreen::new(
        &RESULT_FW_INSTALL,
        Icon::new(CHECK40),
        "Firmware installed\nsuccessfully".into(),
        Label::centered(msg.into(), RESULT_FW_INSTALL.title_style()).vertically_centered(),
        complete_draw,
    );
    show(&mut frame, complete_draw);
}

fn screen_install_success_initial(msg: &str, complete_draw: bool) {
    let mut frame = ResultScreen::new(
        &RESULT_INITIAL,
        Icon::new(CHECK40),
        "Firmware installed\nsuccessfully".into(),
        Label::centered(msg.into(), RESULT_INITIAL.title_style()).vertically_centered(),
        complete_draw,
    );
    show(&mut frame, complete_draw);
}

#[no_mangle]
extern "C" fn screen_install_success(
    restart_seconds: u8,
    initial_setup: bool,
    complete_draw: bool,
) {
    let mut reboot_msg = BootloaderString::new();

    if restart_seconds >= 1 {
        unwrap!(reboot_msg.push_str("RESTARTING IN "));
        // in practice, restart_seconds is 5 or less so this is fine
        let seconds_char = b'0' + restart_seconds % 10;
        unwrap!(reboot_msg.push(seconds_char as char));
    } else {
        unwrap!(reboot_msg.push_str(RECONNECT_MESSAGE));
    }

    if initial_setup {
        screen_install_success_initial(reboot_msg.as_str(), complete_draw)
    } else {
        screen_install_success_bld(reboot_msg.as_str(), complete_draw)
    }
    display::refresh();
}

#[no_mangle]
extern "C" fn screen_welcome() {
    let mut frame = Welcome::new();
    show(&mut frame, true);
}

#[no_mangle]
extern "C" fn bld_continue_label(bg_color: cty::uint16_t) {
    display::text_center(
        Point::new(constant::WIDTH / 2, HEIGHT - 5),
        "click to continue ...",
        Font::NORMAL,
        WHITE,
        Color::from_u16(bg_color),
    );
}
