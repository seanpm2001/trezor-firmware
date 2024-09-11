from __future__ import annotations

from .. import get_hw_model_as_number


def configure(
    env: dict,
    features_wanted: list[str],
    defines: list[str | tuple[str, str]],
    sources: list[str],
    paths: list[str],
) -> list[str]:

    features_available: list[str] = []
    board = "T3T1/boards/t3t1-unix.h"
    hw_model = get_hw_model_as_number("T3T1")
    hw_revision = 0
    mcu = "STM32U585xx"

    defines += ["FRAMEBUFFER", "DISPLAY_RGB565"]
    features_available.append("framebuffer")
    features_available.append("display_rgb565")
    defines += [("USE_RGB_COLORS", "1")]

    defines += [
        mcu,
        ("TREZOR_BOARD", f'"{board}"'),
        ("HW_MODEL", str(hw_model)),
        ("HW_REVISION", str(hw_revision)),
        ("MCU_TYPE", mcu),
        # todo change to blockwise flash when implemented in unix
        ("FLASH_BIT_ACCESS", "1"),
        ("FLASH_BLOCK_WORDS", "1"),
    ]

    if "sd_card" in features_wanted:
        features_available.append("sd_card")
        sources += [
            "embed/io/sdcard/unix/sdcard.c",
            "embed/upymod/modtrezorio/ff.c",
            "embed/upymod/modtrezorio/ffunicode.c",
        ]
        paths += ["embed/io/sdcard/inc"]
        defines += [("USE_SD_CARD", "1")]

    if "sbu" in features_wanted:
        sources += ["embed/io/sbu/unix/sbu.c"]
        paths += ["embed/io/sbu/inc"]
        defines += [("USE_SBU", "1")]

    if "optiga" in features_wanted:
        sources += ["embed/sec/optiga/unix/optiga_hal.c"]
        sources += ["embed/sec/optiga/unix/optiga.c"]
        paths += ["embed/sec/optiga/inc"]
        features_available.append("optiga")
        defines += [("USE_OPTIGA", "1")]

    if "tropic" in features_wanted:
        sources += [
            "vendor/libtropic/src/libtropic.c",
            "vendor/libtropic/src/lt_crc16.c",
            "vendor/libtropic/src/lt_hkdf.c",
            "vendor/libtropic/src/lt_l1.c",
            "vendor/libtropic/src/lt_l1_port_wrap.c",
            "vendor/libtropic/src/lt_l2.c",
            "vendor/libtropic/src/lt_l2_frame_check.c",
            "vendor/libtropic/src/lt_l3.c",
            "vendor/libtropic/src/lt_random.c",
            "vendor/libtropic/hal/port/unix/lt_port_unix.c",
            "vendor/libtropic/hal/crypto/trezor_crypto/lt_crypto_trezor_aesgcm.c",
            "vendor/libtropic/hal/crypto/trezor_crypto/lt_crypto_trezor_ed25519.c",
            "vendor/libtropic/hal/crypto/trezor_crypto/lt_crypto_trezor_sha256.c",
            "vendor/libtropic/hal/crypto/trezor_crypto/lt_crypto_trezor_x25519.c",
        ]
        defines += ["USE_TREZOR_CRYPTO"]
        features_available.append("tropic")
    defines += ["USE_TROPIC=1"]

    if "input" in features_wanted:
        sources += ["embed/io/touch/unix/touch.c"]
        paths += ["embed/io/touch/inc"]
        features_available.append("touch")
        defines += [("USE_TOUCH", "1")]

    features_available.append("backlight")
    defines += [("USE_BACKLIGHT", "1")]

    sources += ["embed/util/flash/stm32u5/flash_layout.c"]

    return features_available
