# This file is part of the Trezor project.
#
# Copyright (C) 2012-2024 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from typing import TYPE_CHECKING

import pytest

from trezorlib import device, messages
from trezorlib.debuglink import LayoutType

from .. import translations as TR
from ..common import EXTERNAL_ENTROPY, WITH_MOCK_URANDOM, generate_entropy
from . import reset

if TYPE_CHECKING:
    from ..device_handler import BackgroundDeviceHandler


pytestmark = pytest.mark.models("core")


@pytest.mark.parametrize(
    "group_threshold, share_threshold, share_count",
    [
        pytest.param(1, 1, 1, id="1of1"),
        pytest.param(1, 2, 3, id="2of3"),
        pytest.param(1, 5, 5, id="5of5"),
    ],
)
@pytest.mark.setup_client(uninitialized=True)
@WITH_MOCK_URANDOM
def test_backup_slip39_custom(
    device_handler: "BackgroundDeviceHandler",
    group_threshold: int,
    share_threshold: int,
    share_count: int,
):
    features = device_handler.features()
    debug = device_handler.debuglink()

    assert features.initialized is False

    device_handler.run(
        device.reset,
        strength=128,
        backup_type=messages.BackupType.Slip39_Basic,
        pin_protection=False,
    )

    # confirm new wallet
    reset.confirm_new_wallet(debug)

    # cancel back up
    reset.cancel_backup(debug, confirm=True)

    assert device_handler.result() == "Initialized"

    device_handler.run(
        device.backup,
        group_threshold=group_threshold,
        groups=[(share_threshold, share_count)],
    )

    # confirm backup configuration
    if share_count > 1:
        TR.assert_template(
            debug.read_layout().text_content(),
            "reset__create_x_of_y_multi_share_backup_template",
        )
    else:
        TR.assert_template(
            debug.read_layout().text_content(), "backup__info_single_share_backup"
        )
    reset.confirm_read(debug)

    # confirm backup intro
    TR.assert_in(debug.read_layout().text_content(), "reset__never_make_digital_copy")
    reset.confirm_read(debug, middle_r=True)

    all_words: list[str] = []
    for _ in range(share_count):
        # read words
        words = reset.read_words(debug)

        # confirm words
        reset.confirm_words(debug, words)

        # confirm share checked
        reset.confirm_read(debug)

        all_words.append(" ".join(words))

    # confirm backup done
    if debug.layout_type is LayoutType.Mercury and share_count > 1:
        reset.confirm_read(debug)
    elif debug.layout_type is not LayoutType.Mercury:
        reset.confirm_read(debug)

    # generate secret locally
    internal_entropy = debug.state().reset_entropy
    assert internal_entropy is not None
    secret = generate_entropy(128, internal_entropy, EXTERNAL_ENTROPY)

    # validate that all combinations will result in the correct master secret
    reset.validate_mnemonics(all_words[:share_threshold], secret)

    assert device_handler.result() == "Seed successfully backed up"
    features = device_handler.features()
    assert features.initialized is True
    assert features.backup_availability == messages.BackupAvailability.NotAvailable
    assert features.pin_protection is False
    assert features.passphrase_protection is False
    assert features.backup_type is messages.BackupType.Slip39_Basic_Extendable
