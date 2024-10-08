# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
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

import pytest

from trezorlib import debuglink, device
from trezorlib.debuglink import SessionDebugWrapper as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.messages import SdProtectOperationType as Op

from ..common import MNEMONIC12

pytestmark = [pytest.mark.skip_t1b1, pytest.mark.skip_t2b1, pytest.mark.sd_card]


def test_enable_disable(session: Session):
    assert session.features.sd_protection is False
    # Disabling SD protection should fail
    with pytest.raises(TrezorFailure):
        device.sd_protect(session, Op.DISABLE)

    # Enable SD protection
    device.sd_protect(session, Op.ENABLE)
    assert session.features.sd_protection is True

    # Enabling SD protection should fail
    with pytest.raises(TrezorFailure):
        device.sd_protect(session, Op.ENABLE)
    assert session.features.sd_protection is True

    # Disable SD protection
    device.sd_protect(session, Op.DISABLE)
    assert session.features.sd_protection is False


def test_refresh(session: Session):
    assert session.features.sd_protection is False
    # Enable SD protection
    device.sd_protect(session, Op.ENABLE)
    assert session.features.sd_protection is True

    # Refresh SD protection
    device.sd_protect(session, Op.REFRESH)
    assert session.features.sd_protection is True

    # Disable SD protection
    device.sd_protect(session, Op.DISABLE)
    assert session.features.sd_protection is False

    # Refreshing SD protection should fail
    with pytest.raises(TrezorFailure):
        device.sd_protect(session, Op.REFRESH)
    assert session.features.sd_protection is False


def test_wipe(session: Session):
    # Enable SD protection
    device.sd_protect(session, Op.ENABLE)
    assert session.features.sd_protection is True

    # Wipe device (this wipes internal storage)
    raise Exception("TEST FAILS AFTER WIPE DEVICE")
    device.wipe(session)
    assert session.features.sd_protection is False

    # Restore device to working status
    debuglink.load_device(
        session,
        mnemonic=MNEMONIC12,
        pin=None,
        passphrase_protection=False,
        label="test",
    )
    assert session.features.sd_protection is False

    # Enable SD protection
    device.sd_protect(session, Op.ENABLE)
    assert session.features.sd_protection is True

    # Refresh SD protection
    device.sd_protect(session, Op.REFRESH)
