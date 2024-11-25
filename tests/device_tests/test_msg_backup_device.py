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
import shamir_mnemonic as shamir

from trezorlib import device, messages
from trezorlib.debuglink import LayoutType
from trezorlib.debuglink import SessionDebugWrapper as Session
from trezorlib.exceptions import TrezorFailure

from ..common import (
    MNEMONIC12,
    MNEMONIC_SLIP39_ADVANCED_20,
    MNEMONIC_SLIP39_CUSTOM_SECRET,
    MNEMONIC_SLIP39_BASIC_20_3of6,
    MNEMONIC_SLIP39_CUSTOM_1of1,
)
from ..input_flows import (
    InputFlowBip39Backup,
    InputFlowSlip39AdvancedBackup,
    InputFlowSlip39BasicBackup,
    InputFlowSlip39CustomBackup,
)


@pytest.mark.models("core")  # TODO we want this for t1 too
@pytest.mark.setup_client(needs_backup=True, mnemonic=MNEMONIC12)
def test_backup_bip39(session: Session):
    assert session.features.backup_availability == messages.BackupAvailability.Required

    with session.client as client:
        IF = InputFlowBip39Backup(client)
        client.set_input_flow(IF.get())
        device.backup(session)

    assert IF.mnemonic == MNEMONIC12
    # TODO remove session.init_device()
    assert session.features.initialized is True
    assert (
        session.features.backup_availability == messages.BackupAvailability.NotAvailable
    )
    assert session.features.unfinished_backup is False
    assert session.features.no_backup is False
    assert session.features.backup_type is messages.BackupType.Bip39


@pytest.mark.models("core")
@pytest.mark.setup_client(needs_backup=True, mnemonic=MNEMONIC_SLIP39_BASIC_20_3of6)
@pytest.mark.parametrize(
    "click_info", [True, False], ids=["click_info", "no_click_info"]
)
def test_backup_slip39_basic(session: Session, click_info: bool):
    if click_info and session.client.layout_type is LayoutType.TR:
        pytest.skip("click_info not implemented on T2B1")

    assert session.features.backup_availability == messages.BackupAvailability.Required

    with session.client as client:
        IF = InputFlowSlip39BasicBackup(client, click_info)
        client.set_input_flow(IF.get())
        device.backup(session)

    # TODO remove session.init_device()
    assert session.features.initialized is True
    assert (
        session.features.backup_availability == messages.BackupAvailability.NotAvailable
    )
    assert session.features.unfinished_backup is False
    assert session.features.no_backup is False
    assert session.features.backup_type is messages.BackupType.Slip39_Basic

    expected_ms = shamir.combine_mnemonics(MNEMONIC_SLIP39_BASIC_20_3of6)
    actual_ms = shamir.combine_mnemonics(IF.mnemonics[:3])
    assert expected_ms == actual_ms


@pytest.mark.models("core")
@pytest.mark.setup_client(needs_backup=True, mnemonic=MNEMONIC_SLIP39_ADVANCED_20)
@pytest.mark.parametrize(
    "click_info", [True, False], ids=["click_info", "no_click_info"]
)
def test_backup_slip39_advanced(session: Session, click_info: bool):
    if click_info and session.client.layout_type is LayoutType.TR:
        pytest.skip("click_info not implemented on T2B1")

    assert session.features.backup_availability == messages.BackupAvailability.Required

    with session.client as client:
        IF = InputFlowSlip39AdvancedBackup(client, click_info)
        client.set_input_flow(IF.get())
        device.backup(session)

    # TODO remove session.init_device()
    assert session.features.initialized is True
    assert (
        session.features.backup_availability == messages.BackupAvailability.NotAvailable
    )
    assert session.features.unfinished_backup is False
    assert session.features.no_backup is False
    assert session.features.backup_type is messages.BackupType.Slip39_Advanced

    expected_ms = shamir.combine_mnemonics(MNEMONIC_SLIP39_ADVANCED_20)
    actual_ms = shamir.combine_mnemonics(
        IF.mnemonics[:3] + IF.mnemonics[5:8] + IF.mnemonics[10:13]
    )
    assert expected_ms == actual_ms


@pytest.mark.models("core")
@pytest.mark.setup_client(needs_backup=True, mnemonic=MNEMONIC_SLIP39_CUSTOM_1of1[0])
@pytest.mark.parametrize(
    "share_threshold,share_count",
    [(1, 1), (2, 2), (3, 5)],
    ids=["1_of_1", "2_of_2", "3_of_5"],
)
def test_backup_slip39_custom(session: Session, share_threshold, share_count):
    assert session.features.backup_availability == messages.BackupAvailability.Required

    with session.client as client:
        IF = InputFlowSlip39CustomBackup(client, share_count)
        client.set_input_flow(IF.get())
        device.backup(
            session, group_threshold=1, groups=[(share_threshold, share_count)]
        )

    # TODO remove session.init_device()
    assert session.features.initialized is True
    assert (
        session.features.backup_availability == messages.BackupAvailability.NotAvailable
    )
    assert session.features.unfinished_backup is False
    assert session.features.no_backup is False

    assert len(IF.mnemonics) == share_count
    assert (
        shamir.combine_mnemonics(IF.mnemonics[-share_threshold:]).hex()
        == MNEMONIC_SLIP39_CUSTOM_SECRET
    )


# we only test this with bip39 because the code path is always the same
@pytest.mark.setup_client(no_backup=True)
def test_no_backup_fails(session: Session):
    # TODO ?? session.ensure_unlocked()
    assert session.features.initialized is True
    assert session.features.no_backup is True
    assert (
        session.features.backup_availability == messages.BackupAvailability.NotAvailable
    )

    # backup attempt should fail because no_backup=True
    with pytest.raises(TrezorFailure, match=r".*Seed already backed up"):
        device.backup(session)


# we only test this with bip39 because the code path is always the same
@pytest.mark.setup_client(needs_backup=True)
def test_interrupt_backup_fails(session: Session):
    session.ensure_unlocked()
    assert session.features.initialized is True
    assert session.features.backup_availability == messages.BackupAvailability.Required
    assert session.features.unfinished_backup is False
    assert session.features.no_backup is False

    # start backup
    session.call_raw(messages.BackupDevice())

    # interupt backup by sending initialize
    session2 = session.client.resume_session(session)
    session2.refresh_features()

    # check that device state is as expected
    assert session2.features.initialized is True
    assert (
        session2.features.backup_availability
        == messages.BackupAvailability.NotAvailable
    )
    assert session2.features.unfinished_backup is True
    assert session2.features.no_backup is False

    # Second attempt at backup should fail
    with pytest.raises(TrezorFailure, match=r".*Seed already backed up"):
        device.backup(session2)
