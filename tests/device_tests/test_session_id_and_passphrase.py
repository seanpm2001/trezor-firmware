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

import random

import pytest

from trezorlib import device, exceptions, messages
from trezorlib.debuglink import LayoutType
from trezorlib.debuglink import TrezorClientDebugLink as Client
from trezorlib.debuglink import SessionDebugWrapper as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.messages import FailureType, SafetyCheckLevel
from trezorlib.tools import parse_path

from .. import translations as TR

XPUB_PASSPHRASES = {
    "A": "xpub6CekxGcnqnJ6osfY4Rrq7W5ogFtR54KUvz4H16XzaQuukMFZCGebEpVznfq4yFcKEmYyShwj2UKjL7CazuNSuhdkofF4mHabHkLxCMVvsqG",
    "B": "xpub6CFxuyQpgryoR64QC38w42dLgDv5P4qWXhn1fbaN62UYzu1wJXZyrYqGnkq5d8xPUK68RXtXFBiqp3rfLGpeQ57zLtx675ZZn5ezKMAWQfu",
    "C": "xpub6BhJMNFwCjGKyRb9RUcnuHhJ2TgcnurfUrQszrmZ1rg8aadsMXLySF6LY3qf4pR7bY4vwpd1VwLPQvuCRr7BPTs8wvqrv2gexxViwj96czT",
    "D": "xpub6DK1vnTBe9EkhLACJRvovv8RSUC3MSiEV64opM7XUqrowxQ8J5C2WpA6n4vt5LS3bs618aKzi7k5w7VzNCv3SfqEeSepvvHaPhRoTvRqR5u",
    "E": "xpub6CqbQjHN7r68GHh7RsiAyrdAmyiZQgWvDxQtba2NxZHumvfMK31U6emVQSexYrTAHWQeLygRD1yXZQLsCs1LLJtaeSxMAnh2YUmP3ov6EQz",
    "F": "xpub6CRDxB1aHVNHfqjPeYhnPBhBfkQb4b4K581uYKxwv4KnkiVsRttBCXSkZM5jtP1Vv2v3wr5FxfzqWWDApLCbutBLnfwYpkWpZUmZSp6hqg5",
    "G": "xpub6DGKmAKYDF44KQEaqXY3bbJNufEDi6QPnahV4JdBxFbFCN9Vg7ZfUHxPv3uhjeeJEtPe2PjFKWRsUrEF3RDttnXf9wXq3BfYBZemwKipJ24",
    "H": "xpub6Bg8zbY94d1cBbAGT2crZL7C1UM8JWCP5CCtiHMnV4tB1pE9oCfjvZxRRFLi6EiamBDyCs3ARaHwU2FLx76YYCPFRVc1YyJi6depNtWRnoJ",
    "I": "xpub6DMpHuTZTTN64eEHcNpyeQwehXgWTrY668ZkRWnRfkFEGKpNv2uPR3js1dJgcFRksSmrdtpHqFDPTzFsR1HqvzNdgZwXmk9vCLt1ypwUzA3",
    "J": "xpub6CVeYPTG57D4tm9BvwCcakppwGJstbXyK8Yd611agusZuHmx7og3dNvr6pjMN6e4BoaNc5MZA4TjMLjMT2h2vJRU8rYLvHFUwrEL9zDbuqe",
}
XPUB_PASSPHRASE_NONE = "xpub6BiVtCpG9fQPxnPmHXG8PhtzQdWC2Su4qWu6XW9tpWFYhxydCLJGrWBJZ5H6qTAHdPQ7pQhtpjiYZVZARo14qHiay2fvrX996oEP42u8wZy"
XPUB_CARDANO_PASSPHRASE_A = "d37eba66d6183547b11b4d0c3e08e761da9f07c3ef32183f8b79360b2b66850e47e8eb3865251784c3c471a854ee40dfc067f7f3afe47d093388ea45239606fd"
XPUB_CARDANO_PASSPHRASE_B = "d80e770f6dfc3edb58eaab68aa091b2c27b08a47583471e93437ac5f8baa61880c7af4938a941c084c19731e6e57a5710e6ad1196263291aea297ce0eec0f177"

ADDRESS_N = parse_path("m/44h/0h/0h")
XPUB_REQUEST = messages.GetPublicKey(address_n=ADDRESS_N, coin_name="Bitcoin")

SESSIONS_STORED = 10


def _get_xpub(session: Session, expected_passphrase_req: bool = False):
    """Get XPUB and check that the appropriate passphrase flow has happened."""
    if expected_passphrase_req:
        expected_responses = [
            messages.PassphraseRequest,
            messages.ButtonRequest,
            messages.ButtonRequest,
            messages.PublicKey,
        ]
    else:
        expected_responses = [messages.PublicKey]

    with session:
        session.set_expected_responses(expected_responses)
        result = session.call(XPUB_REQUEST)
        return result.xpub


@pytest.mark.setup_client(passphrase=True)
def test_session_with_passphrase(client: Client):

    session = Session(client.get_session(passphrase="A"))
    session_id = session.id
    # GetPublicKey requires passphrase and since it is not cached,
    # Trezor will prompt for it.
    assert _get_xpub(session, expected_passphrase_req=True) == XPUB_PASSPHRASES["A"]

    # Call Initialize again, this time with the received session id and then call
    # GetPublicKey. The passphrase should be cached now so Trezor must
    # not ask for it again, whilst returning the same xpub.
    session2 = Session(client.resume_session(session))
    assert session2.id == session_id
    assert _get_xpub(session2) == XPUB_PASSPHRASES["A"]

    # If we set session id in Initialize to None, the cache will be cleared
    # and Trezor will ask for the passphrase again.
    session3 = Session(client.get_session(passphrase="A"))
    assert session3 != session_id
    assert _get_xpub(session3, expected_passphrase_req=True) == XPUB_PASSPHRASES["A"]

    # Unknown session id is the same as setting it to None.
    # _init_session(client, session_id=b"X" * 32)
    # assert _get_xpub(passphrase="A") == XPUB_PASSPHRASES["A"]


@pytest.mark.setup_client(passphrase=True)
def test_multiple_sessions(client: Client):
    # start SESSIONS_STORED sessions
    session_ids = []
    sessions = []
    for _ in range(SESSIONS_STORED):
        session = client.get_session()
        sessions.append(session)
        session_ids.append(session.id)

    # Resume each session
    for i in range(SESSIONS_STORED):
        resumed_session = client.resume_session(sessions[i])
        assert session_ids[i] == resumed_session.id

    # Creating a new session replaces the least-recently-used session
    client.get_session()

    # Resuming session 1 through SESSIONS_STORED will still work
    for i in range(1, SESSIONS_STORED):
        resumed_session = client.resume_session(sessions[i])
        assert session_ids[i] == resumed_session.id

    # Resuming session 0 will not work
    resumed_session = client.resume_session(sessions[0])
    assert session_ids[0] != resumed_session.id

    # New session bumped out the least-recently-used anonymous session.
    # Resuming session 1 through SESSIONS_STORED will still work
    for i in range(1, SESSIONS_STORED):
        resumed_session = client.resume_session(sessions[i])
        assert session_ids[i] == resumed_session.id

    # Creating a new session replaces session_ids[0] again
    client.get_session()

    # Resuming all sessions one by one will in turn bump out the previous session.
    for i in range(SESSIONS_STORED):
        resumed_session = client.resume_session(sessions[i])
        assert session_ids[i] != resumed_session.id


@pytest.mark.setup_client(passphrase=True)
def test_multiple_passphrases(client: Client):
    # start a session
    session_a = Session(client.get_session(passphrase="A"))
    session_a_id = session_a.id
    assert _get_xpub(session_a, expected_passphrase_req=True) == XPUB_PASSPHRASES["A"]
    # start it again wit the same session id
    session_a_resumed = Session(client.resume_session(session_a))
    # session is the same
    assert session_a_resumed.id == session_a_id
    # passphrase is not prompted
    assert _get_xpub(session_a_resumed) == XPUB_PASSPHRASES["A"]

    # start a second session
    session_b = Session(client.get_session(passphrase="B"))
    session_b_id = session_b.id
    # new session -> new session id and passphrase prompt
    assert _get_xpub(session_b, expected_passphrase_req=True) == XPUB_PASSPHRASES["B"]

    # provide the same session id -> must not ask for passphrase again.
    session_b_resumed = Session(client.resume_session(session_b))
    assert session_b_resumed.id == session_b_id
    assert _get_xpub(session_b_resumed) == XPUB_PASSPHRASES["B"]

    # provide the first session id -> must not ask for passphrase again and return the same result.
    session_a_resumed_again = Session(client.resume_session(session_a))
    assert session_a_resumed_again.id == session_a_id
    assert _get_xpub(session_a_resumed_again) == XPUB_PASSPHRASES["A"]

    # provide the second session id -> must not ask for passphrase again and return the same result.
    session_b_resumed_again = Session(client.resume_session(session_b))
    assert session_b_resumed_again.id == session_b_id
    assert _get_xpub(session_b_resumed_again) == XPUB_PASSPHRASES["B"]


@pytest.mark.slow
@pytest.mark.setup_client(passphrase=True)
def test_max_sessions_with_passphrases(client: Client):
    # for the following tests, we are using as many passphrases as there are available sessions
    assert len(XPUB_PASSPHRASES) == SESSIONS_STORED

    # start as many sessions as the limit is
    session_ids = {}
    sessions = {}
    for passphrase, xpub in XPUB_PASSPHRASES.items():
        session = Session(client.get_session(passphrase=passphrase))
        assert session.id not in session_ids.values()
        session_ids[passphrase] = session.id
        sessions[passphrase] = session
        assert _get_xpub(session, expected_passphrase_req=True) == xpub

    for passphrase, xpub in XPUB_PASSPHRASES.items():
        session = Session(client.get_session(passphrase=passphrase))
        assert session.id not in session_ids.values()
        session_ids[passphrase] = session.id
        sessions[passphrase] = session
        assert _get_xpub(session, expected_passphrase_req=True) == xpub
    # passphrase is not prompted for the started the sessions, regardless the order
    # let's try 20 different orderings
    passphrases = list(XPUB_PASSPHRASES.keys())
    shuffling = passphrases[:]
    for _ in range(20):
        random.shuffle(shuffling)
        for passphrase in shuffling:
            resumed_session = Session(client.resume_session(sessions[passphrase]))
            assert resumed_session.id == session_ids[passphrase]
            assert _get_xpub(resumed_session) == XPUB_PASSPHRASES[passphrase]

    # make sure the usage order is the reverse of the creation order
    for passphrase in reversed(passphrases):
        resumed_session = Session(client.resume_session(sessions[passphrase]))
        assert resumed_session.id == session_ids[passphrase]
        assert _get_xpub(resumed_session) == XPUB_PASSPHRASES[passphrase]

    # creating one more session will exceed the limit
    new_session = Session(client.get_session(passphrase="XX"))
    # new session asks for passphrase
    _get_xpub(new_session, expected_passphrase_req=True)

    # restoring the sessions in reverse will evict the next-up session
    for passphrase in reversed(passphrases):
        resumed_session = Session(client.resume_session(sessions[passphrase]))
        _get_xpub(
            resumed_session, expected_passphrase_req=True
        )  # passphrase is prompted


def test_session_enable_passphrase(client: Client):
    # Let's start the communication by calling Initialize.
    session = Session(client.get_session(passphrase=""))

    # Trezor will not prompt for passphrase because it is turned off.
    assert _get_xpub(session, expected_passphrase_req=False) == XPUB_PASSPHRASE_NONE

    # Turn on passphrase.
    # Emit the call explicitly to avoid ClearSession done by the library function
    response = session.call(messages.ApplySettings(use_passphrase=True))
    assert isinstance(response, messages.Success)

    # The session id is unchanged, therefore we do not prompt for the passphrase.
    session_id = session.id
    resumed_session = Session(client.resume_session(session))
    assert session_id == resumed_session.id
    assert _get_xpub(resumed_session) == XPUB_PASSPHRASE_NONE

    # We clear the session id now, so the passphrase should be asked.
    new_session = Session(client.get_session(passphrase="A"))
    assert session_id != new_session.id
    assert _get_xpub(new_session, expected_passphrase_req=True) == XPUB_PASSPHRASES["A"]


@pytest.mark.models("core")
@pytest.mark.setup_client(passphrase=True)
def test_passphrase_on_device(client: Client):
    # _init_session(client)
    session = client.get_session(passphrase="A")
    # try to get xpub with passphrase on host:
    response = session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PassphraseRequest)
    # using `client.call` to auto-skip subsequent ButtonRequests for "show passphrase"
    response = session.call(messages.PassphraseAck(passphrase="A", on_device=False))

    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASES["A"]

    # try to get xpub again, passphrase should be cached
    response = session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASES["A"]

    # make a new session
    session2 = session.client.get_session(passphrase="A")

    # try to get xpub with passphrase on device:
    response = session2.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PassphraseRequest)
    response = session2.call_raw(messages.PassphraseAck(on_device=True))
    # no "show passphrase" here
    assert isinstance(response, messages.ButtonRequest)
    client.debug.input("A")
    response = session2.call_raw(messages.ButtonAck())
    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASES["A"]

    # try to get xpub again, passphrase should be cached
    response = session2.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASES["A"]


@pytest.mark.models("core")
@pytest.mark.setup_client(passphrase=True)
def test_passphrase_always_on_device(client: Client):
    # Let's start the communication by calling Initialize.
    session = client.get_session()
    # session_id = _init_session(client)

    # Force passphrase entry on Trezor.
    response = session.call(messages.ApplySettings(passphrase_always_on_device=True))
    assert isinstance(response, messages.Success)

    # Since we enabled the always_on_device setting, Trezor will send ButtonRequests and ask for it on the device.
    response = session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.ButtonRequest)
    client.debug.input("")  # Input empty passphrase.
    response = session.call_raw(messages.ButtonAck())
    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASE_NONE

    # Passphrase will not be prompted. The session id stays the same and the passphrase is cached.
    resumed_session = client.resume_session(session)
    response = resumed_session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASE_NONE

    # In case we want to add a new passphrase we need to send session_id = None.
    new_session = client.get_session(passphrase="A")
    response = new_session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.ButtonRequest)
    client.debug.input("A")  # Input non-empty passphrase.
    response = new_session.call_raw(messages.ButtonAck())
    assert isinstance(response, messages.PublicKey)
    assert response.xpub == XPUB_PASSPHRASES["A"]


@pytest.mark.models("legacy")
@pytest.mark.setup_client(passphrase="")
def test_passphrase_on_device_not_possible_on_t1(client: Client):
    # This setting makes no sense on T1.
    response = client.call_raw(messages.ApplySettings(passphrase_always_on_device=True))
    assert isinstance(response, messages.Failure)
    assert response.code == FailureType.DataError

    # T1 should not accept on_device request
    response = client.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PassphraseRequest)
    response = client.call_raw(messages.PassphraseAck(on_device=True))
    assert isinstance(response, messages.Failure)
    assert response.code == FailureType.DataError


@pytest.mark.setup_client(passphrase=True)
def test_passphrase_ack_mismatch(session: Session):
    response = session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PassphraseRequest)
    response = session.call_raw(messages.PassphraseAck(passphrase="A", on_device=True))
    assert isinstance(response, messages.Failure)
    assert response.code == FailureType.DataError


@pytest.mark.setup_client(passphrase="")
def test_passphrase_missing(session: Session):
    response = session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PassphraseRequest)
    response = session.call_raw(messages.PassphraseAck(passphrase=None))
    assert isinstance(response, messages.Failure)
    assert response.code == FailureType.DataError

    response = session.call_raw(XPUB_REQUEST)
    assert isinstance(response, messages.PassphraseRequest)
    response = session.call_raw(
        messages.PassphraseAck(passphrase=None, on_device=False)
    )
    assert isinstance(response, messages.Failure)
    assert response.code == FailureType.DataError


@pytest.mark.setup_client(passphrase=True)
def test_passphrase_length(client: Client):
    def call(passphrase: str, expected_result: bool):
        session = client.get_session(passphrase=passphrase)
        response = session.call_raw(XPUB_REQUEST)
        assert isinstance(response, messages.PassphraseRequest)
        try:
            response = session.call(messages.PassphraseAck(passphrase=passphrase))
            assert expected_result is True, "Call should have failed"
            assert isinstance(response, messages.PublicKey)
        except exceptions.TrezorFailure as e:
            assert expected_result is False, "Call should have succeeded"
            assert e.code == FailureType.DataError

    # 50 is ok
    call(passphrase="A" * 50, expected_result=True)
    # 51 is not
    call(passphrase="A" * 51, expected_result=False)
    # "š" has two bytes - 48x A and "š" should be fine (50 bytes)
    call(passphrase="A" * 48 + "š", expected_result=True)
    # "š" has two bytes - 49x A and "š" should not (51 bytes)
    call(passphrase="A" * 49 + "š", expected_result=False)


@pytest.mark.models("core")
@pytest.mark.setup_client(passphrase=True)
def test_hide_passphrase_from_host(client: Client):
    # Without safety checks, turning it on fails
    session = client.get_management_session()
    with pytest.raises(TrezorFailure, match="Safety checks are strict"), client:
        device.apply_settings(session, hide_passphrase_from_host=True)

    device.apply_settings(session, safety_checks=SafetyCheckLevel.PromptTemporarily)

    # Turning it on
    device.apply_settings(session, hide_passphrase_from_host=True)

    passphrase = "abc"
    session = Session(client.get_session(passphrase=passphrase))
    with client, session:

        def input_flow():
            yield
            content = client.debug.read_layout().text_content().lower()
            assert any(
                (s[:50].lower() in content)
                for s in TR.translate("passphrase__from_host_not_shown")
            )
            if client.layout_type in (LayoutType.TT, LayoutType.Mercury):
                client.debug.press_yes()
            elif client.layout_type is LayoutType.TR:
                client.debug.press_right()
                client.debug.press_right()
                client.debug.press_yes()
            else:
                raise KeyError

        client.watch_layout()
        client.set_input_flow(input_flow)
        session.set_expected_responses(
            [
                messages.PassphraseRequest,
                messages.ButtonRequest,
                messages.PublicKey,
            ]
        )
        client.use_passphrase(passphrase)
        result = session.call(XPUB_REQUEST)
        assert isinstance(result, messages.PublicKey)
        xpub_hidden_passphrase = result.xpub

    # Turning it off
    device.apply_settings(session, hide_passphrase_from_host=False)

    # Starting new session, otherwise the passphrase would be cached
    session = Session(client.get_session(passphrase=passphrase))

    with client, session:

        def input_flow():
            yield
            TR.assert_in(
                client.debug.read_layout().text_content(),
                "passphrase__next_screen_will_show_passphrase",
            )
            client.debug.press_yes()

            yield
            TR.assert_equals(
                client.debug.read_layout().title(),
                "passphrase__title_confirm",
            )
            assert passphrase in client.debug.read_layout().text_content()
            client.debug.press_yes()

        client.watch_layout()
        client.set_input_flow(input_flow)
        session.set_expected_responses(
            [
                messages.PassphraseRequest,
                messages.ButtonRequest,
                messages.ButtonRequest,
                messages.PublicKey,
            ]
        )
        client.use_passphrase(passphrase)
        result = session.call(XPUB_REQUEST)
        assert isinstance(result, messages.PublicKey)
        xpub_shown_passphrase = result.xpub

    assert xpub_hidden_passphrase == xpub_shown_passphrase


def _get_xpub_cardano(session: Session, expected_passphrase_req: bool = False):
    msg = messages.CardanoGetPublicKey(
        address_n=parse_path("m/44h/1815h/0h/0/0"),
        derivation_type=messages.CardanoDerivationType.ICARUS,
    )
    response = session.call_raw(msg)
    if expected_passphrase_req:
        assert isinstance(response, messages.PassphraseRequest)
        response = session.call(messages.PassphraseAck(passphrase=session.passphrase))
    assert isinstance(response, messages.CardanoPublicKey)
    return response.xpub


@pytest.mark.models("core")
@pytest.mark.altcoin
@pytest.mark.setup_client(passphrase=True)
def test_cardano_passphrase(client: Client):
    # Cardano has a separate derivation method that needs to access the plaintext
    # of the passphrase.
    # Historically, Cardano calls would ask for passphrase again. Now, they should not.

    # session_id = _init_session(client, derive_cardano=True)

    # GetPublicKey requires passphrase and since it is not cached,
    # Trezor will prompt for it.
    session = Session(client.get_session(passphrase="B", derive_cardano=True))
    assert _get_xpub(session, expected_passphrase_req=True) == XPUB_PASSPHRASES["B"]

    # The passphrase is now cached for non-Cardano coins.
    assert _get_xpub(session) == XPUB_PASSPHRASES["B"]

    # The passphrase should be cached for Cardano as well
    assert _get_xpub_cardano(session) == XPUB_CARDANO_PASSPHRASE_B

    # Initialize with the session id does not destroy the state
    resumed_session = Session(client.resume_session(session))
    # _init_session(client, session_id=session_id, derive_cardano=True)
    assert _get_xpub(resumed_session) == XPUB_PASSPHRASES["B"]
    assert _get_xpub_cardano(resumed_session) == XPUB_CARDANO_PASSPHRASE_B

    # New session will destroy the state
    new_session = Session(client.get_session(passphrase="A", derive_cardano=True))
    # _init_session(client, derive_cardano=True)

    # Cardano must ask for passphrase again
    assert (
        _get_xpub_cardano(new_session, expected_passphrase_req=True)
        == XPUB_CARDANO_PASSPHRASE_A
    )

    # Passphrase is now cached for Cardano
    assert _get_xpub_cardano(new_session) == XPUB_CARDANO_PASSPHRASE_A

    # Passphrase is cached for non-Cardano coins too
    assert _get_xpub(new_session) == XPUB_PASSPHRASES["A"]
