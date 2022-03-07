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

from typing import Optional

import pytest

from trezorlib import hello_world
from trezorlib.debuglink import TrezorClientDebugLink as Client

VECTORS = (  # name, amount, show_display
    ("George", 2, True),
    ("John", 3, False),
    ("Hannah", None, False),
)


@pytest.mark.skip_t1
@pytest.mark.parametrize("name, amount, show_display", VECTORS)
def test_hello_world(
    client: Client, name: str, amount: Optional[int], show_display: bool
):
    with client:
        greeting_text = hello_world.say_hello(
            client, name=name, amount=amount, show_display=show_display
        )
        greeting_lines = greeting_text.strip().splitlines()

        assert len(greeting_lines) == amount or 1
        assert all(name in line for line in greeting_lines)
