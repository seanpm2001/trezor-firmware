# This file is part of the Trezor project.
#
# Copyright (C) 2012-2022 SatoshiLabs and contributors
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

from . import messages
from .tools import expect

if TYPE_CHECKING:
    from .protobuf import MessageType
    from .transport.session import Session


@expect(messages.BenchmarkNames)
def list_names(
    session: "Session",
) -> "MessageType":
    return session.call(messages.BenchmarkListNames())


@expect(messages.BenchmarkResult)
def run(session: "Session", name: str) -> "MessageType":
    return session.call(messages.BenchmarkRun(name=name))
