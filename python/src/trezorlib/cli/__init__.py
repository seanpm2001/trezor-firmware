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

from __future__ import annotations

import functools
import os
import sys
import typing as t
from contextlib import contextmanager

import click

from .. import exceptions, transport, ui
from ..client import TrezorClient
from ..messages import Capability
from ..transport.new import channel_database
from ..transport.new.transport import NewTransport

if t.TYPE_CHECKING:
    # Needed to enforce a return value from decorators
    # More details: https://www.python.org/dev/peps/pep-0612/
    from typing import TypeVar

    from typing_extensions import Concatenate, ParamSpec

    P = ParamSpec("P")
    R = TypeVar("R")


class ChoiceType(click.Choice):

    def __init__(
        self, typemap: t.Dict[str, t.Any], case_sensitive: bool = True
    ) -> None:
        super().__init__(list(typemap.keys()))
        self.case_sensitive = case_sensitive
        if case_sensitive:
            self.typemap = typemap
        else:
            self.typemap = {k.lower(): v for k, v in typemap.items()}

    def convert(self, value: t.Any, param: t.Any, ctx: click.Context) -> t.Any:
        if value in self.typemap.values():
            return value
        value = super().convert(value, param, ctx)
        if isinstance(value, str) and not self.case_sensitive:
            value = value.lower()
        return self.typemap[value]


def get_passphrase(
    passphrase_on_host: bool, available_on_device: bool
) -> t.Union[str, object]:
    if available_on_device and not passphrase_on_host:
        return ui.PASSPHRASE_ON_DEVICE

    env_passphrase = os.getenv("PASSPHRASE")
    if env_passphrase is not None:
        ui.echo("Passphrase required. Using PASSPHRASE environment variable.")
        return env_passphrase

    while True:
        try:
            passphrase = ui.prompt(
                "Passphrase required",
                hide_input=True,
                default="",
                show_default=False,
            )
            # In case user sees the input on the screen, we do not need confirmation
            if not ui.CAN_HANDLE_HIDDEN_INPUT:
                return passphrase
            second = ui.prompt(
                "Confirm your passphrase",
                hide_input=True,
                default="",
                show_default=False,
            )
            if passphrase == second:
                return passphrase
            else:
                ui.echo("Passphrase did not match. Please try again.")
        except click.Abort:
            raise exceptions.Cancelled from None


class NewTrezorConnection:

    def __init__(
        self,
        path: str,
        session_id: bytes | None,
        passphrase_on_host: bool,
        script: bool,
    ) -> None:
        self.path = path
        self.session_id = session_id
        self.passphrase_on_host = passphrase_on_host
        self.script = script

    def get_session(self, derive_cardano: bool = False):
        client = self.get_client()

        if self.session_id is not None:
            pass  # TODO Try resume - be careful of cardano derivation settings!
        features = client.protocol.get_features()

        passphrase_enabled = True  # TODO what to do here?

        if not passphrase_enabled:
            return client.get_session(derive_cardano=derive_cardano)

        # TODO Passphrase empty by default - ???
        available_on_device = Capability.PassphraseEntry in features.capabilities
        passphrase = get_passphrase(available_on_device, self.passphrase_on_host)
        # TODO handle case when PASSPHRASE_ON_DEVICE is returned from get_passphrase func
        if not isinstance(passphrase, str):
            raise RuntimeError("Passphrase must be a str")
        session = client.get_session(
            passphrase=passphrase, derive_cardano=derive_cardano
        )
        return session

    def get_transport(self) -> "NewTransport":
        try:
            # look for transport without prefix search
            return transport.get_transport(self.path, prefix_search=False)
        except Exception:
            # most likely not found. try again below.
            pass

        # look for transport with prefix search
        # if this fails, we want the exception to bubble up to the caller
        return transport.get_transport(self.path, prefix_search=True)

    def get_client(self) -> TrezorClient:
        transport = self.get_transport()

        stored_channels = channel_database.load_stored_channels()
        stored_transport_paths = [ch.transport_path for ch in stored_channels]
        path = transport.get_path()
        if path in stored_transport_paths:
            stored_channel_with_correct_transport_path = next(
                ch for ch in stored_channels if ch.transport_path == path
            )
            client = TrezorClient.resume(
                transport, stored_channel_with_correct_transport_path
            )
        else:
            client = TrezorClient(transport)

        return client

    def get_management_session(self) -> Session:
        client = self.get_client()
        management_session = client.get_management_session()
        return management_session

    @contextmanager
    def client_context(self):
        """Get a client instance as a context manager. Handle errors in a manner
        appropriate for end-users.

        Usage:
        >>> with obj.client_context() as client:
        >>>     do_your_actions_here()
        """
        try:
            client = self.get_client()
        except transport.DeviceIsBusy:
            click.echo("Device is in use by another process.")
            sys.exit(1)
        except Exception:
            click.echo("Failed to find a Trezor device.")
            if self.path is not None:
                click.echo(f"Using path: {self.path}")
            sys.exit(1)

        try:
            yield client
        except exceptions.Cancelled:
            # handle cancel action
            click.echo("Action was cancelled.")
            sys.exit(1)
        except exceptions.TrezorException as e:
            # handle any Trezor-sent exceptions as user-readable
            raise click.ClickException(str(e)) from e
            # other exceptions may cause a traceback


# class TrezorConnection:

#     def __init__(
#         self,
#         path: str,
#         session_id: bytes | None,
#         passphrase_on_host: bool,
#         script: bool,
#     ) -> None:
#         self.path = path
#         self.session_id = session_id
#         self.passphrase_on_host = passphrase_on_host
#         self.script = script

#     def get_transport(self) -> "Transport":
#         try:
#             # look for transport without prefix search
#             return transport.get_transport(self.path, prefix_search=False)
#         except Exception:
#             # most likely not found. try again below.
#             pass

#         # look for transport with prefix search
#         # if this fails, we want the exception to bubble up to the caller
#         return transport.get_transport(self.path, prefix_search=True)

#     def get_ui(self) -> "TrezorClientUI":
#         if self.script:
#             # It is alright to return just the class object instead of instance,
#             # as the ScriptUI class object itself is the implementation of TrezorClientUI
#             # (ScriptUI is just a set of staticmethods)
#             return ScriptUI
#         else:
#             return ClickUI(passphrase_on_host=self.passphrase_on_host)

#     def get_client(self) -> TrezorClient:
#         transport = self.get_transport()
#         ui = self.get_ui()
#         return TrezorClient(transport, ui=ui, session_id=self.session_id)

#     @contextmanager
#     def client_context(self):
#         """Get a client instance as a context manager. Handle errors in a manner
#         appropriate for end-users.

#         Usage:
#         >>> with obj.client_context() as client:
#         >>>     do_your_actions_here()
#         """
#         try:
#             client = self.get_client()
#         except transport.DeviceIsBusy:
#             click.echo("Device is in use by another process.")
#             sys.exit(1)
#         except Exception:
#             click.echo("Failed to find a Trezor device.")
#             if self.path is not None:
#                 click.echo(f"Using path: {self.path}")
#             sys.exit(1)

#         try:
#             yield client
#         except exceptions.Cancelled:
#             # handle cancel action
#             click.echo("Action was cancelled.")
#             sys.exit(1)
#         except exceptions.TrezorException as e:
#             # handle any Trezor-sent exceptions as user-readable
#             raise click.ClickException(str(e)) from e
#             # other exceptions may cause a traceback

from ..transport.new.session import Session


def with_cardano_session(
    func: "t.Callable[Concatenate[Session, P], R]",
) -> "t.Callable[P, R]":
    return with_session(func=func, derive_cardano=True)


def with_session(
    func: "t.Callable[Concatenate[Session, P], R]", derive_cardano: bool = False
) -> "t.Callable[P, R]":

    @click.pass_obj
    @functools.wraps(func)
    def function_with_session(
        obj: NewTrezorConnection, *args: "P.args", **kwargs: "P.kwargs"
    ) -> "R":
        session = obj.get_session(derive_cardano)
        try:
            return func(session, *args, **kwargs)
        finally:
            pass
            # TODO try end session if not resumed

    # the return type of @click.pass_obj is improperly specified and pyright doesn't
    # understand that it converts f(obj, *args, **kwargs) to f(*args, **kwargs)
    return function_with_session  # type: ignore [is incompatible with return type]


def with_management_session(
    func: "t.Callable[Concatenate[Session, P], R]",
) -> "t.Callable[P, R]":

    @click.pass_obj
    @functools.wraps(func)
    def function_with_management_session(
        obj: NewTrezorConnection, *args: "P.args", **kwargs: "P.kwargs"
    ) -> "R":
        session = obj.get_management_session()
        try:
            return func(session, *args, **kwargs)
        finally:
            pass
            # TODO try end session if not resumed

    # the return type of @click.pass_obj is improperly specified and pyright doesn't
    # understand that it converts f(obj, *args, **kwargs) to f(*args, **kwargs)
    return function_with_management_session  # type: ignore [is incompatible with return type]


def with_client(
    func: "t.Callable[Concatenate[TrezorClient, P], R]",
) -> "t.Callable[P, R]":
    """Wrap a Click command in `with obj.client_context() as client`.

    Sessions are handled transparently. The user is warned when session did not resume
    cleanly. The session is closed after the command completes - unless the session
    was resumed, in which case it should remain open.
    """

    @click.pass_obj
    @functools.wraps(func)
    def trezorctl_command_with_client(
        obj: NewTrezorConnection, *args: "P.args", **kwargs: "P.kwargs"
    ) -> "R":
        with obj.client_context() as client:
            # session_was_resumed = obj.session_id == client.session_id
            # if not session_was_resumed and obj.session_id is not None:
            #     # tried to resume but failed
            #     click.echo("Warning: failed to resume session.", err=True)
            click.echo(
                "Warning: resume session detection is not implemented yet!", err=True
            )
            try:
                return func(client, *args, **kwargs)
            finally:
                channel_database.save_channel(client.protocol)
                # if not session_was_resumed:
                #     try:
                #         client.end_session()
                #     except Exception:
                #         pass

    # the return type of @click.pass_obj is improperly specified and pyright doesn't
    # understand that it converts f(obj, *args, **kwargs) to f(*args, **kwargs)
    return trezorctl_command_with_client  # type: ignore [is incompatible with return type]


# def with_client(
#     func: "t.Callable[Concatenate[TrezorClient, P], R]",
# ) -> "t.Callable[P, R]":
#     """Wrap a Click command in `with obj.client_context() as client`.

#     Sessions are handled transparently. The user is warned when session did not resume
#     cleanly. The session is closed after the command completes - unless the session
#     was resumed, in which case it should remain open.
#     """

#     @click.pass_obj
#     @functools.wraps(func)
#     def trezorctl_command_with_client(
#         obj: TrezorConnection, *args: "P.args", **kwargs: "P.kwargs"
#     ) -> "R":
#         with obj.client_context() as client:
#             session_was_resumed = obj.session_id == client.session_id
#             if not session_was_resumed and obj.session_id is not None:
#                 # tried to resume but failed
#                 click.echo("Warning: failed to resume session.", err=True)

#             try:
#                 return func(client, *args, **kwargs)
#             finally:
#                 if not session_was_resumed:
#                     try:
#                         client.end_session()
#                     except Exception:
#                         pass

#     # the return type of @click.pass_obj is improperly specified and pyright doesn't
#     # understand that it converts f(obj, *args, **kwargs) to f(*args, **kwargs)
#     return trezorctl_command_with_client


class AliasedGroup(click.Group):
    """Command group that handles aliases and Click 6.x compatibility.

    Click 7.0 silently switched all underscore_commands to dash-commands.
    This implementation of `click.Group` responds to underscore_commands by invoking
    the respective dash-command.

    Supply an `aliases` dict at construction time to provide an alternative list of
    command names:

    >>> @click.command(cls=AliasedGroup, aliases={"do_bar", do_foo})
    >>> def cli():
    >>>     ...

    If these commands are not known at the construction time, they can be set later:

    >>> @click.command(cls=AliasedGroup)
    >>> def cli():
    >>>     ...
    >>>
    >>> @cli.command()
    >>> def do_foo():
    >>>     ...
    >>>
    >>> cli.aliases={"do_bar", do_foo}
    """

    def __init__(
        self,
        aliases: t.Dict[str, click.Command] | None = None,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.aliases = aliases or {}

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        cmd_name = cmd_name.replace("_", "-")
        # try to look up the real name
        cmd = super().get_command(ctx, cmd_name)
        if cmd:
            return cmd

        # look for a backwards compatibility alias
        if cmd_name in self.aliases:
            return self.aliases[cmd_name]

        return None
