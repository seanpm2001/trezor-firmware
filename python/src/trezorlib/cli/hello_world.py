from typing import TYPE_CHECKING, Optional

import click

from .. import hello_world
from . import with_client

if TYPE_CHECKING:
    from ..client import TrezorClient


@click.group(name="helloworld")
def cli() -> None:
    """Hello world commands."""


@cli.command()
@click.argument("name")
@click.option("-a", "--amount", type=int, help="How many times to greet.")
@click.option(
    "-d", "--show-display", is_flag=True, help="Whether to show confirmation screen."
)
@with_client
def say_hello(
    client: "TrezorClient", name: str, amount: Optional[int], show_display: bool
) -> str:
    """Simply say hello to the supplied name."""
    return hello_world.say_hello(client, name, amount, show_display=show_display)
