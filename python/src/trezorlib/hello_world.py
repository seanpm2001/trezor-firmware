from typing import TYPE_CHECKING, Optional

from . import messages
from .tools import expect

if TYPE_CHECKING:
    from .client import TrezorClient
    from .protobuf import MessageType


@expect(messages.HelloWorldResponse, field="text", ret_type=str)
def say_hello(
    client: "TrezorClient",
    name: str,
    amount: Optional[int],
    show_display: bool,
) -> "MessageType":
    return client.call(
        messages.HelloWorldRequest(
            name=name,
            amount=amount,
            show_display=show_display,
        )
    )
