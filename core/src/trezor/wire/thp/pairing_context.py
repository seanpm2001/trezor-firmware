from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from trezor import log, loop, protobuf, workflow
from trezor.wire import context, message_handler, protocol_common
from trezor.wire.context import UnexpectedMessageWithId
from trezor.wire.errors import ActionCancelled
from trezor.wire.protocol_common import Context, MessageWithType
from trezor.wire.thp.session_context import UnexpectedMessageWithType

from .channel import Channel

if TYPE_CHECKING:
    from typing import (  # pyright:ignore[reportShadowedImports]
        Any,
        Callable,
        Container,
        Coroutine,
    )

    pass


class PairingContext(Context):
    def __init__(self, channel: Channel) -> None:
        super().__init__(channel.iface, channel.channel_id)
        self.channel = channel
        self.incoming_message = loop.chan()

    async def handle(self, is_debug_session: bool = False) -> None:
        if __debug__:
            log.debug(__name__, "handle - start")
            if is_debug_session:
                import apps.debug

                apps.debug.DEBUG_CONTEXT = self

        take = self.incoming_message.take()
        next_message: MessageWithType | None = None

        while True:
            try:
                if next_message is None:
                    # If the previous run did not keep an unprocessed message for us,
                    # wait for a new one.
                    try:
                        message: MessageWithType = await take
                    except protocol_common.WireError as e:
                        if __debug__:
                            log.exception(__name__, e)
                        await self.write(message_handler.failure(e))
                        continue
                else:
                    # Process the message from previous run.
                    message = next_message
                    next_message = None

                try:
                    next_message = await handle_pairing_message(
                        self, message, use_workflow=not is_debug_session
                    )
                except Exception as exc:
                    # Log and ignore. The session handler can only exit explicitly in the
                    # following finally block.
                    if __debug__:
                        log.exception(__name__, exc)
                finally:
                    if not __debug__ or not is_debug_session:
                        # Unload modules imported by the workflow.  Should not raise.
                        # This is not done for the debug session because the snapshot taken
                        # in a debug session would clear modules which are in use by the
                        # workflow running on wire.
                        # TODO utils.unimport_end(modules)

                        if next_message is None:

                            # Shut down the loop if there is no next message waiting.
                            return  # pylint: disable=lost-exception

            except Exception as exc:
                # Log and try again. The session handler can only exit explicitly via
                # loop.clear() above.
                if __debug__:
                    log.exception(__name__, exc)

    async def read(
        self,
        expected_types: Container[int],
        expected_type: type[protobuf.MessageType] | None = None,
    ) -> protobuf.MessageType:
        if __debug__:
            exp_type: str = str(expected_type)
            if expected_type is not None:
                exp_type = expected_type.MESSAGE_NAME
            log.debug(
                __name__,
                "Read - with expected types %s and expected type %s",
                str(expected_types),
                exp_type,
            )

        message: MessageWithType = await self.incoming_message.take()

        if message.type not in expected_types:
            raise UnexpectedMessageWithType(message)

        if expected_type is None:
            expected_type = protobuf.type_for_wire(message.type)

        return message_handler.wrap_protobuf_load(message.data, expected_type)

    async def write(self, msg: protobuf.MessageType) -> None:
        return await self.channel.write(msg)


def _find_handler_placeholder(
    messageType: int,
) -> Callable[[Any, Any], Coroutine[Any, Any, protobuf.MessageType]]:
    raise Exception()


get_handler = _find_handler_placeholder


async def handle_pairing_message(
    ctx: PairingContext, msg: protocol_common.MessageWithType, use_workflow: bool
) -> protocol_common.MessageWithType | None:

    res_msg: protobuf.MessageType | None = None

    # We need to find a handler for this message type.  Should not raise.
    # TODO register handlers to dict
    handler = get_handler(msg.type)  # pylint: disable=assignment-from-none

    if handler is None:
        # If no handler is found, we can skip decoding and directly
        # respond with failure.
        await ctx.write(message_handler.unexpected_message())
        return None

    if msg.type in workflow.ALLOW_WHILE_LOCKED:
        workflow.autolock_interrupts_workflow = False

    # Here we make sure we always respond with a Failure response
    # in case of any errors.
    try:
        # Find a protobuf.MessageType subclass that describes this
        # message.  Raises if the type is not found.
        req_type = protobuf.type_for_wire(msg.type)

        # Try to decode the message according to schema from
        # `req_type`. Raises if the message is malformed.
        req_msg = message_handler.wrap_protobuf_load(msg.data, req_type)

        # Create the handler task.
        task = handler(ctx, req_msg)

        # Run the workflow task.  Workflow can do more on-the-wire
        # communication inside, but it should eventually return a
        # response message, or raise an exception (a rather common
        # thing to do).  Exceptions are handled in the code below.
        if use_workflow:
            # Spawn a workflow around the task. This ensures that concurrent
            # workflows are shut down.
            res_msg = await workflow.spawn(context.with_context(ctx, task))
            pass  # TODO
        else:
            # For debug messages, ignore workflow processing and just await
            # results of the handler.
            res_msg = await task

    except UnexpectedMessageWithId as exc:
        # Workflow was trying to read a message from the wire, and
        # something unexpected came in.  See Context.read() for
        # example, which expects some particular message and raises
        # UnexpectedMessage if another one comes in.
        # In order not to lose the message, we return it to the caller.
        # TODO:
        # We might handle only the few common cases here, like
        # Initialize and Cancel.
        return exc.msg

    except BaseException as exc:
        # Either:
        # - the message had a type that has a registered handler, but does not have
        #   a protobuf class
        # - the message was not valid protobuf
        # - workflow raised some kind of an exception while running
        # - something canceled the workflow from the outside
        if __debug__:
            if isinstance(exc, ActionCancelled):
                log.debug(__name__, "cancelled: %s", exc.message)
            elif isinstance(exc, loop.TaskClosed):
                log.debug(__name__, "cancelled: loop task was closed")
            else:
                log.exception(__name__, exc)
        res_msg = message_handler.failure(exc)
    if res_msg is not None:
        # perform the write outside the big try-except block, so that usb write
        # problem bubbles up
        await ctx.write(res_msg)
    return None
