"""Local uagents Bureau round trip that cannot hang pytest.

The Bureau runs on its own event loop in a daemon thread: uagents' shutdown cancels loop-wide
tasks, which would otherwise take pytest's loop down with it. No mailbox, no Almanac registration.
"""
import asyncio
import logging
import queue
import socket
import threading
from typing import Any, Awaitable, Callable, List, Optional, Tuple

from uagents import Agent, Bureau, Context, Model
from uagents.registration import AgentRegistrationPolicy
from uagents_core.registration import BatchRegistrationPolicy

from common.models import AgentErrorReport


class NoRegistration(AgentRegistrationPolicy):
    async def register(self, *args: Any, **kwargs: Any) -> None:  # never touch Almanac / Agentverse
        return None


class NoBatchRegistration(BatchRegistrationPolicy):
    """Bureau-level equivalent: without it the Bureau still registers its agents over the network."""

    async def register(self) -> None:
        return None

    def add_agent(self, agent_info: Any, identity: Any) -> None:
        return None


# keyword arguments every agent under test must be created with
AGENT_TEST_KWARGS = dict(mailbox=False, enable_agent_inspector=False, shutdown_timeout=5)


def agent_test_kwargs() -> dict:
    return {**AGENT_TEST_KWARGS, "registration_policy": NoRegistration()}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_roundtrip(
    make_target: Callable[[int], Awaitable[Any]],
    make_request: Callable[[], Model],
    timeout: float = 30,
) -> Tuple[str, str, Model]:
    """Send `make_request()` from a throwaway requester agent to the agent built by `make_target(port)`
    (called inside the Bureau's loop) and return (target_address, reply_sender, reply). `make_target` may return
    the agent alone or `(agent, [more agents])` to run helper agents (e.g. the Scanner) in the same Bureau."""
    results: "queue.Queue[object]" = queue.Queue()
    ports = [free_port() for _ in range(3)]
    agent_names: list = []

    async def scenario() -> None:
        built = await make_target(ports[0])
        target, extras = (built[0], list(built[1])) if isinstance(built, tuple) else (built, [])
        agent_names.extend([target.name, "test-requester", *(a.name for a in extras)])
        requester = Agent(
            name="test-requester", seed="bureau requester seed", port=ports[1],
            endpoint=[f"http://127.0.0.1:{ports[1]}/submit"], **agent_test_kwargs(),
        )
        received: asyncio.Queue = asyncio.Queue()

        @requester.on_event("startup")
        async def send_request(ctx: Context) -> None:
            await ctx.send(target.address, make_request())

        async def collect(ctx: Context, sender: str, msg: Model) -> None:
            await received.put((target.address, sender, msg))

        # any reply type the target can produce: its own report, or an AgentErrorReport
        for reply_type in reply_types(make_request()):
            requester.on_message(reply_type)(collect)

        bureau = Bureau(port=ports[2], endpoint=[f"http://127.0.0.1:{ports[2]}/submit"],
                        registration_policy=NoBatchRegistration(), shutdown_timeout=5)
        bureau.add(target)
        for extra in extras:
            bureau.add(extra)
        bureau.add(requester)
        task = asyncio.create_task(bureau.run_async())
        try:
            results.put(await asyncio.wait_for(received.get(), timeout=timeout))
        except BaseException as exc:  # surface timeouts to the test thread
            results.put(exc)
        finally:
            task.cancel()
            await asyncio.wait({task}, timeout=5)

    def runner() -> None:
        try:
            asyncio.run(scenario())
        except BaseException:
            pass  # cancellation during shutdown is expected

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    outcome = results.get(timeout=timeout + 30)
    thread.join(timeout=15)
    # uagents adds a handler to the shared per-name logger for every agent it creates; without this
    # they pile up across tests (each log line printed N times) and slow the suite down.
    for name in agent_names:
        logging.getLogger(name).handlers.clear()
    logging.getLogger("bureau").handlers.clear()
    if isinstance(outcome, BaseException):
        raise AssertionError(f"Bureau round trip failed: {outcome!r}")
    return outcome  # type: ignore[return-value]


def reply_types(request: Model) -> list:
    """Reply models for each request type used in the swarm (plus the shared error report)."""
    from common.models import (
        CommitCorrelationRequest, CommitEvidenceReport, HealthProbeReport, HealthProbeRequest,
        PatchDraftRequest, PatchDraftResult, VulnerabilityReport, VulnerabilityScanRequest,
    )

    mapping = {
        HealthProbeRequest: HealthProbeReport,
        CommitCorrelationRequest: CommitEvidenceReport,
        VulnerabilityScanRequest: VulnerabilityReport,
        PatchDraftRequest: PatchDraftResult,
    }
    return [mapping[type(request)], AgentErrorReport]


def run_chat_session(
    make_swarm: Callable[[int], Awaitable[Any]],
    first_text: str,
    respond: Callable[[List[str]], Optional[str]],
    done: Callable[[List[str]], bool],
    timeout: float = 90,
    on_payment: Optional[Callable[[Any], Optional[Model]]] = None,
    inbox: Optional[list] = None,
) -> List[str]:
    """A stand-in for the ASI:One user. Sends `first_text` to the Orchestrator (the first agent returned by
    `make_swarm`), acknowledges every reply, lets `respond(all_texts_so_far)` answer back (None = stay silent)
    and returns every text received once `done(all_texts)` is true. Same isolated-thread Bureau as run_roundtrip.
    Payment protocol: every RequestPayment/CompletePayment/CancelPayment received is appended to `inbox`, and
    `on_payment(request)` may return a message (CommitPayment, RejectPayment...) to send back to the seller."""
    from uagents_core.contrib.protocols.payment import CancelPayment, CompletePayment, RequestPayment
    from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent

    results: "queue.Queue[object]" = queue.Queue()
    ports = [free_port() for _ in range(3)]
    agent_names: list = []

    async def scenario() -> None:
        built = await make_swarm(ports[0])
        orchestrator, others = built[0], list(built[1])
        agent_names.extend([orchestrator.name, "asi-one-user", *(a.name for a in others)])
        user = Agent(name="asi-one-user", seed="bureau chat user seed", port=ports[1],
                     endpoint=[f"http://127.0.0.1:{ports[1]}/submit"], **agent_test_kwargs())
        texts: List[str] = []
        finished = asyncio.Event()

        @user.on_event("startup")
        async def say_first(ctx: Context) -> None:
            await ctx.send(orchestrator.address, ChatMessage(content=[TextContent(text=first_text)]))

        @user.on_message(ChatMessage)
        async def on_chat(ctx: Context, sender: str, msg: ChatMessage) -> None:
            await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))
            texts.append(msg.text())
            if done(texts):
                results.put(("ok", list(texts)))
                finished.set()
                return
            reply = respond(texts)
            if reply:
                await ctx.send(orchestrator.address, ChatMessage(content=[TextContent(text=reply)]))

        @user.on_message(RequestPayment)
        async def on_request(ctx: Context, sender: str, msg: RequestPayment) -> None:
            if inbox is not None:
                inbox.append(msg)
            answer = on_payment(msg) if on_payment else None
            if answer is not None:
                await ctx.send(sender, answer)

        async def record(ctx: Context, sender: str, msg: Model) -> None:
            if inbox is not None:
                inbox.append(msg)

        user.on_message(CompletePayment)(record)
        user.on_message(CancelPayment)(record)

        @user.on_message(ChatAcknowledgement)
        async def on_ack(ctx: Context, sender: str, msg: ChatAcknowledgement) -> None:
            return None

        bureau = Bureau(port=ports[2], endpoint=[f"http://127.0.0.1:{ports[2]}/submit"],
                        registration_policy=NoBatchRegistration(), shutdown_timeout=5)
        for agent in (orchestrator, *others, user):
            bureau.add(agent)
        task = asyncio.create_task(bureau.run_async())
        try:
            await asyncio.wait_for(finished.wait(), timeout=timeout)
        except BaseException:
            results.put(("timeout", list(texts)))  # the transcript so far makes the failure debuggable
        finally:
            task.cancel()
            await asyncio.wait({task}, timeout=5)

    def runner() -> None:
        try:
            asyncio.run(scenario())
        except BaseException:
            pass

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    outcome = results.get(timeout=timeout + 30)
    thread.join(timeout=15)
    for name in agent_names:
        logging.getLogger(name).handlers.clear()
    logging.getLogger("bureau").handlers.clear()
    status, transcript = outcome  # type: ignore[misc]
    if status != "ok":
        raise AssertionError(f"chat session timed out after {len(transcript)} message(s). Transcript:\n" + "\n---\n".join(transcript))
    return transcript
