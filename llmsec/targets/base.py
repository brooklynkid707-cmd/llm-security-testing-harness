"""Pluggable target interface.

A target is a stateful chat session: ``start_case`` resets history and hands
over any retrieved documents for the case, then ``send`` is called once per
user turn and returns a :class:`TargetResponse`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from llmsec.models import Document, Message, TargetResponse


class Target(ABC):
    """Base class for anything the harness can scan."""

    #: short identifier shown in reports
    name: str = "target"
    #: secrets the judges may look for (``canary``, ``api_key``); empty when unknown
    secrets: dict[str, str]

    def __init__(self) -> None:
        self.secrets = {}
        self.history: list[Message] = []
        self.documents: tuple[Document, ...] = ()

    def start_case(self, documents: tuple[Document, ...] = ()) -> None:
        """Reset conversation state before a new test case."""
        self.history = []
        self.documents = documents

    @abstractmethod
    def send(self, user_text: str) -> TargetResponse:
        """Send one user turn and return the assistant's response."""

    def _record(self, user_text: str, assistant_text: str) -> None:
        self.history.append(Message("user", user_text))
        self.history.append(Message("assistant", assistant_text))

    @property
    def user_turns(self) -> list[str]:
        return [m.content for m in self.history if m.role == "user"]
