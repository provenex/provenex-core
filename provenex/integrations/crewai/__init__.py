"""CrewAI integration: session-scoped trajectory and tool verification.

CrewAI tools don't share state across calls — there's no state dict to
thread a trajectory cursor through, unlike LangGraph. Instead, this
integration supplies a :class:`ProvenexCrewSession` that owns a trajectory
cursor and a receipt list for the duration of a crew run, and produces
wrapped tool callables that share that session.

The integration does NOT import ``crewai`` itself. CrewAI tools are
ultimately callables; our wrapper preserves the callable shape, so a
wrapped tool drops into any place a CrewAI Tool / @tool function fits.
Install ``provenex-core[crewai]`` for the discovery hint.

Memory-store pattern
--------------------

CrewAI's memory subsystems (short-term, long-term, entity) are read/write
content stores backed by a vector DB. The Provenex pattern is:

    * **On write**: fingerprint the content via
      :class:`provenex.integrations.langchain.ProvenexIngestor` (the
      ingestor is framework-agnostic — the name is historical). Each
      memory-write is a ``step_kind="memory_write"`` trajectory step.
    * **On read**: verify the retrieved content via
      :meth:`ProvenexCrewSession.verify_chunks` with
      ``step_kind="memory_read"``.

This is a usage pattern, not new code; see ``test_crewai_integration.py``
for a runnable example.
"""

from .session import ProvenexCrewSession, VerifiedChunks

__all__ = ["ProvenexCrewSession", "VerifiedChunks"]
