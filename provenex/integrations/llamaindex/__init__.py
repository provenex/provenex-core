"""LlamaIndex integration: drop-in retriever middleware and ingestor.

LlamaIndex is an optional dependency. Install with:

    pip install provenex-core[llamaindex]
"""

from .ingestor import IngestionResult, ProvenexIngestor
from .retriever import ProvenexRetriever, RetrievalResult

__all__ = [
    "IngestionResult",
    "ProvenexIngestor",
    "ProvenexRetriever",
    "RetrievalResult",
]
