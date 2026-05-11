"""LangChain integration: drop-in retriever middleware and ingestor.

LangChain is an optional dependency. Install with:

    pip install provenex-core[langchain]
"""

from .ingestor import IngestionResult, ProvenexIngestor
from .retriever import ProvenexRetriever, RetrievalResult

__all__ = [
    "IngestionResult",
    "ProvenexIngestor",
    "ProvenexRetriever",
    "RetrievalResult",
]
