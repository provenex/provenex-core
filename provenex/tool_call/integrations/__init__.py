"""Framework integrations for tool-call admission.

Each integration is a thin shim over :func:`provenex.admission_check`.
The wrapper builds a :class:`ToolCallContext` from the framework's
idiom, runs admission, and either invokes the underlying tool or
surfaces a denial. Receipt shape and policy DSL are identical across
all wrappers — that's load-bearing: a receipt produced via the
LangChain wrapper must be byte-identical (modulo id/timestamp) to the
same call routed through MCP middleware. The standard does not
fragment by framework.
"""
