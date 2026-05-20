# Deployment patterns

Three structural ways to deploy Provenex into an enterprise stack.
The right pattern depends on language, polyglot tolerance, and how
much per-pod state you're willing to take on.

The patterns are not exclusive: a Python-heavy team usually starts
with Pattern A and adds Pattern C only where polyglot services need
the same guarantees.

## Pattern A: SDK on every host

The simplest shape. Every app pod imports `provenex` and talks to
the same Postgres index. Best fit for Python-native stacks.

```
+--------------+    +--------------+    +--------------+
| App pod      |    | App pod      |    | App pod      |
|   provenex   |--->|   provenex   |--->|   provenex   |
+--------------+    +--------------+    +--------------+
        |                  |                  |
        +-----+------+-----+----+-----+-------+
              |      |          |     |
              v      v          v     v
        +----------------------------+
        |     Postgres index         |
        |  (or SQLite, single-node)  |
        +----------------------------+
```

**Trade-offs**

- + Lowest latency (no network hop between app and verify).
- + Each pod can carry its own per-request state.
- - Every pod runs Python. Pod density limited by the runtime.
- - Polyglot stacks (Java, Go, Rust, Node) cannot use it directly.

**Use when**: your stack is Python-first and the verify cost
(~2.2k RPS per pod at the warm-cache benchmark) is acceptable per
app pod.

## Pattern B: Sidecar container

One Provenex sidecar per app pod, accessed over the pod-local network.

```
+----------------------+
|  pod                 |
|  +----------------+  |
|  | App container  |  |
|  |   (any lang)   |--+-> localhost:8080
|  +----------------+  |    |
|  +----------------+  |    v
|  | provenex side- |  | +-------------+
|  |   car (Python) |  | | Postgres    |
|  +----------------+  |->+-------------+
+----------------------+
```

**Trade-offs**

- + Polyglot-friendly. The app needs only a thin HTTP client.
- + Per-pod isolation: each app pod has its own verify pool.
- - Doubles container count.
- - Sidecar lifecycle tied to the app pod.

**Use when**: you run a mixed-language stack and want per-pod
isolation without standing up a separate service. The Helm chart's
verify deployment is the basis; you bind it as a sidecar via
your existing pod template.

## Pattern C: Centralized verify service

A small number of Provenex pods (3-5) behind a Service; every app
pod calls into them.

```
+----------+    +----------+    +----------+
| App pod  |    | App pod  |    | App pod  |   (any language)
+----------+    +----------+    +----------+
      \             |             /
       \            |            /
        v           v           v
        +----------------------+
        | provenex-server x 3+ |
        | (FastAPI + Postgres) |
        +----------------------+
                  |
                  v
        +----------------------+
        | PgBouncer            |
        +----------------------+
                  |
                  v
        +----------------------+
        | Postgres primary +   |
        | read replicas        |
        +----------------------+
```

**Trade-offs**

- + Lowest operational surface: ~5 pods to monitor regardless of how
  many app pods exist.
- + Decouples app pod density from verify pool size.
- - Adds a service dependency on the request path.
- - Polyglot-friendly but you take on the latency of a network hop.

**Use when**: you run hundreds of app pods, or run a polyglot stack
that doesn't want a sidecar per pod, or want a single team owning
the verify infrastructure separate from the app teams.

## Sizing per pattern

| Pattern | Verify pods | Per-pod RPS | Pool size | When PgBouncer matters |
|---|---|---|---|---|
| A | N (one per app pod) | ~2.2k | 10 | Past ~50 app pods |
| B | N (one per app pod) | ~2.2k | 5-10 | Past ~50 app pods |
| C | 3-20 | 2k-15k | 10-20 | Always |

The connection-budget bench in
[docs/scaling.md#postgres-at-scale-measured-1m-chunks](scaling.md#postgres-at-scale-measured-1m-chunks)
is the source for these numbers; on a 6-core laptop Postgres saturates
at ~4 concurrent backend connections. With PgBouncer in transaction
mode you collapse 1000+ client connections onto a handful of server
connections.

## Mixing patterns

A common real-world shape: Pattern A for the Python data-science
pipeline (LangChain RAG, embedding service) and Pattern C for the
polyglot business-app tier (a Spring-Boot service and a Go
microservice). Both call into the same Postgres index; the receipts
they issue verify under the same public key. There is no incompatibility
between patterns because the wire contract is the receipt JSON, not the
runtime.

## What you install per pattern

| Component | Pattern A | Pattern B | Pattern C |
|---|---|---|---|
| `provenex-core` (Python SDK) | every pod | sidecar only | server pods only |
| `provenex-core[server]` | not required | sidecar | server pods |
| `provenex-core[postgres]` | every pod | sidecar | server pods |
| Helm chart | not required | optional (sidecar template) | yes |
| Operator | not required | optional | yes (for Policy CRs) |
