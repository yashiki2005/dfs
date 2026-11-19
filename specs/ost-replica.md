# OST Read Replicas and Multiple Endpoints

> **English** | [日本語](ost-replica.ja.md)

## Assumptions

dfs has a single writer per subtree. Writes are completed on the writer node's **primary OST**,
and OSTs on other nodes are treated as read-only replicas.

- Primary OST: the OST where the writer first places chunks
- Replica OST: an OST that copies and retains chunks from the primary OST
- locator: holds both the primary OST and replica OSTs in `endpoints`

Replica OSTs are not write targets. Multi-writer configurations or direct `announce` calls
to a replica OST are out of scope.

In addition, per-version BitTorrent archives are handled as a separate layer for long-term
retention and last-resort recovery. See `specs/bittorrent.md` for details.

A libp2p/QUIC chunk source can also be used as an additional read-only path.
See `specs/libp2p.md` for details.

## Writes

1. The writer creates a snapshot and sends chunks to the primary OST.
2. Once the upload to the primary OST succeeds, all chunks included in that version are copied to the replica OST(s).
3. Only missing chunks are sent to the replica OST using `batch_has`.
4. Even if a replica OST is down or fails, the write to the primary OST is considered successful.
5. Replication failures are recorded as warnings.
6. On the next push, all chunks in the current tree are targeted for replication again
   (any chunks missed in the previous failure catch up here).

Chunks are content-verified by `wire_id`. If a chunk with the same `wire_id` already exists on
the replica OST, it is not re-sent.

## Reads

`endpoints` in the locator lists the primary OST first, followed by replica OSTs.

- Read clients try endpoints in order.
- If the primary OST is down, times out, or is missing a chunk, the client tries the next endpoint.
- The write `OSTClient` is pinned to the primary OST.
- The read-only `FailoverOSTClient` uses whichever endpoint it successfully connected to as the read target for that session.

Metadata retrieval for `cat` / `pull` / `ls` is combined with L2 multi-registry fallback.

## Failure Semantics

| Failure | Behavior |
|---|---|
| Write to primary OST fails | push fails; L4 head is not advanced |
| Copy to replica OST fails | push succeeds; a warning is emitted and retried on the next push |
| Read from primary OST fails | tries replica OST |
| Read from all OSTs fails | read fails |
| Writer node is down | writes stop because of the single-writer model; reads can continue via replica OST and multiple registries |

A spooling model is not used. Writes are assumed to complete on the primary OST, and there is no
mechanism to buffer uncommitted local writes.

## Configuration

```bash
# Writer: register primary OST and replica OST
dfscli create scw \
  --registry http://primary-registry:9440 \
  --registry-alternate http://secondary-registry:9440 \
  --ost 127.0.0.1:19443 \
  --ost-alternate 127.0.0.1:19453
```

In `remotes.json`, this is stored as:

```json
{
  "ost": "127.0.0.1:19443",
  "ost_alternates": ["127.0.0.1:19453"]
}
```

Readers also discover replica OSTs from `endpoints` in the locator, so `--ost-alternate` can
usually be omitted. When specified in config, it is used as a fallback on initial reads if the
primary OST is down.

## Limitations

- Replica OSTs are read-only. There is not yet a feature to promote a replica OST alone to be a writer.
- The contents of a replica OST may be temporarily stale until the next push.
- If both the writer node and the primary OST go down at the same time, unreplicated chunks cannot be read.
- There is no per-chunk complete replication log or quorum.

## Regression Tests

- `tests/test_availability.py::AvailabilityCase::test_read_fails_over_to_replicated_ost`
- Pulling from the replica OST and locator endpoints succeeds after the primary OST stops.
- The locator `endpoints` contains both primary and replica (2 endpoints).
- All chunks on the primary OST exist on the replica OST.
