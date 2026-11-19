# Registry Primary / Secondary and Manual Promotion

> **English** | [日本語](promotion.ja.md)

## Purpose

Reads can fall back to multiple registries / OSTs / libp2p. Writes are consolidated
on a single primary registry. In case the primary goes down, a secondary can be
**explicitly** promoted to primary.

This is not automatic election or consensus. It is a model where the operator stops
and isolates the old primary before promoting the secondary.

## Role and Fencing Epoch

The registry state holds the following two fields:

- `role`: `primary` or `secondary`
- `role_epoch`: promotion generation (monotonically increasing)

Only the primary accepts `/v1/delegate` and `/v1/announce`. A secondary accepts
`/v1/replicate`, but rejects writes.

The writer includes `role_epoch` from `remotes.json` in `announce`. If it does not
match the `role_epoch` on the registry side, a `ConflictError` is raised. If the old
primary has `role_epoch=1` and the promoted secondary has `role_epoch=2`, a write
with `role_epoch=2` to the old primary is rejected.

## Promotion Procedure

1. Verify that replication on the secondary has caught up to the primary:
   - `resolve` on both returns the same head version / entry_hash
   - `history` contains the required versions
2. Stop the old primary.
3. Promote the secondary's state:

```bash
dfs promote --state-dir ~/.dfs_server --role-epoch 2
```

4. Restart the secondary as primary:

```bash
dfs serve ... --role primary --role-epoch 2
```

5. Update the writer's `remotes.json`:
   - Set `registry` to the secondary's URL
   - Keep the old primary in `registry_alternates` (read-only)
   - Set `role_epoch` to 2

```bash
dfscli config create NAME \
  --registry http://secondary:9440 \
  --registry-alternate http://old-primary:9440 \
  --role-epoch 2 ...
```

6. If using DNSSEC discovery, update the primary/secondary URLs and `epoch`.

## Important Constraints

- No automatic election, quorum, or leases.
- Always stop the old primary before promoting.
- Do not restart the old primary and let both run as primary.
- A writer with an old `role_epoch` can still write to the old primary, so update
  writer configurations at the same time.
- If strong split-brain prevention is required, add leases, fencing tokens, or consensus.

`role_epoch` is a fencing value indicating "explicit promotion has occurred" and does not
resolve network partitions by itself.

## Regression Tests

- `tests/test_availability.py`: secondary write rejection
- `tests/test_availability.py`: `role_epoch` mismatch rejection
- `tests/test_availability.py`: state promote and epoch persistence
