# DPoP replay and nonce stores in production

The default DPoP `jti` replay cache and DPoP nonce store are **single-node,
in-memory (ETS / process-local) stores**. They are for development and test
only. Do not run them in a multi-node deployment.

## Why the in-memory stores are dev/test only

DPoP (RFC 9449) defends against proof replay by remembering every `jti` it has
seen within the proof's acceptance window and rejecting a second use (RFC 9449
§11.1). Server-issued DPoP nonces (RFC 9449 §8 / §9) work the same way: the
nonce a client must echo is tracked server-side.

An in-memory store remembers only what *one* node has seen. With two or more
nodes behind a load balancer, a replayed proof that lands on a different node
than the original is **not** detected, because that node never saw the first
use. The replay protection silently degrades to "per-node," which is no
protection at all under any normal load-balancing.

> DPoP replay protection is only as strong as the shared store behind it. If
> the store is not shared across every node that terminates token requests, the
> protection is not real.

## What production requires

Wire a shared store that every node reads and writes:

  * **Replay check** - set `:replay_check` to a shared implementation. The
    library ships `AttestoPhoenix.Store.EctoReplayCheck`, backed by the same
    Ecto repo as the rest of the token stores:

        replay_check: &AttestoPhoenix.Store.EctoReplayCheck.check_and_record/2

  * **Nonce store** - set `:nonce_store` to a shared
    `Attesto.DPoP.NonceStore` implementation. The library ships
    `AttestoPhoenix.Store.EctoNonceStore`:

        nonce_store: AttestoPhoenix.Store.EctoNonceStore

A Redis-backed store is equally valid as long as every node shares it; the
contract is "one store, all nodes."

## TTL and the sweeper

A shared replay/nonce store accumulates rows that are only relevant for the
proof acceptance window. Two things keep it bounded:

  * **TTL** - each recorded `jti` / nonce carries an expiry tied to the
    acceptance window. An expired row can never cause a false replay rejection,
    so it is safe to delete.

  * **Sweeper** - `AttestoPhoenix.Store.Sweeper` periodically deletes expired
    rows. Start it under your supervision tree and set the interval via
    `:sweep_interval_ms` in `AttestoPhoenix.Config`:

        sweep_interval_ms: 60_000

    If `:sweep_interval_ms` is unset the sweeper is not started, and expired
    rows are retained until you prune them another way.

## Checklist

  - [ ] `:replay_check` points at a store shared by every node.
  - [ ] `:nonce_store` points at a store shared by every node.
  - [ ] The store's tables are migrated (`mix attesto_phoenix.gen.migration`).
  - [ ] `AttestoPhoenix.Store.Sweeper` is supervised with `:sweep_interval_ms`
        set, or another prune mechanism is in place.
