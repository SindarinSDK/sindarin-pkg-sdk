# `test_persistent_rpc_burst` flaky under parallel CPU load

**Status:** Open. Pre-existing. Not caused by the resilience test work; that
work *exposes* it by adding CPU pressure that other parallel test processes
must compete with.

**File:** `tests/net/test_quic.sn` — `test_persistent_rpc_burst` (line ~336)

**Failure mode:**

```
test_persistent_rpc_burst: FAIL (exit code: 1) ~3.7s
Client stream 43 should be open (stream budget exhausted?)
```

The assertion is `assert(!cs.isClosed(), ...)` immediately after
`client.openStream()` inside the 300-iteration loop. It fires at an
iteration that varies between runs (typically 30–80) but well under the
default `initial_max_streams_bidi` of 100 — so **the "stream budget
exhausted" hint in the message is misleading**. Something else is making
the freshly-opened stream report closed.

## Reproduction

```sh
# Direct reproduction under concurrent CPU load. Takes 1–10 runs.
for i in $(seq 1 10); do
  /tmp/test_quic_resilience > /dev/null 2>&1 &
  BG=$!
  ASAN_OPTIONS=detect_leaks=0 /tmp/test_quic_orig > /tmp/tq.log 2>&1
  R=$?
  kill $BG 2>/dev/null
  wait 2>/dev/null
  [[ $R -ne 0 ]] && { echo "run $i FAIL"; tail /tmp/tq.log; break; }
done
```

Or via `make test` at default parallelism (20 workers) — flake rate ~5–10%
historically, rose when the resilience suite was being iterated on.

Runs reliably in isolation (no concurrent test processes). Runs reliably
at `--parallel 4` or lower.

## What's ruled out

- **Not stream budget exhaustion.** Iteration 43 ≪ budget 100. The
  assertion message is wrong. Additionally, the `QUIC_CMD_OPEN_BIDI` retry
  loop (added in this cycle — see
  [the handler in `src/net/quic.sn.c`](../../src/net/quic.sn.c)) retries on
  `NGTCP2_ERR_STREAM_ID_BLOCKED` for ~2 seconds. If budget were the
  culprit, the retry would bridge the gap — it does not.

- **Not caused by the resilience test suite.** Moving the resilience
  tests into a separate sequential pass (`tests_resilience/`) reduced
  but did not eliminate the flake. The pre-existing race is exposed by
  any CPU-heavy concurrent workload, not specifically QUIC-related
  contention.

- **Not caused by the recent `sn_quic_stream_write_line` UAF fix.** Same
  flake rate before and after.

- **Not caused by `settings.handshake_timeout` wiring.** This only
  affects the handshake path, not steady-state stream opens.

## Open hypotheses

1. **Race between `quic_stream_close_cb` and `quic_find_or_create_stream`
   on `ci->streams[]`.** The close callback walks `ci->streams[]` and
   removes the entry without holding any mutex
   (`src/net/quic.sn.c:773-793`). `find_or_create_stream` also reads and
   appends to the same array without a mutex (`src/net/quic.sn.c:854-882`).
   Under normal conditions both run on the I/O thread so they're
   serialized, but `accept_stream` calls `find_or_create_stream` from
   the app thread under `conn_mutex` — and the close callback does NOT
   take `conn_mutex`. Cross-thread access is unsynchronised. The client
   side of `test_persistent_rpc_burst` doesn't go through `accept_stream`,
   so this specific race shouldn't apply to the client, but the server
   side of this test *does* — and any corruption on the server side can
   produce stale state that the client observes as a dead stream on
   the next open. Worth verifying.

2. **Stream `si->closed` being set too eagerly by
   `quic_io_thread_cleanup` on a transient error.** The I/O thread
   cleanup walks all streams and marks them closed. If a transient
   read/write error briefly triggers a cleanup path (not yet identified),
   later opens could return a stream whose internal state was already
   marked closed. The `si->closed` flag is currently set in three places:
   - `stream_close_cb` — the normal final-close path
   - `io_thread_cleanup` — on I/O thread exit
   - `sn_quic_connection_close` — user-initiated close

3. **Server-side I/O thread starvation delaying `stream_close_cb` past
   the client's next `openStream`.** Under heavy scheduler pressure, the
   server's I/O thread might take long enough to process the previous
   stream's close that the client side sees a stale `streams[]` entry
   with `closed=true` when the next `openStream` runs
   `find_or_create_stream`. Dumping stream ID and `closed` state at the
   moment of the assertion would confirm or refute this.

4. **Stream-ID collision.** If the server-side cleanup leaves a stale
   entry in `ci->streams[]` with an old `stream_id`, and ngtcp2
   happens to reuse that ID for the next bidi stream (unlikely — IDs
   monotonically increase), `find_or_create_stream` would return the
   stale closed stream instead of creating a fresh one. Very unlikely
   given how QUIC stream IDs work, but listing for completeness.

## What to check next

1. **Add instrumentation to `test_persistent_rpc_burst`.** When the
   assertion fires, dump: the stream's `stream_id`, `si->closed` value,
   `ci->stream_count`, `ci->closed`, and whether the stream pointer
   looks plausible. This is the cheapest win — tells us which
   hypothesis is live.

2. **Run under TSAN.** ThreadSanitizer should flag any unsynchronised
   access to `ci->streams[]` or `si->closed`. If hypothesis 1 is
   correct, TSAN will point at the exact lines.

3. **Add `conn_mutex` protection around every access to `ci->streams[]`
   and `ci->stream_count`.** This fixes hypothesis 1 by construction.
   It has a perf cost (every read_pkt callback acquires the mutex),
   but the race-free version is the right baseline — can optimise
   with more granular locking later.

4. **Consider giving `ci->streams[]` its own mutex** (`stream_list_mutex`)
   separate from `conn_mutex`. Reduces lock contention compared to
   reusing `conn_mutex`.

## Why this is documented here and not fixed now

Diagnosing and fixing this requires TSAN runs or targeted instrumentation
that would significantly expand the current change scope. The primary
goal of the resilience test work was to add failure-mode coverage and
fix bugs that the resilience tests expose — this particular flake
pre-existed, is in a test file, and the resilience work has been
deliberately kept independent from it via the two-pass `make test`
structure so it does not block the resilience suite from landing.
