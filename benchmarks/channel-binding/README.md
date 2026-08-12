# Channel-binding differential benchmark

This harness measures three candidate deployment shapes on the same host:

1. one TLS 1.3 connection and one exporter call per authentication instance,
   representing the RFC 9266 one-instance-per-connection baseline;
2. one reused connection with the nonce supplied as exporter context and the
   exporter output used directly; and
3. one reused connection with one connection-wide exporter key, one HMAC over
   the candidate 114-byte frame per instance, and one exact replay-store insert.

It runs the same experiment against Node.js/OpenSSL and Go `crypto/tls`. The
result is performance evidence only. It does not establish the cryptographic
soundness, interoperability, or deployment safety of the multiplexed design.

Run the complete matrix:

```sh
node benchmarks/channel-binding/run.mjs \
  --samples 200 \
  --output /tmp/emilia-channel-binding-benchmark.json
```

For a quick contract check:

```sh
node --test benchmarks/channel-binding/test/*.node-test.mjs
```

The effective sample count is the larger of `--samples` and the requested
concurrency, so the 1,000-concurrent row always launches 1,000 instances. The
allocation fields are runtime estimates. Neither runtime exposes a scoped
per-operation lock-contention counter, so that field is reported as
unavailable rather than inferred.

Node exposes exporter and HMAC calls synchronously. Its reused-connection rows
therefore model concurrent authentication instances as one event-loop batch and
include queue delay from scheduling to completion. Go runs the same operations
in goroutines against one reused connection state. This runtime difference is
part of the measured implementation behavior, not proof that either design is
cryptographically preferable.
