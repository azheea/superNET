# Local changes to smoltcp 0.14.0

Vendored from crates.io (0BSD) and wired in with `[patch.crates-io]` in the
workspace `Cargo.toml`. Search `superNET patch` in `src/` for every change.

1. `socket/tcp.rs`, segment acceptability: when a segment's data falls outside
   the receive window, still process its ACK and window fields (RFC 9293
   3.10.7.4 "special allowance ... to accept valid ACKs"), then reply as
   before (challenge ACKs stay rate-limited per RFC 5961).

   Found with `supernet-wg`'s `stress_echo` test: with 256 KiB buffers
   (window scale 2), rounding the advertised window down could move its right
   edge back by up to 3 bytes. The peer's in-flight bytes there were rejected,
   its later pure ACKs carried a sequence number past our zero window and were
   rejected as a whole, so our sending direction stalled for seconds (RTO
   backoff), sometimes past 20 s.

2. `socket/tcp.rs`, zero-window probe: probe with the first unacknowledged
   byte instead of the next unsent one. The trace showed a sender probing at
   offset 4 forever while the peer was missing bytes 0..4.

3. `socket/tcp.rs`, leaving zero-window probing: when the window reopens with
   unacknowledged data in flight, resend from the first unacknowledged byte.
   smoltcp set the timer to idle here, so dropped bytes were never resent
   unless new data produced duplicate ACKs.

4. `socket/tcp.rs`, receive window: remember the furthest right edge ever
   advertised (`rx_promised_edge`) and accept data up to it. Rounding the
   scaled window down could pull the edge back by up to 3 bytes, so segments
   the peer legitimately sent were dropped and recovered only by RTO (1 s,
   then backoff). The promised space always still fits in the buffer.

5. `socket/tcp.rs`, LAST-ACK: an ACK that does not acknowledge our FIN was
   answered with a challenge ACK and discarded, including its window update.
   After `close()` with data still queued the socket is already in LAST-ACK,
   so a peer reopening a zero window was ignored until the probe timer fired
   (1 s). Now only true duplicates (same window) are challenged.

6. `socket/tcp.rs`, `RTTE_MIN_RTO` 1000 ms → 200 ms (Linux's value). With 2 %
   loss a 1 MiB echo took 9–32 s, mostly waiting out 1 s retransmit floors.

7. `socket/tcp.rs`, retransmit timer: after a retransmit/fast-retransmit
   fires, keep a future retransmit timer armed while anything (data or FIN)
   is unacknowledged instead of going idle. Under 2 % loss a lost FIN followed
   by duplicate ACKs triggered a fast retransmit that cannot resend a lone
   FIN; with the timer idle the connection hung until the 25 s keep-alive.
