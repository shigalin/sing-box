Source: github.com/sagernet/sing-snell v0.0.0-20260904135315-bc5a12ac736f.

snellv5/server.go and snellv6/server.go guard the MultiService user map with a lock: UpdateUsers replaces the map under it and authentication reads under it, so users can be updated while connections are served. UpdateUsers also accepts an empty list, which rejects every user, as the other updatable inbounds do. Remove this copy and both root/test replacements when upstream provides equivalent synchronization.

The v5/v6 Service PSKHeaderSize and MatchPSKHeader methods authenticate a
bounded first-record prefix without consuming or modifying it; callers replay
the prefix to the normal service for payload and replay validation. v6
unsafe-raw cannot probe PSKs. v5 ServiceOptions can share a ReplayCache across
per-user services. It records derived cipher keys rather than raw salts, so
replays remain rejected without allocating a Bloom filter pair per user or
rejecting an equal salt used with another PSK.

The v5/v6 single-PSK Service calls snell.RequestAccepted once it has decrypted
and validated the first request (after the v5 replay check), before handling
it. A caller that picked the service from a header prefix registers a function
with snell.ContextWithRequestAccepted to keep its handshake deadline and
admission accounting until then; without one the call does nothing.

The v4/v6 clients and v6 server request a full UDP receive buffer using
WriterMTU. The v5 server requests one byte beyond the largest valid IPv4
response (16377 bytes), which also detects oversized IPv6 responses. This
keeps connected UDP batch buffers in the 32 KiB pool class.
Packets are checked against the wire payload bound (0x3fff for
v4/v5 and 0xffff for v6) after adding their actual address header. This
preserves valid datagrams and rejects oversized datagrams before a truncated
prefix can be forwarded. Record writers preflight their input before changing
cipher state. The v5/v6 server batch writers filter invalid responses before
passing the remaining datagrams to the record writers.

The v5/v6 servers pass the first UDP datagram from WaitReadPacket directly to
the routing layer. They advertise a ReaderMTU so routing can size its sniffing
and UDP timeout reads for a complete cached datagram in low-memory builds.

Single and vectorised packet record writers keep each datagram in one record,
including immediately after an idle reset. TCP record shaping is unchanged.
Packet tests cover IPv4/IPv6/domain address bounds, receive capacity, oversized
rejection and recovery after a rejected batch. test/snell_udp_test.go covers
bidirectional forwarding, shared/independent PSKs and reuse configuration
on/off, IPv4/IPv6 response boundaries on Linux including v5 with udp_connect,
and 8500-byte v5/v6 first datagrams with sniffing and UDP timeouts.

The v4/v6 clients advertise ReaderMTU for UDP response reads through NAT
wrappers, including route address overrides. Linux CI exercises these reads
in standard and low-memory builds.

The v5/v6 server paths incorporate the upstream EOF, reuse session lifecycle,
and dial error fixes through 7cb6221. They also incorporate the server response
behavior from 6055ff1 and 04667b0: discard non-IP responses and use EMSGSIZE for
oversized responses so forwarding can continue on the same tunnel.

The v4/v6 client paths also incorporate the matching upstream fixes:
35f4c8b distinguishes transport EOF from a protocol zero chunk, including v4
record payload/padding truncation; ff8534e and 543d2cb probe idle pooled sockets
and select ready sessions in LIFO order. The idle wrapper also preserves a
pending probe across empty reads and finishes the old watch's state transition
before handing its byte to the next logical connection. The reuse writer
synchronization, write-after-CloseWrite rejection, sticky read EOF and deadline
reset fixes from 5f17be4, 7077fca, 4c925cc and 52e3444 are retained alongside
the local MTU changes. The v4 empty Write fix from 72a9d48 makes empty writes
no-ops rather than sending a protocol EOF. Client packet batches incorporate
04667b0: discard only oversized datagrams and still send valid datagrams from
the same batch.

The v5/v6 server completion path converges through Close's single owner.
After successful completion, Close waits for the final response EOF instead
of interpreting contention with CloseWrite as a blocked write and aborting the
tunnel. Before successful completion, Close still interrupts blocked writes.
Regression tests exercise concurrent completion/close and interrupted writes;
v6 response batch tests cover all three modes and IPv4/IPv6 boundaries.

Dial error replies match native platform socket errors, using Winsock WSAE*
codes on Windows rather than Go's synthetic POSIX errno constants.

Local follow-up regressions cover data returned together with transport EOF,
server metadata reads concurrent with response initialization, and request read
failures after the response has half-closed. The server rejects failed request
streams instead of draining them, while healthy upload drains still permit the
next request. Client read completion and Close share a lock for the pool handoff,
without holding it during transport reads. Non-reusable connection writer
publication and shaped-writer headroom reads are synchronized as well.
