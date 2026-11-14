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
prefix can be forwarded. Vectorised writers preflight the entire batch before
changing cipher state, so a rejected suffix cannot break a later valid write.

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
