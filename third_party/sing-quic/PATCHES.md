Source: github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4.

hysteria/service.go, hysteria2/service.go and tuic/service.go guard the user maps with a lock. UpdateUsers replaces them under the lock and authentication snapshots them (tuic: user and password map together). Remove this copy and both root/test replacements when upstream provides equivalent synchronization.

The Hysteria2 server and client use the Salamander fixes from fad401c and
a5639ae: short packets report zero payload bytes, slice-based writes preserve
the caller's data, and vectorised packet writes transfer buffer ownership only
once. The Hysteria v1 XPlus wrappers incorporate 8aab71d for the same slice and
buffer ownership rules and return payload lengths excluding the salt.
Regression tests cover the client and packet wrappers, including error paths.

The shared congestion controllers incorporate the ACK pacing fix from
5253224. The shared QUIC entry points use the UDP socket sizing from 0979e00,
including for Hysteria2 obfuscation and Realm sockets, with quic-go
v0.61.0-sing-box-mod.14.
