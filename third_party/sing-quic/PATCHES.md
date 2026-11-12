Source: github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4.

hysteria/service.go, hysteria2/service.go and tuic/service.go guard the user maps with a lock. UpdateUsers replaces them under the lock and authentication snapshots them (tuic: user and password map together). Remove this copy and both root/test replacements when upstream provides equivalent synchronization.
