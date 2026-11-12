Source: github.com/sagernet/sing-vmess v0.2.9-0.20261019223527-a0c58542bd9d.

service.go synchronizes authentication publication and legacy key refresh. Handshakes snapshot immutable maps before network I/O. The refresh loop supports legacy users added after Start. Remove this copy and both root/test replacements when upstream provides equivalent synchronization.

vless/service.go guards the user and flow maps with a lock; handshakes snapshot both together. Same removal condition.
