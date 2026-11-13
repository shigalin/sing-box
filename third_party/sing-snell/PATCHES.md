Source: github.com/sagernet/sing-snell v0.0.0-20260904135315-bc5a12ac736f.

snellv5/server.go and snellv6/server.go guard the MultiService user map with a lock: UpdateUsers replaces the map under it and authentication reads under it, so users can be updated while connections are served. UpdateUsers also accepts an empty list, which rejects every user, as the other updatable inbounds do. Remove this copy and both root/test replacements when upstream provides equivalent synchronization.

The v5/v6 Service PSKHeaderSize and MatchPSKHeader methods authenticate a
bounded first-record prefix without consuming or modifying it; callers replay
the prefix to the normal service for payload and replay validation. v6
unsafe-raw cannot probe PSKs. v5 ServiceOptions can share a ReplayCache across
per-user services. It records derived cipher keys rather than raw salts, so
replays remain rejected without allocating a Bloom filter pair per user or
rejecting an equal salt used with another PSK.
