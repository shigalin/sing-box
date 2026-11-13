---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "version": 5,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "obfs_mode": ""
}
```

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "version": 6,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "mode": ""
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

==Required==

The Snell protocol version, one of `5` `6`.

Version `5` supports HTTP obfuscation (`obfs_mode`); version `6` replaces it
with traffic shaping (`mode`) and requires a `psk` of 12 to 255 bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### users

Snell users.

When set, the server runs in multi-user mode: each entry has a `name` (optional, used in
logs) and a `userkey` (the user's key).

#### obfs_mode

==Version 5 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

### Independent PSKs (fork extension)

Set `user_psk: true`, omit the shared `psk`, and provide users as
`{"name": "user-id", "psk": "user-specific-secret"}` without `userkey`.
Names and PSKs must be unique. Empty user updates reject all clients.
Both v5 and v6 encrypted modes are supported; `unsafe-raw` is rejected.
The client sends ordinary Snell wire data, so an unmodified mihomo works.

Optionally set `auth_detour` to a ShadowTLS inbound tag. In this mode the
Snell inbound opens no socket and accepts only connections forwarded from
that ShadowTLS v3 inbound, whose gateway user must have a non-empty name.
The gateway can use one shared password; it does not
select the Snell identity. The inner PSK is always verified and selects the
user for routing and accounting. Without `auth_detour`, normal listen fields
apply and PSKs are identified on the public listener.

User updates preserve services and sessions of unchanged users. Removed or
rekeyed users' transports are closed, including reused TCP and UDP tunnels.
Selection uses bounded authenticated-header probing. One 15-second deadline
covers the header and the first request: a connection stays pending, and its
source is not remembered, until the selected user's service has decrypted and
validated that request. A header that matches but is not followed by a valid
request in time is closed and returns its capacity.
At most 16 fallback candidate groups are checked concurrently per inbound;
connections wait for a slot only after data arrives. A slot is held for at most
256 candidates of one header size and then offered to the next waiting source,
so the wait for a turn does not grow with the user count; a lookup that already
started resumes ahead of new lookups from its own source and is not closed
because the queue filled up meanwhile. Source hints (up to four
users per source, 4096 addresses) are still verified cryptographically on every
connection and are checked outside those slots when enough header bytes exist.
Authentication admission also bounds pending connections and queued lookups
globally and per source. Cold lookups have a separate global budget, and
source-level token budgets limit repeated failed probes.
Fallback and hint verification have separate global token, concurrency and
queue budgets, so remembered sources cannot bypass admission entirely and a
full fallback queue does not close a connection whose hinted user can still
match. One source may use every free slot. While lookups wait, each freed slot
goes to the next waiting source in turn and to that source's oldest waiting
lookup, and a small share of the pending and queue capacity is kept for other
sources. Excess pending or queued handshakes are closed; rate-limited lookups
wait for capacity. Source limits use bursts to accommodate users behind a
shared address. If the bounded per-source accounting table is full, new sources
share the global budgets and one turn; they are not rejected solely because the
table is full. Sessions whose first request was accepted are not subject to
these handshake limits.

Hinted and fallback candidates advance independently. While a connection is
waiting for a slot, an incomplete header may be read by one bounded read-ahead
operation. This allows a fragmented v6 default header to match its hint even
when slots stay busy, and a complete longer header to match while a shorter
hinted candidate waits for its budget. An available slot can still verify a
shorter candidate immediately: it never waits for bytes required only by a
longer hint. If that shorter candidate wins, its protocol inherits the pending
read and all preread bytes in order. Closing or timing out lookup closes the
transport to interrupt any pending read. No polling intervals are introduced.

Hints reduce work when they match; they are not an admission guarantee or a
limit on total CPU use. Before enough bytes for a hint arrive, available slots
may check shorter candidates. Cold or wrong-PSK lookups remain linear in the
active user count. Connection reuse and deployment-specific capacity testing
remain important.
