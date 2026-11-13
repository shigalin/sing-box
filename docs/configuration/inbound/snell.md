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
Selection uses bounded authenticated-header probing with a 15-second deadline
and a maximum of 16 pending lookups per inbound. Lookup cost grows linearly
with the active user count; this extension is not a constant-time user lookup.
