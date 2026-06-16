# innerlink-core — Agent Notes

## Build-tag dependency pitfall (踩过的坑)

`internal/discovery/bind_unix.go` imports `golang.org/x/sys/unix`,
but is only compiled on non-Windows (`//go:build !windows`).
`bind_windows.go` uses raw `syscall` instead.

**The trap:** if you `go mod tidy` on a Windows host, the
`golang.org/x/sys` package is never imported at build time, so
`tidy` strips it from go.sum. The dependency then **silently
disappears from the repository's go.sum** and CI's Linux/macOS
runners fail with "missing go.sum entry for module providing
package golang.org/x/sys/unix".

**The fix:** promote build-tagged dependencies to **direct** requires
explicitly. Run:

```
go get golang.org/x/sys@v0.20.0
go mod tidy
```

The version number must be explicit; `@latest` will resolve to
v0.53+ which requires Go 1.25 and triggers the GOSUMDB=off
deadlock (see HANDOFF 04-LESSONS #3).

**Why we use `golang.org/x/sys/unix` only on non-Windows:** we
deliberately avoid the dependency on Windows by using raw
`syscall.SetsockoptInt` + the constant `SO_BROADCAST = 0x0020`
in `bind_windows.go` / `sockopt_windows.go`. This keeps the
Windows binary smaller and avoids the x/sys/windows dep.

**Future-proofing:** every time you add a new build-tagged file
that imports a module, double-check that `go.sum` contains the
dependency hash by running `go mod tidy` on a non-Windows host
(or in WSL) before pushing.

## CI shell quirk

The CI workflow's `go vet` / `go test` steps must use
`shell: bash` — Windows runners default to PowerShell, which
doesn't glob `./...` and breaks the commands. Already configured
in `.github/workflows/ci.yml`.

## DialStandalone bypasses heartbeat → 60s i/o timeout (踩过的坑)

`internal/transport` has two dial paths:

- `Transport.Dial(ctx, addr)` — registers the new conn in
  `t.conns`, so the heartbeat loop sends keepalives to it.
- `DialStandalone(ctx, addr)` — does **not** register, returns
  a bare Conn that the heartbeat loop never sees.

**The trap:** if the CLI uses `DialStandalone` to reach a peer
(because it's "simpler, doesn't need a Transport"), the
outbound conn goes un-beat. After `DefaultReadTimeout = 60s`
of idle, the peer's read deadline fires, the recv loop sees
`i/o timeout`, the channel dies. Both sides see the EOF
simultaneously at the 60s mark — looks like the conn just
"expired".

**The rule:** any Conn that the heartbeat loop should keep
alive **must** be created via `Transport.Dial`. Reserve
`DialStandalone` for one-shot dial-only flows (testing
helpers, future external-to-process bridges) that have
their own liveness signal.

The CLI learned this the hard way — see commit `6bbc689`:
"dialAndHandshake now takes *Transport and calls tr.Dial".

## Heartbeat frame must be distinguishable from a real payload (踩过的坑)

`heartbeatOnce` used to send a **0-byte body** frame. The
`protocol.Channel.Recv` then read `len(fr.Body) <
SM4GCMNonceSize + SM4GCMTagSize` and treated it as a
malformed envelope, returned an error, the channel closed.

**The rule:** heartbeat frames must be unambiguously distinct
from a real envelope frame. We use a **1-byte 0x00 body**,
and `Conn.Recv` transparently loops over heartbeat frames
so the protocol layer never sees them. The check is
`isHeartbeat(fr) := len(fr.Body) == 1 && fr.Body[0] == 0x00`.

If you ever change the heartbeat marker, update both the
writer (transport.heartbeatOnce) and the filter (transport
.isHeartbeat) in lockstep — there's a unit test for the
filter.

## MaxEnvelopeSize must fit one file chunk post-base64 (踩过的坑)

`protocol.MaxEnvelopeSize` caps the post-decryption envelope
size (i.e. the inner JSON). 1 MiB raw bytes become ~1.4 MiB
after base64 encoding (the `json.Marshal` of an `[]byte` payload
auto-encodes as base64). If MaxEnvelopeSize is 1 MiB the
receiver rejects any 1 MiB file chunk as "frame too large".

Rule: MaxEnvelopeSize ≥ ceil(ChunkSize * 4/3) + headroom.
Currently ChunkSize = 1 MiB and MaxEnvelopeSize = 4 MiB
(~2.6 MiB headroom for JSON keys, Envelope struct fields, etc.).

If you ever lower MaxEnvelopeSize, lower ChunkSize first.
If you ever raise ChunkSize, raise MaxEnvelopeSize first.

## `protocol.Channel.Send` is exported — don't shadow it (踩过的坑)

`Channel.send` (lowercase) is the unexported workhorse that
fills in From/TS/MsgID/Version and does the encryption. v0.1
added `Channel.Send(ctx, Envelope)` (uppercase) as the
public API used by `internal/filetransfer` to send non-chat
envelopes (file offers/chunks/etc.). Chat uses the convenience
methods (`SendText`, `SendPing`); file transfer uses `Send`.

If you add a new message type to the protocol layer, prefer
adding it via the public `Send` rather than calling `send`
directly — otherwise From/TS/MsgID/Version get skipped and
the receiver drops the envelope as malformed.

## Channel.Recv is NOT safe for concurrent callers (踩过的坑)

A `protocol.Channel` wraps a single underlying `transport.Conn`,
and `Channel.Recv` reads one frame at a time. The underlying
`Conn.Recv` is documented as single-reader; calling it from
two goroutines on the same Channel causes frames to be split
between the callers, which surfaces as random "protocol: frame
too short" / "frame too large" errors — even when neither
goroutine is sending anything weird.

**Rule:** exactly ONE goroutine per Channel may call
`Channel.Recv`. If multiple subsystems (chat pump, file
receiver, custom protocol, …) need to read from the same
Channel, write a single dispatcher that calls Recv once and
routes by `env.Type`.

`filetransfer.Receiver` ships two APIs:
  - `Receiver.Loop(ctx)` — its own pump; use when file
    traffic is the only thing on the channel.
  - `Receiver.Handle(ctx, env)` — receive-one-envelope;
    use from a shared dispatcher (the cmd/innerlink CLI
    pattern).
