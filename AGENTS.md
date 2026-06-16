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
