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
