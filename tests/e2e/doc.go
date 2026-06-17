// Package e2e runs the innerlink CLI as a real subprocess and
// drives it the same way a human would from a second terminal,
// except that the test asserts on the resulting log lines
// instead of on a screenshot.
//
// Why subprocess and not in-process: the CLI demo (`cmd/innerlink`)
// is intentionally the integration smoke test. It exercises
// every layer (identity, discovery, transport, handshake,
// protocol, filetransfer, storage) end-to-end. If we wrote
// only in-process tests we would miss:
//   - the OS-level port collision detection
//   - the device.key load path through os.UserHomeDir
//   - the cross-process log file append
//   - signal handling (Ctrl+C / SIGTERM)
//   - the bufio.Scanner on os.Stdin
//
// Everything the user does at a real terminal, this package
// does the same way, just from a Go test instead of from a
// human. That is what makes the e2e tests in this directory
// a true regression net for the milestones.
package e2e
