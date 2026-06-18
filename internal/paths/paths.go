// Package paths owns the on-disk layout for innerlink state and
// runtime files. It is the single source of truth for "where does
// the device key live", "where do received files go", etc. — the
// cmd/innerlink binary asks this package for a Layout, then hands
// the relevant fields to the right subsystem (identity, alias,
// storage, filetransfer, logx).
//
// Why a dedicated package:
//
//  1. Hard-coded path strings are scattered across internal/identity
//     (DefaultDeviceKeyPath), internal/alias (DefaultPath),
//     cmd/innerlink/helpers.go (defaultSaveDir), and the log file
//     default in cmd/innerlink/main.go. Adding a new state file
//     today requires editing every one of them.
//
//  2. The user (2026-06-18) wants all state under the current
//     working directory so a test directory is self-contained and
//     "rm -rf test-dir" is a complete uninstall. We need one place
//     that knows how to compute that layout from a base directory.
//
//  3. Future flexibility: when the user adds a GUI / installer /
//     config file, the Layout type is what they fill in. Nothing
//     else has to change — the cmd layer will just construct
//     Layout from a config file's contents instead of CLI flags.
//
// Default layout rooted at <cwd>:
//
//	<cwd>/
//	├── .innerlink/         ← internal state (hidden)
//	│   ├── device.key
//	│   ├── aliases.json
//	│   └── chat.enc
//	├── received/           ← user-facing: incoming files
//	│   └── <filename>
//	└── innerlink.log       ← human-readable log
//
// Every default is overridable via the Overrides struct (which the
// cmd layer fills from CLI flags). The result is a single Layout
// value that gets passed to every subsystem.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// Layout describes where every piece of innerlink state lives on
// disk. All fields are absolute paths. None of the directories or
// files are guaranteed to exist; call Ensure() to create them.
type Layout struct {
	// DataDir is the root for internal state. Default: <cwd>/.innerlink
	DataDir string
	// DeviceKey is the SM2 private key file. Default: <DataDir>/device.key
	DeviceKey string
	// Aliases is the alias-store JSON file. Default: <DataDir>/aliases.json
	Aliases string
	// ChatLog is the encrypted chat history (M3). Default: <DataDir>/chat.enc
	ChatLog string
	// Roster is the peer directory JSON (M5 gossip). Default: <DataDir>/roster.json
	Roster string
	// Received is the directory for incoming files (M2). Default: <cwd>/received
	Received string
	// LogFile is the log destination. Default: <cwd>/innerlink.log
	LogFile string
}

// Overrides lets a caller (typically the cmd layer) override any
// of the default locations. An empty string means "use the
// default derived from cwd". A non-empty string is used verbatim
// (it can be relative — the Layout's fields are all converted to
// absolute paths before being returned).
type Overrides struct {
	DataDir   string // -data-dir
	DeviceKey string // -device-key
	Aliases   string // -aliases (rare; usually derived from DataDir)
	Roster    string // -roster (rare; usually derived from DataDir)
	SaveDir   string // -save-dir (overrides Received)
	LogFile   string // -log-file
}

// NewLayout computes the on-disk layout for innerlink rooted at
// the given working directory, applying any non-zero overrides.
// The returned Layout has all fields set to absolute paths.
//
// NewLayout does NOT create any directories. Call Ensure() for
// that — keeping the function side-effect-free makes it easy to
// test.
func NewLayout(cwd string, o Overrides) (Layout, error) {
	if cwd == "" {
		// Fall back to os.Getwd if the caller didn't supply one.
		// This makes the function safer for the cmd layer when
		// invoked before the flag-default-resolution pass.
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return Layout{}, fmt.Errorf("paths: cannot determine cwd: %w", err)
		}
	}

	// 1. DataDir. If overridden, use as-is (still need to
	//    re-anchor relative paths to cwd so the rest of the
	//    computation has an absolute base).
	dataDir := o.DataDir
	if dataDir == "" {
		dataDir = filepath.Join(cwd, ".innerlink")
	} else if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(cwd, dataDir)
	}

	// 2. Files inside DataDir. If the caller supplied a
	//    DeviceKey explicitly, use it. Otherwise derive from
	//    DataDir. Aliases and ChatLog are always derived from
	//    DataDir (no override exists today; the field is here
	//    for future flexibility).
	deviceKey := o.DeviceKey
	if deviceKey == "" {
		deviceKey = filepath.Join(dataDir, "device.key")
	} else if !filepath.IsAbs(deviceKey) {
		deviceKey = filepath.Join(cwd, deviceKey)
	}

	aliases := o.Aliases
	if aliases == "" {
		aliases = filepath.Join(dataDir, "aliases.json")
	} else if !filepath.IsAbs(aliases) {
		aliases = filepath.Join(cwd, aliases)
	}

	chatLog := filepath.Join(dataDir, "chat.enc")

	// Roster: the LAN peer directory. M5 gossip keeps
	// this loosely consistent across nodes; the file
	// itself is just local persistence so a restart
	// doesn't lose the "phone book".
	roster := o.Roster
	if roster == "" {
		roster = filepath.Join(dataDir, "roster.json")
	} else if !filepath.IsAbs(roster) {
		roster = filepath.Join(cwd, roster)
	}

	// 3. Received directory. Lives next to .innerlink (sibling),
	//    not inside it, so the user can browse received files
	//    without clicking through a hidden folder.
	received := o.SaveDir
	if received == "" {
		received = filepath.Join(cwd, "received")
	} else if !filepath.IsAbs(received) {
		received = filepath.Join(cwd, received)
	}

	// 4. Log file. Sits at cwd root, not inside .innerlink,
	//    because it's the file the user opens to debug "why
	//    didn't it work".
	logFile := o.LogFile
	if logFile == "" {
		logFile = filepath.Join(cwd, "innerlink.log")
	} else if !filepath.IsAbs(logFile) {
		logFile = filepath.Join(cwd, logFile)
	}

	return Layout{
		DataDir:   dataDir,
		DeviceKey: deviceKey,
		Aliases:   aliases,
		ChatLog:   chatLog,
		Roster:    roster,
		Received:  received,
		LogFile:   logFile,
	}, nil
}

// Ensure creates the directories in the Layout if they don't
// already exist. Idempotent. Returns the first error encountered
// (subsequent creations are skipped).
//
// Why this lives here rather than in each subsystem: it lets the
// cmd layer do one MkdirAll call up front and log the resolved
// paths once, before any subsystem reads or writes anything. The
// subsystems themselves (alias, storage, filetransfer) are still
// defensive — they MkdirAll their own parent dirs on first write
// — but having the Layout do it up front means the user sees
// "data dir: <path>" in the startup log and can sanity-check it.
func (l Layout) Ensure() error {
	for _, dir := range []string{l.DataDir, filepath.Dir(l.Received), filepath.Dir(l.LogFile)} {
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("paths: mkdir %s: %w", dir, err)
		}
	}
	return nil
}
