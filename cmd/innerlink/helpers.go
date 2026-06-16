package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/weishengsuptp/innerlink-core/internal/identity"
)

// identityHex renders a 16-byte PeerID as the 32-char lowercase
// hex string used throughout the CLI's log output.
func identityHex(pid []byte) string {
	return hex.EncodeToString(pid)
}

// hexToBytes decodes a hex-encoded PeerID into the raw 16 bytes.
// Returns an error if the input is the wrong length or not hex.
func hexToBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != identity.PeerIDSize {
		return nil, errBadPeerIDLen
	}
	return b, nil
}

var errBadPeerIDLen = errors.New("peer id must be 32 hex chars (16 bytes)")

// hostname returns a human-readable label for this device. It
// uses $HOSTNAME if set, otherwise os.Hostname, otherwise a
// fallback string. This is what gets announced in discovery
// packets so peers can see "who's that" without knowing the
// 16-byte PeerID yet.
func hostname() string {
	if h := os.Getenv("HOSTNAME"); h != "" {
		return h
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "innerlink-node"
}

// defaultSaveDir returns the directory where incoming files
// are written. We prefer ~/Downloads/innerlink; if HOME is
// not set, we fall back to the current working directory.
func defaultSaveDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		cwd, cerr := os.Getwd()
		if cerr != nil {
			return "", cerr
		}
		return filepath.Join(cwd, "downloads"), nil
	}
	return filepath.Join(home, "Downloads", "innerlink"), nil
}