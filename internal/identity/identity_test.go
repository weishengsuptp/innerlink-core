package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateProducesValidIdentity(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if id == nil {
		t.Fatal("Generate returned nil identity")
	}
	pub := id.PublicKey()
	if len(pub) != 64 {
		t.Errorf("PublicKey length = %d, want 64", len(pub))
	}
	pid := id.PeerID()
	if len(pid) != PeerIDSize {
		t.Errorf("PeerID length = %d, want %d", len(pid), PeerIDSize)
	}
}

func TestPeerIDIsDeterministicFromPublicKey(t *testing.T) {
	id, _ := Generate()
	pub := id.PublicKey()
	pid1, err := PeerIDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pid2 := id.PeerID()
	if !bytes.Equal(pid1, pid2) {
		t.Error("PeerIDFromPublicKey differs from id.PeerID()")
	}
}

func TestDifferentIdentitiesHaveDifferentPeerIDs(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	if EqualPeerIDs(a.PeerID(), b.PeerID()) {
		t.Error("two freshly-generated identities collided on PeerID (incredibly unlikely)")
	}
	if bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Error("two freshly-generated identities have identical public keys")
	}
}

func TestPeerIDHexIsLowercaseAndRightLength(t *testing.T) {
	id, _ := Generate()
	hex := id.PeerIDHex()
	if len(hex) != PeerIDSize*2 {
		t.Errorf("PeerIDHex length = %d, want %d", len(hex), PeerIDSize*2)
	}
	if strings.ToLower(hex) != hex {
		t.Error("PeerIDHex must be lowercase")
	}
}

func TestSaveAndLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "device.key") // also tests MkdirAll

	id1, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id1.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Check the file exists and has the right perms (POSIX only).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 40 {
		t.Errorf("key file size = %d, want 40", info.Size())
	}

	id2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Same PeerID after roundtrip means same underlying key.
	if id1.PeerIDHex() != id2.PeerIDHex() {
		t.Error("PeerID differs after Save/Load — key not preserved")
	}
	if !bytes.Equal(id1.PublicKey(), id2.PublicKey()) {
		t.Error("PublicKey differs after Save/Load")
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.key")
	_, err := Load(path)
	if err == nil {
		t.Error("expected error loading missing file")
	}
	if !strings.Contains(err.Error(), "read key file") {
		t.Errorf("error doesn't mention reading: %v", err)
	}
}

func TestLoadRejectsWrongMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")
	// "XXXX\x00\x00\x00\x00" + 32 bytes of garbage
	bad := append([]byte("XXXX\x00\x00\x00\x00"), bytes.Repeat([]byte{0xff}, 32)...)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error on bad magic")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error doesn't mention magic: %v", err)
	}
}

func TestLoadRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0}, 39), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error on wrong size")
	}
}

func TestLoadOrCreateGeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")

	id, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("expected created=true on first run")
	}
	if id == nil {
		t.Fatal("got nil identity")
	}

	// Second call must return the same identity, with created=false.
	id2, created2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Error("second LoadOrCreate should not create a new identity")
	}
	if id.PeerIDHex() != id2.PeerIDHex() {
		t.Error("LoadOrCreate returned different identities on the second call")
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	id1, _ := Generate()
	id2, _ := Generate()

	msg := []byte("the quick brown fox jumps over the lazy dog")
	sig, err := id1.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !id1.VerifySignature(id1.PublicKey(), msg, sig) {
		t.Error("self-verification failed")
	}
	if !id2.VerifySignature(id1.PublicKey(), msg, sig) {
		t.Error("cross-verification failed (peer can't verify our signature)")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	id1, _ := Generate()
	msg := []byte("hello world")
	sig, _ := id1.Sign(msg)

	bad := append([]byte(nil), msg...)
	bad[0] ^= 0x01
	if id1.VerifySignature(id1.PublicKey(), bad, sig) {
		t.Error("verification succeeded on tampered message")
	}
}

func TestVerifyRejectsWrongPeerKey(t *testing.T) {
	signer, _ := Generate()
	imposter, _ := Generate()
	verifier, _ := Generate()
	msg := []byte("hello")
	sig, _ := signer.Sign(msg)

	// Passing the impostor's public key (not the signer's) must fail.
	if verifier.VerifySignature(imposter.PublicKey(), msg, sig) {
		t.Error("verification succeeded using impostor's public key")
	}
	// Sanity: with the real signer's key, it should succeed.
	if !verifier.VerifySignature(signer.PublicKey(), msg, sig) {
		t.Error("verification failed with signer's own public key")
	}
}

func TestPublicKeyFromBytesRoundtrip(t *testing.T) {
	id, _ := Generate()
	pub := id.PublicKey()
	decoded, err := PublicKeyFromBytes(pub)
	if err != nil {
		t.Fatal(err)
	}
	if decoded == nil {
		t.Fatal("PublicKeyFromBytes returned nil")
	}
	if !bytes.Equal(marshalPublicKey(decoded), pub) {
		t.Error("decoded public key doesn't match original bytes")
	}
}

func TestPublicKeyFromBytesRejectsBadSize(t *testing.T) {
	if _, err := PublicKeyFromBytes(make([]byte, 63)); err == nil {
		t.Error("expected error for 63 bytes")
	}
	if _, err := PublicKeyFromBytes(make([]byte, 65)); err == nil {
		t.Error("expected error for 65 bytes")
	}
}

func TestPublicKeyFromBytesRejectsOffCurve(t *testing.T) {
	if _, err := PublicKeyFromBytes(make([]byte, 64)); err == nil {
		t.Error("expected error for all-zero input")
	}
}

func TestEqualPeerIDsHandlesSizeMismatch(t *testing.T) {
	a := bytes.Repeat([]byte{1}, PeerIDSize)
	b := bytes.Repeat([]byte{1}, PeerIDSize-1)
	if EqualPeerIDs(a, b) {
		t.Error("EqualPeerIDs returned true for different-length slices")
	}
	if !EqualPeerIDs(a, a) {
		t.Error("EqualPeerIDs returned false for same-slice comparison")
	}
}

func TestPeerIDFromPublicKeyValidatesSize(t *testing.T) {
	if _, err := PeerIDFromPublicKey(make([]byte, 63)); err == nil {
		t.Error("expected error for 63 bytes")
	}
}

func TestResolveDeviceKeyPath(t *testing.T) {
	path, err := ResolveDeviceKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %q", path)
	}
	if filepath.Base(path) != "device.key" {
		t.Errorf("expected base name 'device.key', got %q", filepath.Base(path))
	}
}
