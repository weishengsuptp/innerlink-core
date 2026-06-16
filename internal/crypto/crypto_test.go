package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

// SM3 reference vectors from GBT 32905-2016 (the Chinese national SM3
// standard, derived from GM/T 0004-2012). The official test vectors come
// from http://www.oscca.gov.cn/News/201012/News_1199.htm and have been
// cross-verified by independent implementations in Python, PHP, C, and Go.
//
// The single-block "abc" vector is the one that catches off-by-one
// errors in the message-length encoding, which is the most common
// SM3 implementation bug.
var sm3Vectors = []struct {
	in  string
	out string // hex digest
}{
	{
		// 616263 ("abc") → 66c7f0f4 ... a8e0
		in:  "abc",
		out: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	},
	{
		// 616263 * 16 ("abcd..." × 16 = 64 bytes) → debe9ff9 ... 5732
		// (This vector exercises multi-block processing.)
		in:  "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
		out: "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
	},
}

func TestSM3OfficialVectors(t *testing.T) {
	for _, v := range sm3Vectors {
		got := hex.EncodeToString(SM3Sum([]byte(v.in)))
		if got != v.out {
			t.Errorf("SM3(%q) = %s, want %s", v.in, got, v.out)
		}
	}
}

func TestSM3StreamingEqualsOneShot(t *testing.T) {
	// Feeding a 1 MB blob byte-by-byte through the streaming API
	// must produce the same digest as a one-shot call.
	const size = 1 << 20
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatal(err)
	}

	h := SM3()
	for _, b := range buf {
		h.Write([]byte{b})
	}
	streamDigest := h.Sum(nil)

	oneShotDigest := SM3Sum(buf)
	if !bytes.Equal(streamDigest, oneShotDigest) {
		t.Errorf("streaming vs one-shot digest mismatch (size=%d)", size)
	}
}

func TestSM3ImplementsHashInterface(t *testing.T) {
	// Compile-time check that SM3() returns a hash.Hash.
	var _ interface {
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
		Reset()
		Size() int
		BlockSize() int
	} = SM3()
}

func TestSM4GCMRoundtrip(t *testing.T) {
	key, err := NewNonce(SM4KeySize)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce(SM4GCMNonceSize)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	aad := []byte("msg-42")

	ctWithTag, err := SM4EncryptGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// ctWithTag = ciphertext (len(plaintext)) || tag (16 bytes).
	if len(ctWithTag) != len(plaintext)+SM4GCMTagSize {
		t.Errorf("len(ctWithTag) = %d, want %d", len(ctWithTag), len(plaintext)+SM4GCMTagSize)
	}

	pt, err := SM4DecryptGCM(key, nonce, ctWithTag, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("decrypted != plaintext")
	}
}

func TestSM4GCMRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SM4KeySize)
	nonce := bytes.Repeat([]byte{0x01}, SM4GCMNonceSize)

	ctWithTag, err := SM4EncryptGCM(key, nonce, []byte("hello world"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit of the ciphertext portion (not the tag).
	ctWithTag[0] ^= 0x01

	if _, err := SM4DecryptGCM(key, nonce, ctWithTag, []byte("aad")); err == nil {
		t.Error("expected decryption to fail on tampered ciphertext")
	}
}

func TestSM4GCMRejectsTamperedTag(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SM4KeySize)
	nonce := bytes.Repeat([]byte{0x01}, SM4GCMNonceSize)

	ctWithTag, err := SM4EncryptGCM(key, nonce, []byte("hello world"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the trailing tag.
	ctWithTag[len(ctWithTag)-1] ^= 0x01

	if _, err := SM4DecryptGCM(key, nonce, ctWithTag, []byte("aad")); err == nil {
		t.Error("expected decryption to fail on tampered tag")
	}
}

func TestSM4GCMRejectsTamperedAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SM4KeySize)
	nonce := bytes.Repeat([]byte{0x01}, SM4GCMNonceSize)

	ctWithTag, err := SM4EncryptGCM(key, nonce, []byte("hello world"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SM4DecryptGCM(key, nonce, ctWithTag, []byte("DIFFERENT AAD")); err == nil {
		t.Error("expected decryption to fail on tampered AAD")
	}
}

func TestSM4CTRRoundtrip(t *testing.T) {
	key, _ := NewNonce(SM4KeySize)
	iv, _ := NewNonce(SM4KeySize) // CTR uses full block as counter

	// Test with sizes around the SM4 block boundary (16 bytes).
	sizes := []int{0, 1, 15, 16, 17, 1024, 65535}
	for _, n := range sizes {
		pt := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, pt); err != nil {
			t.Fatal(err)
		}
		ct, err := SM4EncryptCTR(key, iv, pt)
		if err != nil {
			t.Fatalf("encrypt n=%d: %v", n, err)
		}
		got, err := SM4DecryptCTR(key, iv, ct)
		if err != nil {
			t.Fatalf("decrypt n=%d: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("CTR roundtrip failed at size %d", n)
		}
	}
}

func TestSM4CBCRoundtrip(t *testing.T) {
	key, _ := NewNonce(SM4KeySize)
	iv, _ := NewNonce(SM4KeySize)

	pt := []byte("innerlink chat history line 1\nline 2\n")
	ct, err := SM4EncryptCBC(key, iv, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SM4DecryptCBC(key, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("CBC roundtrip failed: got %q want %q", got, pt)
	}
}

func TestSM4GCMRejectsBadKeyLength(t *testing.T) {
	_, err := SM4EncryptGCM(make([]byte, 15), make([]byte, 12), []byte("x"), nil)
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestSM4GCMRejectsBadNonceLength(t *testing.T) {
	_, err := SM4EncryptGCM(make([]byte, 16), make([]byte, 11), []byte("x"), nil)
	if err == nil {
		t.Error("expected error for short nonce")
	}
}

func TestSM4GCMRejectsInputShorterThanTag(t *testing.T) {
	// ctWithTag shorter than the tag itself is nonsensical.
	_, err := SM4DecryptGCM(make([]byte, 16), make([]byte, 12), make([]byte, 8), nil)
	if err == nil {
		t.Error("expected error on input shorter than tag")
	}
}

func TestSM2KeyGenSignVerify(t *testing.T) {
	priv, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	if priv.D == nil {
		t.Fatal("private key has nil D")
	}
	pub := &priv.PublicKey
	if pub.X == nil || pub.Y == nil {
		t.Fatal("public key has nil X/Y")
	}

	msg := []byte("handshake challenge #1")
	sig, err := SignSM2(priv, msg)
	if err != nil {
		t.Fatalf("SignSM2: %v", err)
	}
	if !VerifySM2(pub, msg, sig) {
		t.Error("verify failed on freshly signed message")
	}

	// Tamper detection: flipping any byte of msg must invalidate the sig.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0x01
	if VerifySM2(pub, bad, sig) {
		t.Error("verify succeeded on tampered message (should fail)")
	}

	// Wrong key must reject.
	other, _ := GenerateSM2Key()
	if VerifySM2(&other.PublicKey, msg, sig) {
		t.Error("verify succeeded with wrong public key")
	}
}

func TestSM2MarshalUnmarshalPublic(t *testing.T) {
	priv, err := GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey

	encoded := SM2MarshalPublic(pub)
	if len(encoded) != 64 {
		t.Fatalf("encoded length = %d, want 64", len(encoded))
	}

	decoded, err := SM2UnmarshalPublic(encoded)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.X.Cmp(pub.X) != 0 || decoded.Y.Cmp(pub.Y) != 0 {
		t.Error("decoded point does not match original")
	}

	// Verify works across the marshal boundary.
	msg := []byte("cross-boundary test")
	sig, _ := SignSM2(priv, msg)
	if !VerifySM2(decoded, msg, sig) {
		t.Error("verify failed after marshal roundtrip")
	}
}

func TestSM2UnmarshalRejectsBadSize(t *testing.T) {
	if _, err := SM2UnmarshalPublic(make([]byte, 63)); err == nil {
		t.Error("expected error on 63-byte input")
	}
	if _, err := SM2UnmarshalPublic(make([]byte, 65)); err == nil {
		t.Error("expected error on 65-byte input")
	}
}

func TestSM2UnmarshalRejectsOffCurve(t *testing.T) {
	// All zeros is not on the curve.
	if _, err := SM2UnmarshalPublic(make([]byte, 64)); err == nil {
		t.Error("expected error on all-zero input (off-curve)")
	}
}

func TestSM2MarshalPrivate(t *testing.T) {
	priv, err := GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	d := SM2MarshalPrivate(priv)
	if len(d) != 32 {
		t.Fatalf("private marshal length = %d, want 32", len(d))
	}
	if new([32]byte) == nil {
		t.Fatal("compiler sanity") // keeps linters from stripping
	}
}

func TestKDFDeterministic(t *testing.T) {
	secret := []byte("shared-secret-bytes")
	info := []byte("innerlink-handshake-v1")

	a, err := KDF(secret, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := KDF(secret, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("KDF must be deterministic for same inputs")
	}
	if len(a) != 32 {
		t.Errorf("output length = %d, want 32", len(a))
	}
}

func TestKDFDifferentInfo(t *testing.T) {
	secret := []byte("shared-secret-bytes")

	a, _ := KDF(secret, []byte("info-A"), 32)
	b, _ := KDF(secret, []byte("info-B"), 32)
	if bytes.Equal(a, b) {
		t.Error("different info must yield different output")
	}
}

func TestKDFDifferentSecret(t *testing.T) {
	info := []byte("x")

	a, _ := KDF([]byte("secret-A"), info, 32)
	b, _ := KDF([]byte("secret-B"), info, 32)
	if bytes.Equal(a, b) {
		t.Error("different secret must yield different output")
	}
}

func TestKDFLargeOutput(t *testing.T) {
	// 100 bytes spans multiple SM3 blocks (32 bytes each).
	out, err := KDF([]byte("k"), []byte("i"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 100 {
		t.Errorf("len = %d, want 100", len(out))
	}
}

func TestKDFRejectsBadLength(t *testing.T) {
	if _, err := KDF([]byte("k"), []byte("i"), 0); err == nil {
		t.Error("expected error on outLen=0")
	}
	if _, err := KDF([]byte("k"), []byte("i"), 255*SM3Size+1); err == nil {
		t.Error("expected error on outLen > SM3 limit")
	}
}

func TestNewNonceIsRandom(t *testing.T) {
	a, _ := NewNonce(16)
	b, _ := NewNonce(16)
	if bytes.Equal(a, b) {
		t.Error("two consecutive nonces collided — rand.Reader broken?")
	}
}

func TestSM3KnownStreamingVector(t *testing.T) {
	// Verify that streaming 3 chunks produces the same digest as one-shot.
	parts := []string{"in", "ner", "link"}
	h := SM3()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	got := hex.EncodeToString(h.Sum(nil))

	all := ""
	for _, p := range parts {
		all += p
	}
	want := hex.EncodeToString(SM3Sum([]byte(all)))
	if got != want {
		t.Errorf("streaming %v = %s, want %s", parts, got, want)
	}
}
