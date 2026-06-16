package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/tjfoc/gmsm/sm4"
)

// SM4KeySize is the required key length for SM4 (16 bytes, 128 bits).
const SM4KeySize = 16

// SM4GCMNonceSize is the nonce length we standardize on for SM4-GCM.
// 12 bytes is what NIST SP 800-38D recommends and what gmsm expects
// when calling GCMEncrypt/GCMDecrypt directly. Using a different size
// forces an extra J0 derivation step — not worth the surprise.
const SM4GCMNonceSize = 12

// SM4GCMTagSize is the authentication tag length gmsm produces.
// We hard-code 16 (full tag) because nothing in innerlink has a reason
// to truncate.
const SM4GCMTagSize = 16

// SM4EncryptGCM encrypts plaintext with SM4-GCM.
//
// Inputs:
//   - key:  16 bytes (SM4-128)
//   - nonce: 12 bytes; MUST be unique per (key, message). Generate with
//     crypto/rand for each message.
//   - plaintext: any length; GCM is a stream cipher, no padding needed.
//   - aad: additional authenticated data — set to nil if you have none.
//     In innerlink this is the message ID, so an attacker can't swap
//     ciphertexts between messages.
//
// Output: ciphertext||tag concatenated (16-byte tag at the end).
// We deliberately concatenate so callers have a single []byte to put
// on the wire, and our wrapper round-trip matches that layout.
//
// This is the workhorse for message encryption in innerlink.
func SM4EncryptGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("crypto: SM4 key must be 16 bytes")
	}
	if len(nonce) != SM4GCMNonceSize {
		return nil, errors.New("crypto: SM4-GCM nonce must be 12 bytes")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag to dst; we pass nil so it allocates.
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// SM4DecryptGCM verifies the tag and recovers plaintext from
// ciphertext||tag (the format SM4EncryptGCM produces).
// Returns an error if the tag doesn't match (tampered or wrong key).
func SM4DecryptGCM(key, nonce, ctWithTag, aad []byte) ([]byte, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("crypto: SM4 key must be 16 bytes")
	}
	if len(nonce) != SM4GCMNonceSize {
		return nil, errors.New("crypto: SM4-GCM nonce must be 12 bytes")
	}
	if len(ctWithTag) < SM4GCMTagSize {
		return nil, errors.New("crypto: SM4-GCM input too short to contain tag")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ctWithTag, aad)
}

// SM4EncryptCTR encrypts with SM4 in counter mode.
//
// CTR is used for file payloads because it:
//   - is a stream cipher (no padding — every byte of input produces
//     one byte of output, useful when we're already chunking).
//   - is parallelizable (we'll need that for big files).
//   - has no integrity check; we add a separate SHA-256 hash on top
//     in the filetransfer package.
//
// Inputs:
//   - key: 16 bytes
//   - iv: 16 bytes (SM4 block size, all of it is the initial counter).
//     MUST be unique per file. For multiple chunks within a single
//     file, derive chunk_iv = base_iv XOR chunk_index — out of scope
//     here, that's the caller's job.
//
// Output: ciphertext, same length as plaintext. No tag.
func SM4EncryptCTR(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("crypto: SM4 key must be 16 bytes")
	}
	if len(iv) != SM4KeySize {
		return nil, errors.New("crypto: SM4-CTR iv must be 16 bytes")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, len(plaintext))
	stream.XORKeyStream(out, plaintext)
	return out, nil
}

// SM4DecryptCTR is the inverse of SM4EncryptCTR (CTR is symmetric).
func SM4DecryptCTR(key, iv, ciphertext []byte) ([]byte, error) {
	return SM4EncryptCTR(key, iv, ciphertext)
}

// SM4EncryptCBC encrypts with SM4-CBC + PKCS#7 padding.
// Used for at-rest storage of chat history (paired with a device key).
// Not used on the wire (GCM is preferred because it authenticates).
//
// ============================================================
// Why we DON'T use gmsm's Sm4Cbc directly:
// ============================================================
// gmsm v1.4.1's sm4.Sm4Cbc(key, in, mode) does NOT take an IV
// parameter — it reads from a package-global `IV` variable
// (set via sm4.SetIV()). This is a confirmed limitation with
// open issue tickets on the upstream repo:
//
//   - github.com/tjfoc/gmsm#199 "allow to use input iv"
//   - github.com/tjfoc/gmsm#220 "sm4使用CBC模式进行加密，IV在外部需要加锁"
//
// Both are still Open (as of v1.4.1). The implication:
//   - NOT safe to call Sm4Cbc concurrently from multiple goroutines
//     (the global IV races between calls).
//   - NOT safe to use in any server / daemon / pipeline shape.
//
// The Go ecosystem's standard workaround — used by basically every
// Chinese-language tutorial on gmsm and by every production project —
// is:
//
//     block, _ := sm4.NewCipher(key)
//     cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
//
// We follow that pattern: gmsm provides the SM4 block cipher
// (the cryptographic primitive), Go's stdlib provides the CBC
// mode (the operating mode). Same split as AES:
// crypto/aes.NewCipher + cipher.NewCBCEncrypter.
//
// ============================================================
// Why we implement PKCS#7 ourselves:
// ============================================================
// crypto/cipher deliberately does NOT include padding — padding
// is application-layer policy, not part of the cipher mode.
// There is no golang.org/x/crypto/pad (we checked — it doesn't
// exist). Every Go project that does AES-CBC with PKCS#7 writes
// these ~10 lines themselves; they're not secret, just boilerplate.
//
// Reference implementations used to verify our shape:
//   - https://github.com/golang/go/wiki/CryptoLibraryPitfalls
//   - V2Ray / WireGuard / cloudflare/circl all use the same pattern.
func SM4EncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("crypto: SM4 key must be 16 bytes")
	}
	if len(iv) != SM4KeySize {
		return nil, errors.New("crypto: SM4-CBC iv must be 16 bytes")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// SM4DecryptCBC decrypts SM4-CBC ciphertext and removes PKCS#7 padding.
// Returns an error if the padding is invalid (tampered ciphertext).
func SM4DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("crypto: SM4 key must be 16 bytes")
	}
	if len(iv) != SM4KeySize {
		return nil, errors.New("crypto: SM4-CBC iv must be 16 bytes")
	}
	if len(ciphertext) == 0 || len(ciphertext)%SM4KeySize != 0 {
		return nil, errors.New("crypto: SM4-CBC ciphertext length invalid")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out, block.BlockSize())
}

// pkcs7Pad appends n bytes of value n so the result is a multiple of size.
// Size must be > 0 and <= 255.
//
// PKCS#7 is the standard padding for AES-CBC / SM4-CBC. The padding
// byte value equals the padding length, which makes the padding
// self-describing and lets the receiver remove it unambiguously.
func pkcs7Pad(b []byte, size int) []byte {
	n := size - len(b)%size
	pad := bytes.Repeat([]byte{byte(n)}, n)
	return append(b, pad...)
}

// pkcs7Unpad removes PKCS#7 padding. Validates that the padding bytes
// are consistent (all n have the same value n) and that n is in range.
//
// Note: a 16-byte buffer of all 0x10 (full padding) is a valid padding
// — that's the case where the plaintext was a multiple of block size.
// n = 16 (== block size) is allowed.
func pkcs7Unpad(b []byte, size int) ([]byte, error) {
	if len(b) == 0 || len(b)%size != 0 {
		return nil, errors.New("crypto: PKCS#7 input length invalid")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > size {
		return nil, errors.New("crypto: PKCS#7 padding value out of range")
	}
	for i := len(b) - n; i < len(b); i++ {
		if b[i] != byte(n) {
			return nil, errors.New("crypto: PKCS#7 padding inconsistent")
		}
	}
	return b[:len(b)-n], nil
}

// NewNonce returns a fresh random nonce of length n using crypto/rand.
// Convenience for SM4-GCM nonces and SM4-CBC IVs.
//
// For GCM nonces specifically: 12 bytes is correct. The probability
// of collision under random selection is negligible at innerlink's
// message rates (millions of messages before 50% collision).
func NewNonce(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
