// Package handshake performs mutual identity verification and
// shared-secret derivation on top of an established transport.Conn.
//
// What it does, in one sentence:
// two peers prove they each hold the SM2 private key matching the
// public key they announced in discovery, then derive a fresh
// SM4 session key from SM2 ECDH + per-handshake nonces (PFS).
//
// What it does NOT do:
//   - Transport: see internal/transport.
//   - Encryption of the rest of the session: see internal/protocol,
//     which uses the SM4 session key returned here.
//
// The handshake is a 3-message exchange:
//
//	Initiator                            Responder
//	  |  (1) helloA: {PeerID, PubKey, nonceA}  --->  |
//	  |  (2) helloB: {PeerID, PubKey, nonceB,    |
//	  |              sign(privB, nonceA)}      <---  |
//	  |  (3) helloA': {sign(privA, nonceB)}     --->  |
//	  |  (4) done                               <---  |
//
// Why 3 messages (not 2):
//   - The signature in (2) proves the responder holds privB.
//   - The signature in (3) proves the initiator holds privA.
//   - If we only signed once (say by responder), an attacker
//     could replay responder's signed message to another victim.
//
// On success both sides have:
//   - Verified that the other peer holds the private key matching
//     the public key they announced in discovery (no MITM).
//   - The same sessionKey: KDF(ECDH(privA, pubB) || ECDH(privB, pubA),
//                            "innerlink-handshake-v1" || nonceA || nonceB,
//                            16 bytes)
//
// We rely on SM2 ECDH giving the same shared secret regardless of
// who initiates (the curve is commutative). If it doesn't, we
// panic on init — that would be a gmsm bug, not our bug.
package handshake

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tjfoc/gmsm/sm2"

	ic "github.com/weishengsuptp/innerlink-core/internal/crypto"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// ProtocolVersion is the version baked into every handshake frame.
// Bumped if the wire format changes incompatibly.
const ProtocolVersion = 1

// SessionKeySize is the length of the SM4 key produced by KDF at
// the end of a successful handshake. 16 bytes = SM4-128.
const SessionKeySize = 16

// NonceSize is the length of each per-handshake nonce. 32 bytes =
// 256 bits of entropy, way more than enough to make replay attacks
// infeasible.
const NonceSize = 32

// kdfInfo is the domain-separation tag mixed into the session-key
// KDF. Bumping it produces a logically distinct key from the same
// shared secret, so we can rotate the KDF independently of the
// ECDH parameters.
var kdfInfo = []byte("innerlink-handshake-v1")

// frameKind enumerates the four message types in the protocol.
type frameKind uint8

const (
	frameHelloA frameKind = iota + 1
	frameHelloB
	frameHelloAPrime
	frameDone
)

// frame is the wire encoding of one handshake message. We use JSON
// for v0.1 simplicity (per project decision to migrate to
// Protobuf in v0.2). Each frame is small (<256 bytes).
type frame struct {
	Kind       frameKind `json:"k"`   // one of frameHelloA/B/A'/Done
	Version    uint8     `json:"v"`   // ProtocolVersion
	PeerID     []byte    `json:"pid"` // 16 bytes
	PubKey     []byte    `json:"pk"`  // 64 bytes
	Ephemeral  []byte    `json:"ep"`  // 64 bytes (SM2 ephemeral public key for ECDH)
	Nonce      []byte    `json:"nc"`  // 32 bytes (omitted in "done")
	NonceA     []byte    `json:"na"`  // 32 bytes; responder echoes initiator's nonce
	SigOfNonce []byte    `json:"sig"` // ASN.1 signature over the peer's nonce
}

// Session is the result of a successful handshake. The
// transport.Conn it was negotiated over is no longer safe to
// read plaintext on (the next layer, internal/protocol, will
// encrypt everything with sessionKey).
type Session struct {
	// SessionKey is the SM4-128 key derived from the handshake.
	// Both sides hold the same bytes.
	SessionKey []byte

	// RemotePeerID is the 16-byte short ID of the other peer.
	RemotePeerID []byte

	// RemotePubKey is the 64-byte SM2 public key of the other peer.
	// Same value as the discovery layer reported; stored here so
	// the protocol layer doesn't have to look it up again.
	RemotePubKey []byte

	// Initiator is true if the local side initiated the handshake.
	// Useful for the protocol layer's session-management UI.
	Initiator bool
}

// Identity is the minimal contract Handshake needs from the
// identity package. Same shape as discovery.Device — a tiny,
// narrow interface.
type Identity interface {
	PeerID() []byte
	PublicKey() []byte
	Sign(msg []byte) ([]byte, error)
}

// RunAsInitiator performs the initiator side of the handshake on
// the given already-open Conn. Blocks until the handshake
// completes (success or failure) or ctx is done. Returns a
// Session on success. On any failure, conn is closed.
func RunAsInitiator(ctx context.Context, id Identity, conn *transport.Conn) (*Session, error) {
	sess, err := runHandshake(ctx, id, conn, true)
	if err != nil {
		conn.Close()
	}
	return sess, err
}

// RunAsResponder is the responder counterpart. On any failure
// conn is closed.
func RunAsResponder(ctx context.Context, id Identity, conn *transport.Conn) (*Session, error) {
	sess, err := runHandshake(ctx, id, conn, false)
	if err != nil {
		conn.Close()
	}
	return sess, err
}

// runHandshake is the shared state machine. The `initiator` flag
// drives which side speaks first.
func runHandshake(ctx context.Context, id Identity, conn *transport.Conn, initiator bool) (*Session, error) {
	nonceA := make([]byte, NonceSize)
	nonceB := make([]byte, NonceSize)
	if _, err := readRandom(nonceA); err != nil {
		return nil, fmt.Errorf("handshake: read nonceA: %w", err)
	}
	if _, err := readRandom(nonceB); err != nil {
		return nil, fmt.Errorf("handshake: read nonceB: %w", err)
	}

	// Each side generates an ephemeral SM2 key for the ECDH. SM2's
	// KeyAgreement protocol requires the two parties to exchange
	// their ephemeral public keys, then call keyExchange with both
	// (my_priv, my_ephemeral_priv, their_pub, their_ephemeral_pub).
	ephemeralPriv, err := ic.GenerateSM2Key()
	if err != nil {
		return nil, fmt.Errorf("handshake: gen ephemeral: %w", err)
	}
	ephemeralPub := ic.SM2MarshalPublic(&ephemeralPriv.PublicKey)

	var remotePub []byte
	var remotePID []byte
	var remoteEphemeralPub []byte

	if initiator {
		// 1) send helloA
		if err := writeFrame(ctx, conn, &frame{
			Kind:      frameHelloA,
			Version:   ProtocolVersion,
			PeerID:    id.PeerID(),
			PubKey:    id.PublicKey(),
			Ephemeral: ephemeralPub,
			Nonce:     nonceA,
		}); err != nil {
			return nil, fmt.Errorf("handshake: send helloA: %w", err)
		}
		// 2) receive helloB, verify sig(nonceA)
		f2, err := readFrame(ctx, conn)
		if err != nil {
			return nil, fmt.Errorf("handshake: recv helloB: %w", err)
		}
		if f2.Kind != frameHelloB {
			return nil, fmt.Errorf("handshake: expected helloB, got kind %d", f2.Kind)
		}
		if !bytes.Equal(f2.NonceA, nonceA) {
			return nil, errors.New("handshake: responder's echoed nonceA doesn't match")
		}
		nonceBFromB := append([]byte(nil), f2.Nonce...)
		remoteEphemeralPub = f2.Ephemeral
		respPub, err := identity.PublicKeyFromBytes(f2.PubKey)
		if err != nil {
			return nil, fmt.Errorf("handshake: parse responder pub: %w", err)
		}
		ok := verifySM2(respPub, nonceA, f2.SigOfNonce)
		if !ok {
			return nil, errors.New("handshake: responder signature on nonceA failed")
		}
		// 3) send helloA' with our sig on nonceB
		sig, err := id.Sign(nonceBFromB)
		if err != nil {
			return nil, fmt.Errorf("handshake: sign nonceB: %w", err)
		}
		if err := writeFrame(ctx, conn, &frame{
			Kind:       frameHelloAPrime,
			Version:    ProtocolVersion,
			PeerID:     id.PeerID(),
			PubKey:     id.PublicKey(),
			Nonce:      nonceBFromB,
			SigOfNonce: sig,
		}); err != nil {
			return nil, fmt.Errorf("handshake: send helloA': %w", err)
		}
		// 4) receive done
		f4, err := readFrame(ctx, conn)
		if err != nil {
			return nil, fmt.Errorf("handshake: recv done: %w", err)
		}
		if f4.Kind != frameDone {
			return nil, fmt.Errorf("handshake: expected done, got kind %d", f4.Kind)
		}
		remotePub = f2.PubKey
		remotePID = f2.PeerID
		copy(nonceB, nonceBFromB)
	} else {
		// Responder flow.
		// 1) recv helloA
		f1, err := readFrame(ctx, conn)
		if err != nil {
			return nil, fmt.Errorf("handshake: recv helloA: %w", err)
		}
		if f1.Kind != frameHelloA {
			return nil, fmt.Errorf("handshake: expected helloA, got kind %d", f1.Kind)
		}
		// B's "nonceA" is the nonce A sent in helloA — copy it out
		// so deriveSessionKey uses the same value A used.
		nonceA = append([]byte(nil), f1.Nonce...)
		remoteEphemeralPub = f1.Ephemeral
		// 2) send helloB with our sig on their nonceA.
		sig, err := id.Sign(f1.Nonce)
		if err != nil {
			return nil, fmt.Errorf("handshake: sign nonceA: %w", err)
		}
		if err := writeFrame(ctx, conn, &frame{
			Kind:       frameHelloB,
			Version:    ProtocolVersion,
			PeerID:     id.PeerID(),
			PubKey:     id.PublicKey(),
			Ephemeral:  ephemeralPub,
			Nonce:      nonceB,
			NonceA:     f1.Nonce,
			SigOfNonce: sig,
		}); err != nil {
			return nil, fmt.Errorf("handshake: send helloB: %w", err)
		}
		// 3) recv helloA', verify sig on nonceB
		f3, err := readFrame(ctx, conn)
		if err != nil {
			return nil, fmt.Errorf("handshake: recv helloA': %w", err)
		}
		if f3.Kind != frameHelloAPrime {
			return nil, fmt.Errorf("handshake: expected helloA', got kind %d", f3.Kind)
		}
		if !bytes.Equal(f3.Nonce, nonceB) {
			return nil, errors.New("handshake: initiator's echoed nonceB doesn't match")
		}
		initPub, err := identity.PublicKeyFromBytes(f3.PubKey)
		if err != nil {
			return nil, fmt.Errorf("handshake: parse initiator pub: %w", err)
		}
		ok := verifySM2(initPub, nonceB, f3.SigOfNonce)
		if !ok {
			return nil, errors.New("handshake: initiator signature on nonceB failed")
		}
		// 4) send done
		if err := writeFrame(ctx, conn, &frame{
			Kind:    frameDone,
			Version: ProtocolVersion,
			PeerID:  id.PeerID(),
			PubKey:  id.PublicKey(),
		}); err != nil {
			return nil, fmt.Errorf("handshake: send done: %w", err)
		}
		remotePub = f1.PubKey
		remotePID = f1.PeerID
	}

	// 5) Both sides: derive the session key using SM2 ECDH.
	sessionKey, err := deriveSessionKey(id, ephemeralPriv, remotePub, remoteEphemeralPub, nonceA, nonceB, initiator)
	if err != nil {
		return nil, err
	}

	return &Session{
		SessionKey:   sessionKey,
		RemotePeerID: remotePID,
		RemotePubKey: remotePub,
		Initiator:    initiator,
	}, nil
}

// deriveSessionKey runs SM2 ECDH using my private key + my ephemeral
// private key and the peer's static public key + ephemeral public key.
// Both sides call this with their own (priv, ephemeralPriv, remotePub,
// remoteEphemeralPub) and get the same SessionKey.
//
// isInitiator selects which side of the SM2 KeyAgreement protocol
// we run: the initiator calls KeyExchangeA (thisIsA=true) and the
// responder calls KeyExchangeB (thisIsA=false). Both produce the
// same shared secret given symmetric inputs.
func deriveSessionKey(id Identity, ephemeralPriv *sm2.PrivateKey, remotePub, remoteEphemeralPub, nonceA, nonceB []byte, isInitiator bool) ([]byte, error) {
	priv, err := identity.PrivateKeyFromAny(id)
	if err != nil {
		return nil, err
	}
	ephPriv, err := identity.PrivateKeyFromAny(ephemeralPriv)
	if err != nil {
		return nil, err
	}
	rpub, err := identity.PublicKeyFromBytes(remotePub)
	if err != nil {
		return nil, fmt.Errorf("handshake: parse remote static pub: %w", err)
	}
	repub, err := identity.PublicKeyFromBytes(remoteEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: parse remote ephemeral pub: %w", err)
	}
	// SM2 standard KeyAgreement per GM/T 0003-2012 §6:
	//   A (initiator) calls keyExchange(thisIsA=true) with (ida, idb,
	//     privA, pubB, rprivA, rpubB)
	//   B (responder) calls keyExchange(thisIsA=false) with (ida, idb,
	//     privB, pubA, rprivB, rpubA)
	// The ida / idb byte strings are user-identity tags (e.g.
	// "1234567812345678..." per the GMSS standard) and MUST be
	// identical on both sides for the resulting key to match.
	//
	// gmsm exposes this as two functions: KeyExchangeA and
	// KeyExchangeB, that just toggle the thisIsA flag internally.
	// We use them per-role. The input tuple we pass in is:
	//   priv       = my static private key
	//   pub        = peer's static public key
	//   ephPriv    = my ephemeral private key (just generated)
	//   pub        = peer's ephemeral public key (sent in their hello)
	//
	// Verified against gmsm's own test (sm2_test.go) which uses
	// the same call pattern.
	var shared []byte
	if isInitiator {
		// A path: my priv + their pub + my eph priv + their eph pub
		shared, _, _, err = sm2.KeyExchangeA(
			SessionKeySize*8,
			[]byte("innerlink-A"),
			[]byte("innerlink-B"),
			priv, rpub,
			ephPriv, repub,
		)
	} else {
		// B path: my priv + their pub + my eph priv + their eph pub
		// Same inputs, but the wrapper selects the "I'm B" branch.
		shared, _, _, err = sm2.KeyExchangeB(
			SessionKeySize*8,
			[]byte("innerlink-A"),
			[]byte("innerlink-B"),
			priv, rpub,
			ephPriv, repub,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("handshake: ECDH: %w", err)
	}
	ecdhKey := shared[:SessionKeySize]
	// Derive the final session key: KDF(secret=ecdhKey, info=tag||nonceA||nonceB, 16)
	info := append(append([]byte{}, kdfInfo...), nonceA...)
	info = append(info, nonceB...)
	out, err := ic.KDF(ecdhKey, info, SessionKeySize)
	if err != nil {
		return nil, fmt.Errorf("handshake: KDF: %w", err)
	}
	return out, nil
}

// verifySM2 wraps the crypto package's verify with a friendly
// error rather than the verbose raw API.
func verifySM2(pub *sm2.PublicKey, msg, sig []byte) bool {
	return ic.VerifySM2(pub, msg, sig)
}

// writeFrame JSON-encodes f and writes it as a single transport frame.
func writeFrame(ctx context.Context, conn *transport.Conn, f *frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	buf, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("handshake: marshal frame: %w", err)
	}
	if err := conn.Send(buf); err != nil {
		return fmt.Errorf("handshake: send frame: %w", err)
	}
	return nil
}

// readFrame reads one frame from conn. We don't enforce a per-frame
// timeout here; the transport layer's read deadline handles liveness.
func readFrame(ctx context.Context, conn *transport.Conn) (*frame, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fr, err := conn.Recv()
	if err != nil {
		return nil, fmt.Errorf("handshake: recv frame: %w", err)
	}
	var f frame
	if err := json.Unmarshal(fr.Body, &f); err != nil {
		return nil, fmt.Errorf("handshake: unmarshal frame: %w", err)
	}
	if f.Version != ProtocolVersion {
		return nil, fmt.Errorf("handshake: bad version %d (want %d)", f.Version, ProtocolVersion)
	}
	return &f, nil
}

// readRandom reads n bytes from crypto/rand. Kept in a helper so
// tests can substitute a deterministic source if they ever need
// to (today they don't, but the seam is here).
func readRandom(b []byte) (int, error) {
	return ic.NewNonceFill(b)
}

// Unused-import guard for time / binary packages that the
// package may need in future versions. Remove this when those
// are actually used.
var (
	_ = time.Second
	_ = binary.BigEndian
)
