package handshake

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// loopbackConnPair returns two connected transport.Conns: a "client"
// and a "server". They are linked via a real loopback TCP so the
// transport.Conn.Recv/ReadDeadline paths are exercised.
func loopbackConnPair(t *testing.T) (*transport.Conn, *transport.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		c   net.Conn
		err error
	}
	c1Ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		c1Ch <- result{c, err}
	}()

	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-c1Ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return transport.NewConnForTest(c2), transport.NewConnForTest(r.c)
}

func TestHandshakeProducesMatchingSessionKey(t *testing.T) {
	idA, _ := identity.Generate()
	idB, _ := identity.Generate()

	initConn, respConn := loopbackConnPair(t)
	defer initConn.Close()
	defer respConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	var sessA, sessB *Session
	var errA, errB error

	doneCh := make(chan struct{})

	go func() {
		defer wg.Done()
		t.Log("A: RunAsInitiator start")
		sessA, errA = RunAsInitiator(ctx, idA, initConn)
		t.Logf("A: RunAsInitiator done err=%v key=%x", errA, sessA.SessionKey)
	}()
	go func() {
		defer wg.Done()
		t.Log("B: RunAsResponder start")
		sessB, errB = RunAsResponder(ctx, idB, respConn)
		t.Logf("B: RunAsResponder done err=%v key=%x", errB, sessB.SessionKey)
	}()

	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not complete within 5s")
	}

	if errA != nil {
		t.Fatalf("initiator: %v", errA)
	}
	if errB != nil {
		t.Fatalf("responder: %v", errB)
	}

	// Both sides must derive the same SessionKey.
	if !bytes.Equal(sessA.SessionKey, sessB.SessionKey) {
		t.Errorf("session keys differ:\n  A=%x\n  B=%x", sessA.SessionKey, sessB.SessionKey)
	}
	if len(sessA.SessionKey) != SessionKeySize {
		t.Errorf("session key length = %d, want %d", len(sessA.SessionKey), SessionKeySize)
	}

	// Each side must see the other's PeerID and PubKey.
	if !bytes.Equal(sessA.RemotePeerID, idB.PeerID()) {
		t.Error("initiator: RemotePeerID doesn't match idB")
	}
	if !bytes.Equal(sessB.RemotePeerID, idA.PeerID()) {
		t.Error("responder: RemotePeerID doesn't match idA")
	}
	if !bytes.Equal(sessA.RemotePubKey, idB.PublicKey()) {
		t.Error("initiator: RemotePubKey doesn't match idB")
	}
	if !bytes.Equal(sessB.RemotePubKey, idA.PublicKey()) {
		t.Error("responder: RemotePubKey doesn't match idA")
	}

	// Initiator flag should be opposite on each side.
	if !sessA.Initiator {
		t.Error("sessA.Initiator = false, want true")
	}
	if sessB.Initiator {
		t.Error("sessB.Initiator = true, want false")
	}
}

func TestHandshakeRejectsMismatchedPublicKey(t *testing.T) {
	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	impostor, _ := identity.Generate() // third identity, used to sign instead of B

	initConn, respConn := loopbackConnPair(t)
	defer initConn.Close()
	defer respConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Wrap the responder so it announces idB's keys but signs
	// with impostor's key. The initiator's helloA nonce
	// verification will catch the mismatch.
	respId := wrappedIdentity{
		Identity: idB,
		signer:   impostor,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var errA, errB error
	doneCh := make(chan struct{})
	go func() {
		_, errA = RunAsInitiator(ctx, idA, initConn)
		wg.Done()
	}()
	go func() {
		_, errB = RunAsResponder(ctx, &respId, respConn)
		wg.Done()
	}()
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("mismatch test did not complete in 5s")
	}

	if errA == nil {
		t.Error("initiator should have rejected mismatched signature")
	}
	if errB == nil {
		t.Error("responder should have failed to send")
	}
}

// wrappedIdentity lets a test substitute the signing key without
// changing the announced keys. Used to simulate a MITM that has
// someone else's private key but is trying to claim idB's identity.
type wrappedIdentity struct {
	*identity.Identity
	signer *identity.Identity
}

func (w *wrappedIdentity) Sign(msg []byte) ([]byte, error) {
	return w.signer.Sign(msg)
}

func (w *wrappedIdentity) PublicKey() []byte {
	return w.Identity.PublicKey()
}

func (w *wrappedIdentity) PeerID() []byte {
	return w.Identity.PeerID()
}
