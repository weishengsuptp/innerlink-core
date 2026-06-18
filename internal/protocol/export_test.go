package protocol

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// NewLoopbackChannelPairForTest is a test-only helper exported
// to other packages (filetransfer, cmd) that need a complete
// handshake over loopback TCP. It returns two Channels ready
// for chat / file traffic.
//
// This file lives in package protocol (not _test) so the
// symbol is visible from any *_test.go in the module. It is
// guarded by the file name suffix _test.go convention in
// production builds (Go excludes _test.go files from the
// compiled package), so it is NOT part of the public API.
func NewLoopbackChannelPairForTest(t *testing.T) (*Channel, *Channel) {
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

	cA := transport.NewConnForTest(c2)
	cB := transport.NewConnForTest(r.c)

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type hr struct {
		s *handshake.Session
		e error
	}
	aCh := make(chan hr, 1)
	bCh := make(chan hr, 1)
	go func() {
		s, e := handshake.RunAsInitiator(ctx, idA, cA)
		aCh <- hr{s, e}
	}()
	go func() {
		s, e := handshake.RunAsResponder(ctx, idB, cB)
		bCh <- hr{s, e}
	}()
	rA, rB := <-aCh, <-bCh
	if rA.e != nil {
		t.Fatalf("init: %v", rA.e)
	}
	if rB.e != nil {
		t.Fatalf("resp: %v", rB.e)
	}
	chA, err := NewChannel(cA, rA.s)
	if err != nil {
		t.Fatal(err)
	}
	chB, err := NewChannel(cB, rB.s)
	if err != nil {
		t.Fatal(err)
	}
	return chA, chB
}
