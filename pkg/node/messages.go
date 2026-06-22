package node

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/filetransfer"
	"github.com/weishengsuptp/innerlink-core/internal/storage"
)

// Direction of a Message: "in" for received, "out" for sent.
const (
	DirIn  = "in"
	DirOut = "out"
)

// Message is one chat message, either received from a
// peer (Direction == "in") or sent to one (Direction == "out").
// Delivered on SubscribeMessages; also returned by History().
type Message struct {
	PeerID    string    // sender (in) or recipient (out)
	Body      string    // text body (UTF-8)
	Timestamp time.Time // UTC; UI may render in local tz
	Direction string    // DirIn or DirOut
}

// SubscribeMessages returns a channel of every chat
// message, inbound and outbound, as the dispatcher
// processes them. Buffered to 64; under sustained flood
// drops oldest.
//
// The channel is closed when Close() is called.
func (n *Node) SubscribeMessages() <-chan Message {
	return n.messageCh
}

// SendText sends a chat message to a peer, identified
// by either an alias name or a 32-char hex PeerID.
// Returns an error if no active channel exists for the
// peer, or if the underlying Channel.Send fails.
//
// The send is synchronous on the underlying connection:
// returns once the bytes have been handed to the TCP
// stack. UI callers can fire-and-forget without
// worrying about lost messages — the encrypted local
// log (chat.enc) is written on success.
func (n *Node) SendText(peerRef, text string) error {
	if n.ctx == nil {
		return errors.New("node: not started")
	}
	if peerRef == "" {
		return errors.New("peer ref is empty")
	}
	peerHexStr, err := n.resolvePeerRef(peerRef)
	if err != nil {
		return err
	}
	pid, err := hexToBytes(peerHexStr)
	if err != nil {
		return errors.New("bad peer id hex: " + err.Error())
	}
	st := n.channels.get(pid)
	if st == nil {
		return errors.New("no active channel for peer " + peerHexStr)
	}
	if err := st.ch.SendText(n.ctx, text); err != nil {
		return err
	}
	log.Printf("[MSG  ] out >%s> %s", peerHexStr, text)
	rec := &storage.Record{
		Timestamp: time.Now().UTC(),
		From:      n.id.PeerIDHex(),
		To:        peerHexStr,
		Direction: "out",
		Body:      text,
		MsgID:     "",
	}
	if err := n.chatStore.Append(rec); err != nil {
		log.Printf("[ERROR] chat log append: %v", err)
	}
	n.historyMu.Lock()
	n.history = append(n.history, rec)
	n.historyMu.Unlock()
	n.publishMessage(Message{
		PeerID: peerHexStr, Body: text,
		Timestamp: rec.Timestamp, Direction: DirOut,
	})
	return nil
}

// SendFile streams a local file to a peer. Runs in a
// background goroutine (file transfers can take
// minutes for GiB-sized files); this method returns
// immediately once the goroutine is launched.
//
// Progress is logged to the configured log sink. UI
// callers wanting in-app progress should subscribe to
// the file-receiver events (TODO when we add them).
func (n *Node) SendFile(peerRef, path string) error {
	if n.ctx == nil {
		return errors.New("node: not started")
	}
	if peerRef == "" {
		return errors.New("peer ref is empty")
	}
	peerHexStr, err := n.resolvePeerRef(peerRef)
	if err != nil {
		return err
	}
	pid, err := hexToBytes(peerHexStr)
	if err != nil {
		return errors.New("bad peer id hex: " + err.Error())
	}
	st := n.channels.get(pid)
	if st == nil {
		return errors.New("no active channel for peer " + peerHexStr)
	}
	progress := func(sent, total int64) {
		pct := int64(0)
		if total > 0 {
			pct = sent * 100 / total
		}
		log.Printf("[FILE] sending %s to %s  %d/%d bytes (%d%%)",
			path, peerHexStr, sent, total, pct)
	}
	log.Printf("[FILE] start send peer=%s path=%s", peerHexStr, path)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := filetransfer.Send(context.Background(), st.ch, path, progress, st.rcv.WaitForReply); err != nil {
			log.Printf("[ERROR] sendfile: %v", err)
			return
		}
		log.Printf("[FILE] done peer=%s path=%s", peerHexStr, path)
	}()
	return nil
}

// History returns the most recent chat records from
// the encrypted local log. If peerRef is non-empty,
// only records between us and that peer (alias or
// hex) are returned; "" returns records for all peers.
//
// Records are ordered oldest-first within the result,
// capped at 200 entries (older entries are still on
// disk in chat.enc — the UI can request more via a
// future HistoryRange API).
const historyLimit = 200

func (n *Node) History(peerRef string) []Message {
	n.historyMu.Lock()
	src := make([]*storage.Record, len(n.history))
	copy(src, n.history)
	n.historyMu.Unlock()

	var filterPeer string
	if peerRef != "" {
		var err error
		filterPeer, err = n.resolvePeerRef(peerRef)
		if err != nil {
			return nil
		}
	}
	out := make([]Message, 0, len(src))
	for _, r := range src {
		if filterPeer != "" && r.From != filterPeer && r.To != filterPeer {
			continue
		}
		out = append(out, Message{
			PeerID:    pickOther(r.From, r.To, n.id.PeerIDHex()),
			Body:      r.Body,
			Timestamp: r.Timestamp,
			Direction: r.Direction,
		})
		if len(out) >= historyLimit {
			break
		}
	}
	return out
}

// pickOther returns the peer ID on the OTHER side of a
// chat record (relative to self). For inbound records
// that's the sender; for outbound, the recipient.
func pickOther(from, to, self string) string {
	if from == self {
		return to
	}
	return from
}