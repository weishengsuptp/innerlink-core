package node

import (
	"errors"
	"sort"
	"time"
)

// Alias is the public, UI-facing view of one user-assigned
// peer name. Underlying storage is alias.Store; this
// struct is what ListAliases returns.
type Alias struct {
	Name     string
	PeerID   string
	LastSeen time.Time
}

// SetAlias assigns a human-readable name to a peer.
// peerRef may be either the peer's 32-char hex PeerID
// or an existing alias (the latter is unusual but
// supported — it lets you re-target a name to a new
// peer if the old one is replaced).
//
// Names are case-sensitive, 1-64 chars (validated by
// the underlying alias package). A peer can have at
// most one alias; assigning a second one overwrites
// the first.
func (n *Node) SetAlias(peerRef, name string) error {
	if peerRef == "" {
		return errors.New("alias: peer ref is empty")
	}
	if name == "" {
		return errors.New("alias: name is empty")
	}
	peerHexStr, err := n.resolvePeerRef(peerRef)
	if err != nil {
		return err
	}
	if err := n.aliasStore.Set(peerHexStr, name); err != nil {
		return err
	}
	return n.aliasStore.Save()
}

// RemoveAlias drops an alias by name (or by PeerID).
// Resolving by name first is the common case; if no
// alias by that name exists, the argument is treated
// as a raw PeerID.
func (n *Node) RemoveAlias(ref string) error {
	if ref == "" {
		return errors.New("unalias: ref is empty")
	}
	pid, err := n.resolvePeerRef(ref)
	if err != nil {
		// Treat as raw peer id.
		pid = ref
	}
	if err := n.aliasStore.Remove(pid); err != nil {
		return err
	}
	return n.aliasStore.Save()
}

// ListAliases returns every alias in stable order
// (name asc, unnamed rows last).
func (n *Node) ListAliases() []Alias {
	rows := n.aliasStore.ListWithNames()
	out := make([]Alias, 0, len(rows))
	for _, r := range rows {
		out = append(out, Alias{
			Name:     r.Name,
			PeerID:   r.PeerID,
			LastSeen: r.LastSeen,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Named entries first, sorted by Name asc.
		// Unnamed entries after, sorted by PeerID.
		ai, aj := out[i], out[j]
		if (ai.Name == "") != (aj.Name == "") {
			return ai.Name != ""
		}
		if ai.Name != "" {
			return ai.Name < aj.Name
		}
		return ai.PeerID < aj.PeerID
	})
	return out
}

// resolvePeerRef maps a user-typed peer reference
// (alias name or 32-char hex PeerID) to the peer's
// 32-char hex. Returns an error if the ref is neither.
// This is the single place where alias lookup lives;
// SendText / SendFile / SetAlias / History all go
// through it.
func (n *Node) resolvePeerRef(ref string) (string, error) {
	if id, ok := n.aliasStore.ResolvePeerRef(ref); ok {
		return id, nil
	}
	return "", errUnknownPeer{ref: ref}
}

type errUnknownPeer struct{ ref string }

func (e errUnknownPeer) Error() string {
	return "unknown peer \"" + e.ref + "\" (use `peers` to list, `alias` to name)"
}