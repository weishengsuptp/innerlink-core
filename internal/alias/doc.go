// Package alias persists a small map of PeerID -> friendly
// name on disk, so users can refer to peers by name
// ("send 老王工位机 你好") instead of memorizing 32-char
// hex strings.
//
// Why this package exists:
//
//  v0.3 innerlink knows every peer only as a hex
//  PeerID. That's the right thing at the protocol
//  layer (compact, deterministic, no encoding
//  surprises) but it's the wrong thing at the
//  human layer. v0.4 introduces alias as a
//  user-friendly indirection: the user assigns
//  names once, then uses them everywhere REPL
//  accepts a peer-id.
//
// Storage:
//
//  JSON file at <device-key-dir>/aliases.json,
//  i.e. the same directory as device.key
//  (~/.innerlink/aliases.json on a normal
//  install). The file is small (one entry per
//  known peer) and only the user mutates it
//  via the `alias` / `unalias` REPL commands,
//  so concurrency is single-process.
//
// Format:
//
//  {
//    "v": 1,
//    "aliases": {
//      "<peer-id-hex>": {
//        "name": "老王工位机",
//        "first_seen": "2026-06-17T...",
//        "last_seen":  "2026-06-17T..."
//      }
//    }
//  }
//
// The peer-id-hex key is always 32 lowercase hex
// characters (16 bytes, SM3(public key)[:16]).
// We do NOT case-fold or normalize on read;
// REPL matching is exact.
//
// Concurrency model:
//
//  Single-process file. All access goes through
//  Store, which holds an in-memory map guarded
//  by a sync.RWMutex. Saves are serialized via
//  a separate sync.Mutex (you don't want two
//  Set() calls racing on the same temp file).
//  The on-disk file is rewritten on every Save
//  — small enough (a few KB at most) that
//  this is cheaper than incremental updates.
package alias
