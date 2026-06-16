// Package filetransfer implements chunked P2P file transfer on
// top of an established protocol.Channel.
//
// Wire protocol (uses protocol.Envelope with dedicated MsgType
// values; see internal/protocol/protocol.go for the constants):
//
//  1. Sender → Receiver:  TypeFileOffer    {fileID, name, size,
//     sha256, totalChunks, chunkSize}
//  2. Receiver → Sender: TypeFileAccept   {fileID, acceptedChunks}
//     — tells sender which indexes the receiver already has
//     (for resume). Empty list = fresh transfer.
//  3. Sender → Receiver: TypeFileChunk    {fileID, index, sha256,
//     data}  (one Envelope per chunk; data is base64 of 1 MiB
//     raw bytes — see ChunkSize below)
//  4. Receiver → Sender: TypeFileDone     {fileID, ok, err?}
//     — sent after the full file is on disk AND its SHA-256
//     matches the offer.
//
// Either side may send TypeFileAbort at any time to cancel.
//
// Concurrency model:
//   - Send() is a blocking call; it does not return until the
//     receiver acks Done, aborts, or the context is cancelled.
//   - Receive() is meant to be run as a background goroutine
//     (Receiver.Loop). The loop reads envelopes off the channel,
//     dispatches offers to disk, and writes back Accepts.
//   - A single Channel is bidirectional; a Receiver running on
//     it does NOT block a Send call on the SAME side, but
//     channel ordering is preserved per direction, so it is
//     safe to multiplex chat + file on the same channel.
//
// Limits (v0.1):
//   - ChunkSize is fixed at 1 MiB. Smaller than the transport
//     MaxFrameSize of 16 MiB, so the encrypted envelope of one
//     chunk always fits in one TCP frame.
//   - No multi-stream: one file at a time per Channel. To send
//     multiple files in parallel, use multiple Channels (i.e.
//     multiple peer sessions — not implemented in v0.1).
//   - The full-file SHA-256 is verified by the receiver before
//     it sends Done. A mismatch triggers Abort and deletes the
//     temp file.
package filetransfer
