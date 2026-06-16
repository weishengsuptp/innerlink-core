package filetransfer

import "crypto/rand"

// randRead is a small indirection over crypto/rand.Read so tests
// can stub it if they ever need to.
var randRead = rand.Read
