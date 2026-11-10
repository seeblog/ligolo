package relaykit

import (
	"errors"
	"net"
	"time"
)

// recordShaper wraps an established TLS connection and splits every write
// into randomly sized chunks (64B..16KB). Because the underlying TLS stack
// emits one record per Write, this randomizes the ciphertext record-length
// distribution seen on the wire. The stream protocol above (yamux) is
// boundary-insensitive, so correctness is unaffected.
//
// IMPORTANT: it must only wrap a connection AFTER the TLS handshake is done.
// Wrapping earlier would split the ClientHello and destroy the emulated
// browser fingerprint.
type recordShaper struct {
	net.Conn
}

// NewRecordShaper wraps a post-handshake TLS connection.
func NewRecordShaper(c net.Conn) net.Conn { return recordShaper{Conn: c} }

const (
	shaperMinChunk = 64
	shaperMaxChunk = 16 * 1024
)

func (s recordShaper) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := shaperMinChunk + RandIntn(shaperMaxChunk-shaperMinChunk)
		if n > len(b) {
			n = len(b)
		}
		// Bound the per-chunk write time so a stalled peer cannot hang the
		// relay loop indefinitely.
		if dl, ok := s.Conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = dl.SetWriteDeadline(time.Now().Add(WriteTimeout))
		}
		w, err := s.Conn.Write(b[:n])
		total += w
		if err != nil {
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}

var errShaperClosed = errors.New("record shaper: connection closed")

var _ = errShaperClosed // reserved for future use
