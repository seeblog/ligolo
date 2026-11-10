package relaykit

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// Activity tracks the last time data was seen in either direction of the
// tunnel. It is shared by relay loops, the noise pump and the watchdog.
type Activity struct {
	last int64 // unix nanos
}

func NewActivity() *Activity { return &Activity{last: time.Now().UnixNano()} }

func (a *Activity) Touch()                      { atomic.StoreInt64(&a.last, time.Now().UnixNano()) }
func (a *Activity) Idle() time.Duration {
	return time.Duration(time.Now().UnixNano() - atomic.LoadInt64(&a.last))
}

// OpenNoiseStream opens the noise/heartbeat stream on the given session,
// writes the magic header and returns it. The caller launches pumpNoise on it.
// Returns nil stream if the magic could not be written (session dying).
func OpenNoiseStream(session *yamux.Session) (net.Conn, error) {
	stream, err := session.Open()
	if err != nil {
		return nil, err
	}
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Write(noiseStreamMagic); err != nil {
		stream.Close()
		return nil, err
	}
	stream.SetDeadline(time.Time{})
	return stream, nil
}

// ServeNoiseStreams accepts incoming streams forever. Streams starting with
// the noise magic are drained in the background; anything else is returned
// to the caller on the returned channel (business traffic).
func ServeNoiseStreams(session *yamux.Session, act *Activity) (<-chan net.Conn, error) {
	business := make(chan net.Conn, 16)
	go func() {
		defer close(business)
		for {
			stream, err := session.Accept()
			if err != nil {
				return
			}
			go classifyStream(stream, business, act)
		}
	}()
	return business, nil
}

func classifyStream(stream net.Conn, business chan<- net.Conn, act *Activity) {
	header := make([]byte, len(noiseStreamMagic))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, header); err != nil {
		// Peer never sent the magic header: treat as a business stream that
		// died early. Push it anyway so the owner can close it properly.
		stream.SetReadDeadline(time.Time{})
		select {
		case business <- stream:
		default:
			stream.Close()
		}
		return
	}
	stream.SetReadDeadline(time.Time{})
	act.Touch()
	for i := range noiseStreamMagic {
		if header[i] != noiseStreamMagic[i] {
			// Not a noise stream: it is a business connection whose first
			// bytes happened to arrive with the header read. Wrap it so the
			// already-consumed prefix is replayed to the reader.
			select {
			case business <- newPrefixConn(stream, header):
			default:
				stream.Close()
			}
			return
		}
	}
	// Noise stream: drain forever, updating activity as we receive.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				act.Touch()
			}
			if err != nil {
				stream.Close()
				return
			}
		}
	}()
}

// PumpNoise writes random-length noise frames on the noise stream at
// randomized intervals, but only while the channel has been idle for at
// least NoiseMinIdle. Each frame is: [4-byte length][payload]. The peer's
// drain loop consumes and discards it. A write error ends the pump (session
// is closing anyway).
func PumpNoise(stream net.Conn, act *Activity) {
	for {
		time.Sleep(RandDuration(NoiseMinInterval, NoiseMaxInterval))
		if act.Idle() < NoiseMinIdle {
			continue // business traffic seen recently: suppress heartbeat
		}
		stream.SetWriteDeadline(time.Now().Add(WriteTimeout))
		payload := RandBytes(MinNoisePayload + RandIntn(MaxNoisePayload-MinNoisePayload))
		frame := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(frame, uint32(len(payload)))
		copy(frame[4:], payload)
		if _, err := stream.Write(frame); err != nil {
			return
		}
		act.Touch()
	}
}

// prefixConn replays an already-read byte prefix before reading the
// underlying stream. Used when a business stream was peeked for the noise
// magic header and the peeked bytes must not be lost.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func newPrefixConn(c net.Conn, prefix []byte) net.Conn { return &prefixConn{Conn: c, prefix: prefix} }

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// YamuxConfig returns the shared yamux configuration: keepalive disabled
// (heartbeat is handled by the application-layer noise pump), generous
// write timeout, default windowing.
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.ConnectionWriteTimeout = WriteTimeout
	return cfg
}

// RunWatchdog closes the session if no activity (business or noise) has been
// seen for WatchdogTimeout. Closing makes the pending Accept()/Open()/Read()
// return errors, so the existing reconnect / session-pool logic fires.
func RunWatchdog(session io.Closer, act *Activity) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if act.Idle() > WatchdogTimeout {
			session.Close()
			return
		}
	}
}



