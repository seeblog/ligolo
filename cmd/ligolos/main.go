package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	relay "github.com/vertexnet/relaykit"

	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
)

func main() {
	localServer := flag.String("p", "127.0.0.1:1080", relay.Str_SRV_P_HELP.Get())
	relayServer := flag.String("l", "0.0.0.0:443", relay.Str_SRV_L_HELP.Get())
	certFile := flag.String("cert", "", relay.Str_SRV_CERT_HELP.Get())
	keyFile := flag.String("key", "", relay.Str_SRV_KEY_HELP.Get())
	certDomain := flag.String("cert-domain", "", relay.Str_SRV_CN_HELP.Get())

	flag.Parse()

	relay := NewRelayService(*localServer, *relayServer, *certFile, *keyFile, *certDomain)
	relay.Start()
}

// RelayService structure contains configuration, the current session and the ConnectionPool
type RelayService struct {
	LocalServer    string
	RelayServer    string
	CertFile       string
	KeyFile        string
	CertDomain     string
	ConnectionPool chan *yamux.Session
	Session        *yamux.Session
	activity       *relay.Activity
}

// NewRelayService creates a new RelayService struct
func NewRelayService(localServer string, relayServer string, certFile string, keyFile string, certDomain string) *RelayService {
	return &RelayService{LocalServer: localServer, RelayServer: relayServer, CertFile: certFile, KeyFile: keyFile, CertDomain: certDomain, ConnectionPool: make(chan *yamux.Session, 100)}
}

// Start listening for local and relay connections
func (s RelayService) Start() {

	logrus.WithFields(logrus.Fields{"socks5server": s.LocalServer, "listen": s.RelayServer}).Println(relay.Str_SRV_STARTED.Get())
	go s.startRelayHandler()
	s.startLocalHandler()
}

// loadCertificate loads a custom keypair when provided, or generates a fresh
// deployment-specific self-signed certificate (no more globally shared,
// fingerprintable default certificate).
func (svc RelayService) loadCertificate() (tls.Certificate, error) {
	if svc.CertFile != "" && svc.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(svc.CertFile, svc.KeyFile)
		if err != nil {
			return tls.Certificate{}, err
		}
		fp, err := relay.CertFingerprint(cert)
		if err != nil {
			return tls.Certificate{}, err
		}
		logrus.Infof(relay.Str_SRV_LOADED_CERT.Get(), fp)
		return cert, nil
	}

	cn := svc.CertDomain
	if cn == "" {
		cn = randomCommonName()
	}
	cert, fp, err := relay.GenerateCertificate(cn)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(relay.Str_ERR_GEN_CERT.Get(), err)
	}
	logrus.Infof(relay.Str_SRV_GEN_CERT.Get(), cn, fp)
	logrus.Infof(relay.Str_SRV_PASS_FP.Get(), fp)
	return cert, nil
}

// randomCommonName picks a plausible-looking hostname for the generated
// certificate instead of a fixed, easily flagged value.
func randomCommonName() string {
	names := []string{
		"cdn-gateway", "update-service", "api-gateway", "metrics-collector",
		"assets-cache", "status-endpoint", "sync-service", "log-ingestor",
	}
	tlds := []string{"net", "com", "io", "cloud", "cdn"}
	return fmt.Sprintf("%s-%d.%s", names[relay.RandIntn(len(names))], relay.RandIntn(65536), tlds[relay.RandIntn(len(tlds))])
}

// Listen for relay connections
func (s RelayService) startRelayHandler() {

	cer, err := s.loadCertificate()
	if err != nil {
		logrus.Errorf(relay.Str_ERR_LOAD_CERT.Get(), err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	listener, err := tls.Listen("tcp4", s.RelayServer, config)
	if err != nil {
		logrus.Errorf(relay.Str_ERR_BIND.Get() + "\n", err)
		return
	}
	defer listener.Close()
	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Errorf(relay.Str_ERR_ACCEPT.Get() + "\n", err)
			return
		}

		session, act, err := handleRelayConnection(c)
		if err != nil {
			logrus.Errorf(relay.Str_ERR_SESSION_START.Get() + "\n", err)
			continue
		}
		s.activity = act
		s.ConnectionPool <- session
	}

}

// Listen for local connections
func (s RelayService) startLocalHandler() {
	listener, err := net.Listen("tcp4", s.LocalServer)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()
	s.Session = <-s.ConnectionPool
	go func() {
		for {
			<-s.Session.CloseChan()
			logrus.WithFields(logrus.Fields{"remoteaddr": s.Session.RemoteAddr()}).Println(relay.Str_SRV_SESSION_DOWN.Get())
			s.Session = <-s.ConnectionPool
			logrus.WithFields(logrus.Fields{"remoteaddr": s.Session.RemoteAddr()}).Println(relay.Str_SRV_SESSION_NEW.Get())
		}
	}()
	logrus.Println(relay.Str_SRV_SESSION_ACQ.Get())
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}

		go s.handleLocalConnection(conn)
	}
}

// Handle new local connections
func (s RelayService) handleLocalConnection(conn net.Conn) {
	if s.Session.IsClosed() {
		logrus.Warning(relay.Str_SRV_NO_SESSION.Get())
		conn.Close()
		return
	}

	logrus.Println(relay.Str_SRV_NEW_PROXY.Get())

	stream, err := s.Session.Open()
	if err != nil {
		logrus.Errorf(relay.Str_ERR_OPEN_SESSION.Get() + "\n", err)
		return
	}

	logrus.Println(relay.Str_SRV_YAMUX_OK.Get())

	go pipe(conn, stream, s.activity)
	go pipe(stream, conn, s.activity)

}

// Handle new client connections.
// Note: no session.Ping() anymore - the fixed server-first ping/pong
// template is gone; liveness is handled by the noise pump and watchdog.
func handleRelayConnection(conn net.Conn) (*yamux.Session, *relay.Activity, error) {
	logrus.WithFields(logrus.Fields{"remoteaddr": conn.RemoteAddr().String()}).Info(relay.Str_SRV_NEW_CONN.Get() + "\n")

	act := relay.NewActivity()
	session, err := yamux.Server(conn, relay.YamuxConfig())
	if err != nil {
		return nil, act, err
	}

	// Serve incoming streams: drain noise streams, hand business streams
	// over to the relay via the session's Open() from the local side.
	business, err := relay.ServeNoiseStreams(session, act)
	if err != nil {
		session.Close()
		return nil, act, err
	}

	go func() {
		for range business {
			// The server never initiates business streams; anything the
			// peer opens that is not noise arrives here and is closed.
			// (Business connections are opened from the local handler side.)
		}
	}()

	// Server-side noise pump with randomized, traffic-suppressed intervals.
	noiseStream, err := relay.OpenNoiseStream(session)
	if err != nil {
		session.Close()
		return nil, act, err
	}
	go relay.PumpNoise(noiseStream, act)
	go relay.RunWatchdog(session, act)

	// Give the client's noise stream a moment to be classified before the
	// session is handed to the pool.
	time.Sleep(50 * time.Millisecond)

	return session, act, nil
}

func pipe(src net.Conn, dst net.Conn, act *relay.Activity) {
	io.Copy(dst, actReader{Reader: src, act: act})
	dst.Close()
	src.Close()
	return
}

type actReader struct {
	io.Reader
	act *relay.Activity
}

func (a actReader) Read(p []byte) (int, error) {
	n, err := a.Reader.Read(p)
	if n > 0 {
		a.act.Touch()
	}
	return n, err
}










