package main

import (

	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	relay "github.com/vertexnet/relaykit"
	utls "github.com/refraction-networking/utls"

	"github.com/armon/go-socks5"
	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// activeProfile is chosen once at process start (-profile, default chrome)
// and never changes across reconnects, so the TLS fingerprint, the
// User-Agent and the decoy SNI always stay mutually consistent.
var activeProfile relay.ClientProfile

type ProxyAuth struct {
	Enable   bool
	Username string
	Passwd   string
}

func DialTcpByProxy(proxyStr string, addr string) (c net.Conn, err error) {
	var proxyUrl *url.URL
	if proxyUrl, err = url.Parse(proxyStr); err != nil {
		return
	}

	auth := &ProxyAuth{}
	if proxyUrl.User != nil {
		auth.Enable = true
		auth.Username = proxyUrl.User.Username()
		auth.Passwd, _ = proxyUrl.User.Password()
	}

	switch proxyUrl.Scheme {
	case "http":
		return DialTcpByHttpProxy(proxyUrl.Host, addr, auth)
	case "socks5":
		return DialTcpBySocks5Proxy(proxyUrl.Host, addr, auth)
	default:
		err = fmt.Errorf("%s", fmt.Sprintf(relay.Str_ERR_PROXY_SCHEME.Get(), proxyUrl.Scheme))
		return
	}
}

func DialTcpByHttpProxy(proxyHost string, dstAddr string, auth *ProxyAuth) (c net.Conn, err error) {
	if c, err = net.Dial("tcp", proxyHost); err != nil {
		return
	}

	req, err := http.NewRequest("CONNECT", "http://"+dstAddr, nil)
	if err != nil {
		return
	}
	if auth.Enable {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth.Username+":"+auth.Passwd)))
	}
	// User-Agent always matches the emulated TLS fingerprint (same profile).
	req.Header.Set("User-Agent", activeProfile.UA())
	req.Write(c)

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		err = fmt.Errorf("%s", fmt.Sprintf(relay.Str_ERR_HTTP_STATUS.Get(), resp.StatusCode))
		return
	}
	return
}

func DialTcpBySocks5Proxy(proxyHost string, dstAddr string, auth *ProxyAuth) (c net.Conn, err error) {
	var s5Auth *proxy.Auth
	if auth.Enable {
		s5Auth = &proxy.Auth{
			User:     auth.Username,
			Password: auth.Passwd,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", proxyHost, s5Auth, nil)
	if err != nil {
		return nil, err
	}

	if c, err = dialer.Dial("tcp", dstAddr); err != nil {
		return
	}
	return
}

func main() {
	relayServer := flag.String("s", "", relay.Str_S_HELP.Get())
	targetServer := flag.String("t", "", relay.Str_T_HELP.Get())
	proxyStr := flag.String("proxy", "", relay.Str_PROXY_HELP.Get())
	fingerprint := flag.String("fingerprint", "", relay.Str_FP_HELP.Get())
	profileName := flag.String("profile", relay.DefaultClientProfileName, relay.Str_PROFILE_HELP.Get())
	flag.Parse()

	activeProfile = relay.GetClientProfile(*profileName)
	if activeProfile.Name != *profileName {
		logrus.Warningf(relay.Str_LOG_UNKNOWN_PROFILE.Get(), *profileName, activeProfile.Name)
	}

	attempt := 0
	for {
		attempt++
		err := StartSession(*relayServer, *targetServer, *proxyStr, *fingerprint)
		if err != nil {
			logrus.Error(err)
		}
		delay := relay.BackoffDelay(attempt)
		logrus.Warningf(relay.Str_LOG_RESTARTING.Get(), delay)
		time.Sleep(delay)
	}
}

// dialTLS establishes the emulated-browser TLS connection (uTLS) to the
// relay server, validating the pinned certificate fingerprint (TOFU).
// The record shaper is applied only AFTER the handshake so the emulated
// ClientHello bytes are left untouched.
func dialTLS(relayServer, proxyStr, fingerprint string) (net.Conn, error) {
	tlsConfig := &utls.Config{
		// Chain validation is skipped, but the peer certificate is pinned
		// below via VerifyPeerCertificate when a fingerprint is provided.
		InsecureSkipVerify: fingerprint != "",
		// Single ALPN value: announcing h2 without speaking real HTTP/2
		// is an observable inconsistency; http/1.1 keeps behaviour honest.
		NextProtos: []string{"http/1.1"},
		ServerName: activeProfile.HostnameForSNI(relayServer),
	}
	if fingerprint != "" {
		want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New(relay.Str_ERR_NO_CERT.Get())
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != want {
				return fmt.Errorf("%s", fmt.Sprintf(relay.Str_ERR_FP_MISMATCH.Get(), got))
			}
			return nil
		}
	} else {
		// No pin provided: warn loudly, keep legacy behaviour.
		logrus.Warning(relay.Str_LOG_NO_FINGERPRINT.Get())
	}

	var rawConn net.Conn
	var err error
	if proxyStr == "" {
		rawConn, err = net.Dial("tcp", relayServer)
	} else {
		logrus.Infoln(relay.Str_LOG_USING_PROXY.Get())
		rawConn, err = DialTcpByProxy(proxyStr, relayServer)
	}
	if err != nil {
		return nil, err
	}

	// Emulated-browser handshake (uTLS) on the raw connection.
	tlsConn := utls.UClient(rawConn, tlsConfig, activeProfile.HelloID)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Handshake done: wrap with the record shaper to randomize the
	// application-data record lengths seen on the wire.
	return relay.NewRecordShaper(tlsConn), nil
}

func StartSession(relayServer string, targetServer string, proxyStr string, fingerprint string) error {
	var socks *socks5.Server
	logrus.Infoln(relay.Str_LOG_CONNECTING.Get())

	conn, err := dialTLS(relayServer, proxyStr, fingerprint)
	if err != nil {
		return err
	}

	socks, err = startSocksProxy()
	if err != nil {
		logrus.Error(relay.Str_ERR_SOCKS_START.Get())
		return err
	}

	act := relay.NewActivity()
	session, err := yamux.Client(conn, relay.YamuxConfig())
	if err != nil {
		return err
	}

	// Randomized delay before the first frame so the post-handshake
	// first-packet timing is not a fixed template.
	time.Sleep(relay.RandDuration(200*time.Millisecond, 2*time.Second))

	// Open the noise/heartbeat stream and start pumping randomized noise.
	noiseStream, err := relay.OpenNoiseStream(session)
	if err != nil {
		session.Close()
		return err
	}
	go relay.PumpNoise(noiseStream, act)
	go relay.RunWatchdog(session, act)

	// Accept business streams, draining noise streams transparently.
	business, err := relay.ServeNoiseStreams(session, act)
	if err != nil {
		session.Close()
		return err
	}

	logrus.Infoln(relay.Str_LOG_WAITING.Get())

	for stream := range business {
		logrus.WithFields(logrus.Fields{"active_sessions": session.NumStreams()}).Println(relay.Str_LOG_ACCEPTED.Get())
		// When no targetServer are specified, starts a socks5 proxy
		if targetServer == "" {
			go socks.ServeConn(stream)
		} else {
			go func(s net.Conn) {
				proxyConn, err := net.Dial("tcp", targetServer)
				if err != nil {
					logrus.Errorf(relay.Str_ERR_PROXY_DIAL.Get() + "\n", err)
					s.Close()
					return
				}
				handleRelay(s, proxyConn, act)
			}(stream)
		}
	}

	// business channel closes when the session dies.
	return nil
}

func startSocksProxy() (*socks5.Server, error) {
	conf := &socks5.Config{}
	socks, err := socks5.New(conf)
	if err != nil {
		logrus.Error(relay.Str_ERR_SOCKS_START.Get())
		return nil, err
	}
	return socks, nil
}

// countingReader / relay keep the shared Activity timestamp fresh so the
// watchdog and the noise suppression see business traffic.
type countingReader struct {
	io.Reader
	act *relay.Activity
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	if n > 0 {
		c.act.Touch()
	}
	return n, err
}

func handleRelay(src net.Conn, dst net.Conn, act *relay.Activity) {
	stop := make(chan bool, 2)

	go pipe(src, dst, stop, act)
	go pipe(dst, src, stop, act)

	select {
	case <-stop:
		return
	}
}

func pipe(src net.Conn, dst net.Conn, stop chan bool, act *relay.Activity) {
	io.Copy(dst, countingReader{Reader: src, act: act})
	dst.Close()
	src.Close()
	stop <- true
	return
}







