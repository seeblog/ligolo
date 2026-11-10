package relaykit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// noiseStreamMagic identifies the dedicated obfuscation/heartbeat stream.
// Intentionally random, non-meaningful bytes. Any yamux stream starting
// with these bytes carries random-length noise and must be drained and
// discarded by the peer.
var noiseStreamMagic = []byte{0x9c, 0x37, 0xd1, 0x58, 0x4a, 0xe2, 0x0b, 0x6f}

// Common TLS parameters shared by both peers.
const (
	// NoiseMinIdle is the channel idle time required before a noise
	// (heartbeat) frame is emitted. Business traffic suppresses heartbeats.
	NoiseMinIdle = 90 * time.Second
	// NoiseMinInterval / NoiseMaxInterval bound the randomized interval
	// between two consecutive noise frames.
	NoiseMinInterval = 60 * time.Second
	NoiseMaxInterval = 180 * time.Second
	// MinNoisePayload / MaxNoisePayload bound the random payload length.
	MinNoisePayload = 64
	MaxNoisePayload = 4096
	// WatchdogTimeout is the maximum channel silence before the session is
	// considered dead. Must exceed NoiseMinIdle + NoiseMaxInterval.
	WatchdogTimeout = 10 * time.Minute
	// WriteTimeout replaces yamux's per-write timeout (keepalive disabled).
	WriteTimeout = 10 * time.Minute
)

// RandIntn returns a cryptographically secure random int in [0, n).
func RandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// RandDuration returns a cryptographically secure random duration in [min, max).
func RandDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(RandIntn(int(max-min)))
}

// RandBytes returns n cryptographically secure random bytes.
func RandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// BackoffDelay returns a jittered exponential backoff delay for the given
// connection attempt (1-based). Base grows 1s, 2s, 4s ... capped at 300s,
// each step jittered by +/-40%.
func BackoffDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 9 {
		shift = 9
	}
	base := time.Second << uint(shift)
	if base > 300*time.Second {
		base = 300 * time.Second
	}
	jitter := time.Duration(float64(base) * 0.4)
	return base - jitter + RandDuration(0, 2*jitter)
}

// FingerprintDER returns the SHA-256 fingerprint (hex) of a DER certificate.
func FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// GenerateCertificate creates a fresh self-signed ECDSA P-256 certificate
// with the given common name. It returns a ready-to-use tls.Certificate and
// its SHA-256 fingerprint (hex) so it can be pinned by the peer.
func GenerateCertificate(commonName string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Cloud Services"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return cert, FingerprintDER(der), nil
}

// CertFingerprint returns the SHA-256 fingerprint (hex) of the leaf
// certificate of an already loaded tls.Certificate.
func CertFingerprint(cert tls.Certificate) (string, error) {
	if cert.Leaf == nil {
		if len(cert.Certificate) == 0 {
			return "", errors.New("empty certificate chain")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return "", err
		}
		cert.Leaf = leaf
	}
	return FingerprintDER(cert.Leaf.Raw), nil
}

// ClientProfile bundles every externally visible client identity aspect so
// the TLS fingerprint, the HTTP User-Agent and the decoy SNI hostname always
// stay consistent with each other. The profile is chosen once at process
// start (default chrome) and never changes across reconnects.
type ClientProfile struct {
	Name        string // human-readable, also the -profile flag value
	HelloID     utls.ClientHelloID
	DecoyServer string // filled lazily via Decoy()
	UserAgent   string // filled lazily via UA()
	SIDA        string // internal: which accessor pair to use
}

var clientProfiles = map[string]ClientProfile{
	"chrome": {
		Name:        "chrome",
		HelloID:     utls.HelloChrome_120,
		UserAgent:   "", // resolved lazily via accessor below
		DecoyServer: "",
		SIDA:        "chrome",
	},
	"firefox": {
		Name:        "firefox",
		HelloID:     utls.HelloFirefox_120,
		UserAgent:   "",
		DecoyServer: "",
		SIDA:        "firefox",
	},
	"safari": {
		Name:        "safari",
		HelloID:     utls.HelloSafari_16_0,
		UserAgent:   "",
		DecoyServer: "",
		SIDA:        "safari",
	},
}

// UA returns the (obfuscated-at-rest) User-Agent for this profile.
func (p ClientProfile) UA() string {
	switch p.SIDA {
	case "firefox":
		return Str_UA_FIREFOX.Get()
	case "safari":
		return Str_UA_SAFARI.Get()
	default:
		return Str_UA_CHROME.Get()
	}
}

// Decoy returns the (obfuscated-at-rest) decoy SNI hostname.
func (p ClientProfile) Decoy() string {
	switch p.SIDA {
	case "firefox":
		return Str_SNI_FIREFOX.Get()
	case "safari":
		return Str_SNI_SAFARI.Get()
	default:
		return Str_SNI_CHROME.Get()
	}
}

// DefaultClientProfileName is used when -profile is not given.
const DefaultClientProfileName = "chrome"

// GetClientProfile returns the profile for name, falling back to the default
// profile when the name is unknown.
func GetClientProfile(name string) ClientProfile {
	if p, ok := clientProfiles[name]; ok {
		return p
	}
	return clientProfiles[DefaultClientProfileName]
}

// HostnameForSNI extracts the host part of addr (host:port). When the host
// is a bare IP address, the profile's decoy hostname is returned so the
// ClientHello carries a plausible SNI instead of none.
func (p ClientProfile) HostnameForSNI(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return p.Decoy()
	}
	if ip := net.ParseIP(host); ip != nil {
		return p.Decoy()
	}
	return host
}




