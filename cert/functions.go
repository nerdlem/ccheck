package cert

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// unwrapError captures the X509 certificate left in the error from the x509
// package and places it in the Result r so that its data can be analyzed by our
// caller.
func unwrapError(err error, r *Result) {
	if hErr, ok := err.(x509.HostnameError); ok {
		r.Cert = hErr.Certificate
		_ = Check(r.Cert, r)
	}

	if hErr, ok := err.(x509.CertificateInvalidError); ok {
		r.Cert = hErr.Cert
		_ = Check(r.Cert, r)
	}
}

func maybeAddSpec(pSpec string, port int) string {
	if strings.Contains(pSpec, ":") {
		return pSpec
	}

	return fmt.Sprintf("%s:%d", pSpec, port)
}

func (r *Result) tlsMetadata(state *tls.ConnectionState) {

	switch state.Version {
	case tls.VersionSSL30:
		r.TLSVersion = "SSL-3.0"
	case tls.VersionTLS10:
		r.TLSVersion = "TLS-1.0"
	case tls.VersionTLS11:
		r.TLSVersion = "TLS-1.1"
	case tls.VersionTLS12:
		r.TLSVersion = "TLS-1.2"
	// When TLS-1.3 support is here...
	// case tls.VersionTLS13:
	case 0x0304:
		r.TLSVersion = "TLS-1.3"
	default:
		r.TLSVersion = fmt.Sprintf("(Unknown version %d)", state.Version)
	}

	switch state.CipherSuite {
	// These are for TLS 1.3
	// case tls.TLS_AES_128_GCM_SHA256:
	// 	r.CipherSuite = "TLS_AES_128_GCM_SHA256"
	// case tls.TLS_AES_256_GCM_SHA384:
	// 	r.CipherSuite = "TLS_AES_256_GCM_SHA384"
	// case tls.TLS_CHACHA20_POLY1305_SHA256:
	// 	r.CipherSuite = "TLS_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		r.CipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		r.CipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		r.CipherSuite = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		r.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		r.CipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		r.CipherSuite = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	default:
		r.CipherSuite = fmt.Sprintf("Cipersuite %d", state.CipherSuite)
	}

	r.PeerCertificates = &state.PeerCertificates
	r.VerifiedChains = &state.VerifiedChains

}

// ProcessCert takes a spec certificate specification, which might be a file
// containing a PEM certificate or a dial string to connect to and obtain the
// certificate from.
func ProcessCert(spec string, config *tls.Config, p Protocol) (Result, error) {

	start := time.Now()
	var err error

	if _, err = os.Stat(spec); err == nil {
		return ReadFromFile(spec)
	}

	r := Result{Protocol: p, Success: false, Expired: false, DaysLeft: -1, Delay: 0 * time.Second}

	switch p {
	case PSOCKET:
		var conn *tls.Conn

		conn, err = tls.Dial("tcp", maybeAddSpec(spec, 443), config)
		if err == nil {
			defer conn.Close()

			state := conn.ConnectionState()

			if len(state.PeerCertificates) == 0 {
				return Result{Success: false, DaysLeft: -1, Delay: time.Now().Sub(start)}, ErrNoCerts
			}

			r.tlsMetadata(&state)

			err = evalCerts(state.PeerCertificates, &r)
			break
		}

		unwrapError(err, &r)

		if err == io.EOF {
			err = ErrNoTLS
		}

	case PSTARTTLS:
		var cs *tls.ConnectionState

		cs, err = GetValidSTARTTLSCert(maybeAddSpec(spec, 587), config)
		if err != nil {
			unwrapError(err, &r)
			break
		}

		r.tlsMetadata(cs)

		err = evalCerts(cs.PeerCertificates, &r)

	case PPG:
		var cs *tls.ConnectionState

		cs, err = GetValidPostgresCert(maybeAddSpec(spec, 5432), config)
		if err != nil {
			unwrapError(err, &r)
			break
		}

		r.tlsMetadata(cs)

		err = evalCerts(cs.PeerCertificates, &r)

	default:
		return r, fmt.Errorf("unimplemented protocol %d", p)
	}

	r.Success = err == nil
	r.Delay = time.Now().Sub(start)
	return r, err
}

// ReadSpecSliceFromFile reads a list of certificate specs from a file and returns the
// list of specs.
func ReadSpecSliceFromFile(name string) ([]string, error) {
	r, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	ret := []string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// Remove comments and whitespace
		t := reWhitespace.ReplaceAllString(reComment.ReplaceAllString(scanner.Text(), ""), "")
		if t != "" {
			ret = append(ret, t)
		}
	}

	return ret, nil
}

// ReadFromFile reads a certificate from a local file and returns the result of
// processing it
func ReadFromFile(name string) (Result, error) {

	start := time.Now()

	r := Result{
		Success:  false,
		DaysLeft: -1,
		Cert:     nil,
	}

	rest, err := ioutil.ReadFile(name)
	if err != nil {
		return r, err
	}

	var block *pem.Block
	var c *x509.Certificate
	certs := []*x509.Certificate{}

	for block, rest = pem.Decode(rest); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			c, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return Result{Success: false, DaysLeft: -1}, err
			}

			certs = append(certs, c)
		}
	}

	err = evalCerts(certs, &r)
	r.Success = err == nil
	r.Delay = time.Now().Sub(start)
	return r, err
}
