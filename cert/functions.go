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
	"time"
)

// unwrapError captures the X509 certificate left in the error from the x509
// package and places it in the Result r so that its data can be analyzed by our
// caller.
func unwrapError(err error, start time.Time, r *Result) {
	if hErr, ok := err.(x509.HostnameError); ok {
		r.Cert = hErr.Certificate
		_ = Check(r.Cert, r)
		r.Delay = time.Now().Sub(start)
	}
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

	r := Result{Success: false, Expired: false, DaysLeft: -1, Delay: 0 * time.Second}

	switch p {
	case PSOCKET:
		var conn *tls.Conn

		conn, err = tls.Dial("tcp", spec, config)
		if err == nil {
			defer conn.Close()

			state := conn.ConnectionState()

			if len(state.PeerCertificates) == 0 {
				return Result{Success: false, DaysLeft: -1, Delay: time.Now().Sub(start)}, ErrNoCerts
			}

			err = evalCerts(state.PeerCertificates, &r, start)
			break
		}

		unwrapError(err, start, &r)

		if err == io.EOF {
			err = ErrNoTLS
		}

	case PSTARTTLS:
		var certs []*x509.Certificate

		certs, err = GetValidSTARTTLSCert(spec, config)
		if err != nil {
			unwrapError(err, start, &r)
			break
		}

		err = evalCerts(certs, &r, start)

	case PPG:
		var certs []*x509.Certificate

		certs, err = GetValidPostgresCert(spec, config)
		if err != nil {
			unwrapError(err, start, &r)
			break
		}

		err = evalCerts(certs, &r, start)

	default:
		return r, fmt.Errorf("unimplemented protocol %d", p)
	}

	r.Success = err == nil
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

	err = evalCerts(certs, &r, start)
	r.Success = err == nil
	return r, err
}
