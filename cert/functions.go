package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

// Result encodes the result of validating a Certificate
type Result struct {
	// Success indicates whether the checking was successful or not.
	Success bool
	// DaysLeft indicates the difference between current time and expiration date
	// of the certificate, with negative numbers indicating errors or expired
	// certificates.
	DaysLeft int
	// Cert points to the certificate that was checked. This is useful to
	// piggyback checks on certificates.
	Cert *x509.Certificate
}

// String satisfies the Stringer interface
func (r *Result) String() string {
	res := fmt.Sprintf("Success=%v, DaysLeft=%d, cert is", r.Success, r.DaysLeft)
	if r.Cert == nil {
		res = fmt.Sprintf("%s %s", res, "nil")
	} else {
		res = fmt.Sprintf("%s %s", res, "present")
	}

	return res
}

// ErrExpired is returned when the certificate is found to be expired
var ErrExpired = fmt.Errorf("certififcate is expired")

// ErrFuture indicates that a certificate NotBefore date is in the future
var ErrFuture = fmt.Errorf("certificate is still not valid")

// ErrNil is an error thrown when a nil certificate pointer is evaluated
var ErrNil = fmt.Errorf("nil certificate")

// ErrNoCerts indicates that no certificates are available for processing with
// the given spec
var ErrNoCerts = fmt.Errorf("no certificates to process")

// ProcessCert takes a spec certificate specification, which might be a file
// containing a PEM certificate or a dial string to connect to and obtain the
// certificate from.
func ProcessCert(spec string) (Result, error) {

	if _, err := os.Stat(spec); err == nil {
		return ReadFromFile(spec)
	}

	conn, err := tls.Dial("tcp", spec, nil)
	if err == nil {
		defer conn.Close()

		state := conn.ConnectionState()

		r := Result{}

		if len(state.PeerCertificates) == 0 {
			return Result{Success: false, DaysLeft: -1}, ErrNoCerts
		}

		for _, c := range state.PeerCertificates {
			r, err = Check(c)
			if err != nil {
				return r, err
			}
		}

		return r, nil
	}

	return Result{Success: false, DaysLeft: -1}, err
}

// ReadFromFile reads a certificate from a local file and returns the result of
// processing it
func ReadFromFile(name string) (Result, error) {

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

	if len(certs) == 0 {
		return r, ErrNoCerts
	}

	for _, c := range certs {
		r, err = Check(c)
		if err != nil {
			return r, err
		}
	}

	return r, nil
}

// Check validates the expiration dates of the given certificate, returning the
// relevant data.
func Check(c *x509.Certificate) (Result, error) {
	if c == nil {
		return Result{Success: false, DaysLeft: -1}, ErrNil
	}

	now := time.Now()

	r := Result{
		Cert:     c,
		DaysLeft: int(c.NotAfter.Sub(now).Round(time.Hour).Hours() / 24),
		Success:  true,
	}

	if !now.After(c.NotBefore) {
		r.Success = false
		return r, ErrFuture
	}

	if now.After(c.NotAfter) {
		r.Success = false
		return r, ErrExpired
	}

	return r, nil
}
