package cert

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strings"
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
	// Delay keeps track of how long it took to perform the certificate validation
	Delay time.Duration
}

// String satisfies the Stringer interface
func (r *Result) String() string {
	res := fmt.Sprintf("Success=%v, DaysLeft=%d, Delay=%0.3f cert is", r.Success, r.DaysLeft, r.Delay.Seconds())
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

// ErrNoESMTP indicates that the SMTP server does not support ESMTP, so no
// STARTTLS is even attempted
var ErrNoESMTP = fmt.Errorf("SMTP server does not speak ESMTP")

// ErrNoSTARTTLS indicates that the SMTP server does not advertise STARTTLS
// support after EHLO
var ErrNoSTARTTLS = fmt.Errorf("SMTP server does not announce STARTTLS")

// TNewConn is the interval to wait for a new connection to the MTA to complete
var TNewConn = 30 * time.Second

// TGreeting is the interval to wait for the MTA greeting after connecting
var TGreeting = 10 * time.Second

// TEHLO is the interval to wait our EHLO command to be accepted and replied to
var TEHLO = 10 * time.Second

// TSTARTTLS is the interval to wait for out STARTTLS to be accepted and responded
var TSTARTTLS = 10 * time.Second

// TTLS is the interval to wait for TLS establishment after STARTTLS
var TTLS = 10 * time.Second

// TNOOP is the interval to wait for the NOOP command issued upon TLS to complete
var TNOOP = 10 * time.Second

// TQUIT is the interval to wait for our final QUIT command to be accepted and responded
var TQUIT = 10 * time.Second

// GetValidSTARTTLSCert connects to a SMTP server and retrieves and validates
// the certificate obtained through a valid protocol negotiation.
func GetValidSTARTTLSCert(spec string, config *tls.Config) ([]*x509.Certificate, error) {

	var hostName, msg string
	var tconn *textproto.Conn

	nc, err := net.Dial("tcp", spec)
	if err != nil {
		return nil, err
	}

	nc.SetDeadline(time.Now().Add(TNewConn))
	conn := textproto.NewConn(nc)

	// Accept any 2xx greeting or bust
	nc.SetDeadline(time.Now().Add(TGreeting))
	_, msg, err = conn.Reader.ReadResponse(2)
	if err != nil {
		return nil, err
	}

	// This is a very liberal test, as the spec requires this to be immediately
	// following the FQDN in the greeting.
	if !strings.Contains(msg, "ESMTP") {
		return nil, ErrNoESMTP
	}

	// EHLO FQDN

	hostName, err = os.Hostname()
	if err != nil {
		return nil, err
	}

	nc.SetDeadline(time.Now().Add(TEHLO))
	_, err = conn.Cmd("EHLO %s", hostName)
	if err != nil {
		return nil, err
	}

	// Read response and look for STARTTLS support

	_, msg, err = conn.Reader.ReadResponse(2)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(msg, "STARTTLS") {
		return nil, ErrNoSTARTTLS
	}

	// Setup STARTTLS (passing conn to the TLS layer) — force SNI in case it matters

	nc.SetDeadline(time.Now().Add(TSTARTTLS))
	_, err = conn.Cmd("STARTTLS")
	if err != nil {
		return nil, err
	}

	_, _, err = conn.Reader.ReadResponse(2)
	if err != nil {
		return nil, err
	}

	// At this point, we're ready to pass the socket to the underlying TLS layer

	nc.SetDeadline(time.Now().Add(TTLS))
	tc := tls.Client(nc, config)
	tconn = textproto.NewConn(tc)

	// At this point, we have a TLS connection initialized so let's pull the certs
	// out of it to return no our caller. We need to send some traffic to populate
	// state, so let's send a NOOP at this point.

	nc.SetDeadline(time.Now().Add(TNOOP))
	if _, err = tconn.Cmd("NOOP"); err != nil {
		return nil, err
	}

	if _, _, err = tconn.Reader.ReadResponse(0); err != nil {
		return nil, err
	}

	cs := tc.ConnectionState()
	ret := cs.PeerCertificates

	nc.SetDeadline(time.Now().Add(TQUIT))
	if _, err = tconn.Cmd("QUIT"); err != nil {
		return nil, err
	}

	if _, _, err = tconn.Reader.ReadResponse(2); err != nil {
		return nil, err
	}

	return ret, nil
}

// ProcessCert takes a spec certificate specification, which might be a file
// containing a PEM certificate or a dial string to connect to and obtain the
// certificate from.
func ProcessCert(spec string, config *tls.Config, starttls bool) (Result, error) {

	start := time.Now()

	if _, err := os.Stat(spec); err == nil {
		return ReadFromFile(spec)
	}

	r := Result{Success: false, DaysLeft: -1, Delay: 0 * time.Second}

	if starttls {
		targetName := (strings.SplitN(spec, ":", 2))[0]
		config.ServerName = targetName

		certs, err := GetValidSTARTTLSCert(spec, config)
		if err != nil {
			return r, err
		}

		if len(certs) == 0 {
			return r, ErrNoCerts
		}

		var ret Result

		for i, c := range certs {
			if i == 0 {
				ret = r
			}

			r, err = Check(c)
			if err != nil {
				return r, err
			}

			if !c.IsCA {
				ret = r
			}
		}

		ret.Delay = time.Now().Sub(start)
		return ret, nil
	}

	conn, err := tls.Dial("tcp", spec, config)
	if err == nil {
		defer conn.Close()

		state := conn.ConnectionState()

		r := Result{}

		if len(state.PeerCertificates) == 0 {
			return Result{Success: false, DaysLeft: -1, Delay: time.Now().Sub(start)}, ErrNoCerts
		}

		var ret Result

		for i, c := range state.PeerCertificates {
			if i == 0 {
				ret = r
			}

			r, err = Check(c)
			if err != nil {
				r.Delay = time.Now().Sub(start)
				return r, err
			}

			if !c.IsCA {
				ret = r
			}
		}

		ret.Delay = time.Now().Sub(start)
		return ret, nil
	}

	return Result{Success: false, DaysLeft: -1, Delay: time.Now().Sub(start)}, err

}

var (
	reComment    = regexp.MustCompile(`#.*$`)
	reWhitespace = regexp.MustCompile(`\s+`)
)

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

	if len(certs) == 0 {
		return r, ErrNoCerts
	}

	var ret Result

	for i, c := range certs {
		if i == 0 {
			ret = r
		}

		r, err = Check(c)
		if err != nil {
			return r, err
		}

		if !c.IsCA {
			ret = r
		}
	}

	ret.Delay = time.Now().Sub(start)
	return ret, nil
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
