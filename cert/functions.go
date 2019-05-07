package cert

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/pgproto3"
)

// Result encodes the result of validating a Certificate
type Result struct {
	// Success indicates whether the checking was successful or not.
	Success bool `json:"success"`
	// DaysLeft indicates the difference between current time and expiration date
	// of the certificate, with negative numbers indicating errors or expired
	// certificates.
	DaysLeft int `json:"days_left"`
	// Cert points to the certificate that was checked. This is useful to
	// piggyback checks on certificates.
	Cert *x509.Certificate `json:"cert"`
	// Delay keeps track of how long it took to perform the certificate validation
	Delay time.Duration `json:"delay"`
}

// Protocol is used to encode the protocol to use to get TLS certificates from
// the server side.
type Protocol int

const (
	// PSOCKET is a plain old TLS socket
	PSOCKET Protocol = iota
	// PSTARTTLS is a session in which STARTTLS is used to access TLS
	// certificates.
	PSTARTTLS
	// PPG is a PostgreSQL session
	PPG
)

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

// ErrNoSTARTTLS indicates that the remote server does not advertise STARTTLS
// support
var ErrNoSTARTTLS = fmt.Errorf("Remote server does not announce STARTTLS")

// ErrUnsupportedSTARTTLS is returned when the remote server does not speak a
// protocol for which we support STARTTLS
var ErrUnsupportedSTARTTLS = fmt.Errorf("Unknown / unsupported protocol for STARTTLS")

// ErrNoPostgresTLS indicates that the PotgreSQL server did not accept our
// attempt to setup TLS.
var ErrNoPostgresTLS = fmt.Errorf("PostgreSQL does not seem to support TLS")

// TNewConn is the interval to wait for a new connection to the MTA to complete
var TNewConn = 30 * time.Second

// TGreeting is the interval to wait for the server greeting after connecting
var TGreeting = 10 * time.Second

// TEHLO is the interval to wait our EHLO command to be accepted and replied to,
// for SMTP servers
var TEHLO = 10 * time.Second

// TSTARTTLS is the interval to wait for out STARTTLS to be accepted and responded
var TSTARTTLS = 10 * time.Second

// TTLS is the interval to wait for TLS establishment after STARTTLS
var TTLS = 10 * time.Second

// TNOOP is the interval to wait for the NOOP command issued upon TLS to complete
var TNOOP = 10 * time.Second

// TQUIT is the interval to wait for our final QUIT command to be accepted and
// responded. Also used for the LOGOUT IMAP command for IMAP servers
var TQUIT = 10 * time.Second

func doSMTPStartTLS(nc net.Conn, spec string, config *tls.Config) ([]*x509.Certificate, error) {

	var tconn *textproto.Conn
	var msg string

	conn := textproto.NewConn(nc)

	// EHLO FQDN

	hostName, err := os.Hostname()
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

func doIMAPStartTLS(nc net.Conn, spec string, config *tls.Config) ([]*x509.Certificate, error) {

	var tconn *textproto.Conn
	var msg string

	conn := textproto.NewConn(nc)

	// Check whether this server supports STARTTLS

	nc.SetDeadline(time.Now().Add(TEHLO))
	_, err := conn.Cmd("1 CAPABILITY")
	if err != nil {
		return nil, err
	}

	msg = ""
	for {
		var line string
		line, err = conn.Reader.ReadLine()
		if err != nil {
			return nil, err
		}

		msg = fmt.Sprintf("%s%s", msg, line)
		if strings.HasPrefix(line, "1 ") {
			break
		}
	}

	if !strings.Contains(msg, "STARTTLS") {
		return nil, ErrNoSTARTTLS
	}

	// Setup STARTTLS (passing conn to the TLS layer) — force SNI in case it matters

	nc.SetDeadline(time.Now().Add(TSTARTTLS))
	_, err = conn.Cmd("1 STARTTLS")
	if err != nil {
		return nil, err
	}

	msg, err = conn.Reader.ReadLine()
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(msg, "1 OK") {
		return nil, fmt.Errorf(msg)
	}

	// At this point, we're ready to pass the socket to the underlying TLS layer

	nc.SetDeadline(time.Now().Add(TTLS))
	tc := tls.Client(nc, config)
	tconn = textproto.NewConn(tc)

	// At this point, we have a TLS connection initialized so let's pull the certs
	// out of it to return no our caller. We need to send some traffic to populate
	// state, so let's send a NOOP at this point.

	nc.SetDeadline(time.Now().Add(TNOOP))
	if _, err = tconn.Cmd("2 NOOP"); err != nil {
		return nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, err
	}

	cs := tc.ConnectionState()
	ret := cs.PeerCertificates

	nc.SetDeadline(time.Now().Add(TQUIT))
	if _, err = tconn.Cmd("3 LOGOUT"); err != nil {
		return nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, err
	}

	return ret, nil
}

func doPOPStartTLS(nc net.Conn, spec string, config *tls.Config) ([]*x509.Certificate, error) {

	var tconn *textproto.Conn
	var msg string

	conn := textproto.NewConn(nc)

	// Setup STARTTLS (passing conn to the TLS layer) — force SNI in case it matters

	nc.SetDeadline(time.Now().Add(TSTARTTLS))
	_, err := conn.Cmd("STLS")
	if err != nil {
		return nil, err
	}

	msg, err = conn.Reader.ReadLine()
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(msg, "+OK") {
		return nil, fmt.Errorf(msg)
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

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, err
	}

	cs := tc.ConnectionState()
	ret := cs.PeerCertificates

	nc.SetDeadline(time.Now().Add(TQUIT))
	if _, err = tconn.Cmd("QUIT"); err != nil {
		return nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, err
	}

	return ret, nil
}

func getGreeting(conn *textproto.Conn) (string, error) {
	msg := ""

	for {
		buf, err := conn.Reader.ReadLine()
		if err != nil {
			return "", err
		}

		// Is it IMAP? Then return right away
		if strings.HasPrefix(buf, "* OK") {
			return buf, nil
		}

		// Perhaps POP?
		if strings.HasPrefix(buf, "+OK") {
			return buf, nil
		}

		// Short-circuit SMTP with rejection (rate-limiting, etc)
		if !strings.HasPrefix(buf, "2") {
			return buf, ErrUnsupportedSTARTTLS
		}

		// We know that the response starts with 2 and has a space after the result
		// code, so this is either a single line greeting or the end of a multi-line
		// greeting.
		if len(buf) > 4 && buf[3] == ' ' {
			msg = fmt.Sprintf("%s%s", msg, buf)
			return msg, nil
		}
		msg = fmt.Sprintf("%s%s", msg, buf)
	}
}

// GetValidSTARTTLSCert connects to a server, determines the underlying protocol
// and if supported, forwards to the correct handler method. Otherwise returns
// an appropriate error.
func GetValidSTARTTLSCert(spec string, config *tls.Config) ([]*x509.Certificate, error) {

	var msg string

	nc, err := net.DialTimeout("tcp", spec, TNewConn)
	if err != nil {
		return nil, err
	}

	conn := textproto.NewConn(nc)

	// Accept any 2xx greeting or bust
	nc.SetDeadline(time.Now().Add(TGreeting))
	msg, err = getGreeting(conn)
	if err != nil {
		return nil, err
	}

	// Check for known protocols and pass control to the right handler method.

	if strings.Contains(msg, "SMTP") {
		if !strings.Contains(msg, "ESMTP") {
			return nil, ErrNoESMTP
		}

		return doSMTPStartTLS(nc, spec, config)
	}

	if strings.HasPrefix(msg, "* OK") {
		return doIMAPStartTLS(nc, spec, config)
	}

	if strings.HasPrefix(msg, "+OK") {
		return doPOPStartTLS(nc, spec, config)
	}

	// return nil, ErrUnsupportedSTARTTLS
	return nil, fmt.Errorf("Unhandled response <%s>", msg)
}

// GetValidPostgresCert connects to a SMTP server and retrieves and validates
// the certificate obtained through a valid protocol negotiation.
func GetValidPostgresCert(spec string, config *tls.Config) ([]*x509.Certificate, error) {

	nc, err := net.DialTimeout("tcp", spec, TNewConn)
	if err != nil {
		return nil, err
	}

	// Magic command to start TLS
	err = binary.Write(nc, binary.BigEndian, []int32{8, 80877103})
	if err != nil {
		return nil, err
	}

	response := make([]byte, 1)
	if _, err = io.ReadFull(nc, response); err != nil {
		return nil, err
	}

	if response[0] != 'S' {
		return nil, ErrNoPostgresTLS
	}

	// TLS request accepted, so setup TLS and send a startup message to initialize
	// the certificate chain.

	tc := tls.Client(nc, config)

	startupMsg := pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":     "ccheck",
			"password": "ccheck",
			"database": "ccheck",
		},
	}

	if _, err := tc.Write(startupMsg.Encode(nil)); err != nil {
		return nil, err
	}

	cs := tc.ConnectionState()
	ret := cs.PeerCertificates

	return ret, nil
}

func evalCerts(certs []*x509.Certificate, r Result, start time.Time) (Result, error) {
	var ret Result
	var err error

	for i, c := range certs {
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

// ProcessCert takes a spec certificate specification, which might be a file
// containing a PEM certificate or a dial string to connect to and obtain the
// certificate from.
func ProcessCert(spec string, config *tls.Config, p Protocol) (Result, error) {

	start := time.Now()
	var err error

	if _, err = os.Stat(spec); err == nil {
		return ReadFromFile(spec)
	}

	r := Result{Success: false, DaysLeft: -1, Delay: 0 * time.Second}

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

			return evalCerts(state.PeerCertificates, Result{}, start)
		}
	case PSTARTTLS:
		var certs []*x509.Certificate

		certs, err = GetValidSTARTTLSCert(spec, config)
		if err != nil {
			return r, err
		}

		if len(certs) == 0 {
			return r, ErrNoCerts
		}

		return evalCerts(certs, r, start)
	case PPG:
		var certs []*x509.Certificate

		certs, err = GetValidPostgresCert(spec, config)
		if err != nil {
			return r, err
		}

		if len(certs) == 0 {
			return r, ErrNoCerts
		}

		return evalCerts(certs, r, start)

	default:
		return r, fmt.Errorf("unimplemented protocol %d", p)
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
