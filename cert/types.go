package cert

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Result encodes the result of validating a Certificate
type Result struct {
	// Success indicates whether the checking was successful or not.
	Success bool `json:"success"`
	// DaysLeft indicates the difference between current time and expiration date
	// of the certificate, with negative numbers indicating errors or expired
	// certificates.
	DaysLeft int `json:"days_left"`
	// Set to true when the certificate is known to be expired
	Expired bool `json:"expired"`
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

// ErrNoTLS indicates that the specified endpoint did not complete the TLS handshake.
var ErrNoTLS = fmt.Errorf("Unable to complete TLS handshake")

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
