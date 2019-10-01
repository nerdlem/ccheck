package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgproto3"
)

func doSMTPStartTLS(nc net.Conn, spec string, config *tls.Config) ([]*x509.Certificate, [][]*x509.Certificate, error) {

	var tconn *textproto.Conn
	var msg string

	conn := textproto.NewConn(nc)

	// EHLO FQDN

	hostName, err := os.Hostname()
	if err != nil {
		return nil, nil, err
	}

	nc.SetDeadline(time.Now().Add(TEHLO))
	_, err = conn.Cmd("EHLO %s", hostName)
	if err != nil {
		return nil, nil, err
	}

	// Read response and look for STARTTLS support

	_, msg, err = conn.Reader.ReadResponse(2)
	if err != nil {
		return nil, nil, err
	}

	if !strings.Contains(msg, "STARTTLS") {
		return nil, nil, ErrNoSTARTTLS
	}

	// Setup STARTTLS (passing conn to the TLS layer) — force SNI in case it matters

	nc.SetDeadline(time.Now().Add(TSTARTTLS))
	_, err = conn.Cmd("STARTTLS")
	if err != nil {
		return nil, nil, err
	}

	_, _, err = conn.Reader.ReadResponse(2)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	if _, _, err = tconn.Reader.ReadResponse(0); err != nil {
		return nil, nil, err
	}

	cs := tc.ConnectionState()

	nc.SetDeadline(time.Now().Add(TQUIT))
	if _, err = tconn.Cmd("QUIT"); err != nil {
		return nil, nil, err
	}

	if _, _, err = tconn.Reader.ReadResponse(2); err != nil {
		return nil, nil, err
	}

	return cs.PeerCertificates, cs.VerifiedChains, nil
}

func doIMAPStartTLS(nc net.Conn, spec string, config *tls.Config) ([]*x509.Certificate, [][]*x509.Certificate, error) {

	var tconn *textproto.Conn
	var msg string

	conn := textproto.NewConn(nc)

	// Check whether this server supports STARTTLS

	nc.SetDeadline(time.Now().Add(TEHLO))
	_, err := conn.Cmd("1 CAPABILITY")
	if err != nil {
		return nil, nil, err
	}

	msg = ""
	for {
		var line string
		line, err = conn.Reader.ReadLine()
		if err != nil {
			return nil, nil, err
		}

		msg = fmt.Sprintf("%s%s", msg, line)
		if strings.HasPrefix(line, "1 ") {
			break
		}
	}

	if !strings.Contains(msg, "STARTTLS") {
		return nil, nil, ErrNoSTARTTLS
	}

	// Setup STARTTLS (passing conn to the TLS layer) — force SNI in case it matters

	nc.SetDeadline(time.Now().Add(TSTARTTLS))
	_, err = conn.Cmd("1 STARTTLS")
	if err != nil {
		return nil, nil, err
	}

	msg, err = conn.Reader.ReadLine()
	if err != nil {
		return nil, nil, err
	}

	if !strings.HasPrefix(msg, "1 OK") {
		return nil, nil, fmt.Errorf(msg)
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
		return nil, nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, nil, err
	}

	cs := tc.ConnectionState()

	nc.SetDeadline(time.Now().Add(TQUIT))
	if _, err = tconn.Cmd("3 LOGOUT"); err != nil {
		return nil, nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, nil, err
	}

	return cs.PeerCertificates, cs.VerifiedChains, nil
}

func doPOPStartTLS(nc net.Conn, spec string, config *tls.Config) ([]*x509.Certificate, [][]*x509.Certificate, error) {

	var tconn *textproto.Conn
	var msg string

	conn := textproto.NewConn(nc)

	// Setup STARTTLS (passing conn to the TLS layer) — force SNI in case it matters

	nc.SetDeadline(time.Now().Add(TSTARTTLS))
	_, err := conn.Cmd("STLS")
	if err != nil {
		return nil, nil, err
	}

	msg, err = conn.Reader.ReadLine()
	if err != nil {
		return nil, nil, err
	}

	if !strings.HasPrefix(msg, "+OK") {
		return nil, nil, fmt.Errorf(msg)
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
		return nil, nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, nil, err
	}

	cs := tc.ConnectionState()

	nc.SetDeadline(time.Now().Add(TQUIT))
	if _, err = tconn.Cmd("QUIT"); err != nil {
		return nil, nil, err
	}

	if _, err = tconn.Reader.ReadLine(); err != nil {
		return nil, nil, err
	}

	return cs.PeerCertificates, cs.VerifiedChains, nil
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
func GetValidSTARTTLSCert(spec string, config *tls.Config) ([]*x509.Certificate, [][]*x509.Certificate, error) {

	var msg string

	nc, err := net.DialTimeout("tcp", spec, TNewConn)
	if err != nil {
		return nil, nil, err
	}

	conn := textproto.NewConn(nc)

	// Accept any 2xx greeting or bust
	nc.SetDeadline(time.Now().Add(TGreeting))
	msg, err = getGreeting(conn)
	if err != nil {
		return nil, nil, err
	}

	// Check for known protocols and pass control to the right handler method.

	if strings.HasPrefix(msg, "220") {
		return doSMTPStartTLS(nc, spec, config)
	}

	if strings.HasPrefix(msg, "* OK") {
		return doIMAPStartTLS(nc, spec, config)
	}

	if strings.HasPrefix(msg, "+OK") {
		return doPOPStartTLS(nc, spec, config)
	}

	// return nil, ErrUnsupportedSTARTTLS
	return nil, nil, fmt.Errorf("Unhandled response <%s>", msg)
}

// GetValidPostgresCert connects to a SMTP server and retrieves and validates
// the certificate obtained through a valid protocol negotiation.
func GetValidPostgresCert(spec string, config *tls.Config) ([]*x509.Certificate, [][]*x509.Certificate, error) {

	nc, err := net.DialTimeout("tcp", spec, TNewConn)
	if err != nil {
		return nil, nil, err
	}

	// Magic command to start TLS
	err = binary.Write(nc, binary.BigEndian, []int32{8, 80877103})
	if err != nil {
		return nil, nil, err
	}

	response := make([]byte, 1)
	if _, err = io.ReadFull(nc, response); err != nil {
		return nil, nil, err
	}

	if response[0] != 'S' {
		return nil, nil, ErrNoPostgresTLS
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
		return nil, nil, err
	}

	cs := tc.ConnectionState()

	return cs.PeerCertificates, cs.VerifiedChains, nil
}
