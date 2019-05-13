package cert

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

func TestList(t *testing.T) {
	l, err := ReadSpecSliceFromFile("no-such-file")
	if err == nil {
		t.Errorf("reading unexistent list file should return an error")
	}

	if l != nil {
		t.Errorf("for unexistent list files nil should be returned")
	}

	l, err = ReadSpecSliceFromFile("empty.list")
	if err != nil {
		t.Errorf("unexpected error returned reading empty.list: %s", err)
	}

	if len(l) != 0 {
		t.Logf("unexpected list contents: %s", spew.Sdump(l))
		t.Errorf("returned list should be empty, but has %d elements instead", len(l))
	}

	l, err = ReadSpecSliceFromFile("simple.list")
	if err != nil {
		t.Errorf("unexpected error returned reading empty.list: %s", err)
	}

	t.Logf("unexpected list contents: %s", spew.Sdump(l))

	if len(l) != 1 {
		t.Errorf("returned list should have a single, but has %d elements instead", len(l))
	}

	if l[0] != "google-chain.pem" {
		t.Errorf("simple list should only contain google-chain.pem")
	}
}

func TestLocal(t *testing.T) {
	for _, spec := range []string{"google-chain.pem"} {

		t.Logf("testing spec %s", spec)

		r, err := ProcessCert(spec, nil, PSOCKET)

		t.Logf("result is %s", r.String())

		if err != nil {
			t.Errorf("unexpected error %s", err)
		}

		if !r.Success {
			t.Errorf("spec %s should have a valid certificate", spec)
		}

		if r.DaysLeft <= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}

	r, err := ProcessCert("empty.pem", nil, PSOCKET)
	if err != ErrNoCerts {
		t.Errorf("empty .pem file gave unexpected error %s", err)
	}
	if r.Success || r.DaysLeft != -1 || r.Cert != nil {
		t.Errorf("unexpected result for empty.pem: %s", r.String())
	}

	r, err = ProcessCert("bad.pem", nil, PSOCKET)
	if err == nil {
		t.Errorf("bad .pem should have thrown error")
	}
	if r.Success || r.DaysLeft != -1 || r.Cert != nil {
		t.Errorf("unexpected result for bad.pem: %s", r.String())
	}
}

func TestExternalPostgreSQL(t *testing.T) {
	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"babar.elephantsql.com:5432"} {

		t.Logf("testing spec %s", spec)

		cfg := tls.Config{
			InsecureSkipVerify: true,
		}

		r, err := ProcessCert(spec, &cfg, PPG)

		t.Logf("result is %s", r.String())

		if err != nil {
			t.Errorf("unexpected error %s", err)
		}

		if !r.Success {
			t.Errorf("spec %s should have a valid certificate", spec)
		}

		if r.DaysLeft <= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}
}

func TestExternalHTTPS(t *testing.T) {

	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"www.google.com:443", "microsoft.com:443", "apple.com:443"} {

		t.Logf("testing spec %s", spec)

		r, err := ProcessCert(spec, nil, PSOCKET)

		t.Logf("result is %s", r.String())

		if err != nil {
			t.Errorf("unexpected error %s", err)
		}

		if !r.Success {
			t.Errorf("spec %s should have a valid certificate", spec)
		}

		if r.DaysLeft <= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}
}

func TestESMTPSTARTTLS(t *testing.T) {
	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"ccheck.libertad.link:587"} {

		t.Logf("testing STARTTLS spec %s", spec)

		tc := tls.Config{
			ServerName: "ccheck.libertad.link",
		}

		r, err := ProcessCert(spec, &tc, PSTARTTLS)

		t.Logf("result is %s", r.String())

		if err != nil {
			t.Errorf("unexpected error %s", err)
		}

		if !r.Success {
			t.Errorf("spec %s should have a valid certificate", spec)
		}

		if r.DaysLeft <= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}
}

func TestIMAPSTARTTLS(t *testing.T) {
	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"outlook.office365.com:143"} {

		t.Logf("testing STARTTLS spec %s", spec)

		tc := tls.Config{
			ServerName: "outlook.office365.com",
		}

		r, err := ProcessCert(spec, &tc, PSTARTTLS)

		t.Logf("result is %s", r.String())

		if err != nil {
			t.Errorf("unexpected error %s", err)
		}

		if !r.Success {
			t.Errorf("spec %s should have a valid certificate", spec)
		}

		if r.DaysLeft <= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}
}

func TestPOPSTARTTLS(t *testing.T) {
	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"outlook.office365.com:110"} {

		t.Logf("testing STARTTLS spec %s", spec)

		tc := tls.Config{
			ServerName: "outlook.office365.com",
		}

		r, err := ProcessCert(spec, &tc, PSTARTTLS)

		t.Logf("result is %s", r.String())

		if err != nil {
			t.Errorf("unexpected error %s", err)
		}

		if !r.Success {
			t.Errorf("spec %s should have a valid certificate", spec)
		}

		if r.DaysLeft <= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}
}

func TestESMTPSTARTTLSBadName(t *testing.T) {
	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"ccheck.libertad.link:587"} {

		t.Logf("testing STARTTLS spec %s w/bogus ServerName", spec)

		tc := tls.Config{
			ServerName: "ccheck.libertad.invalid",
		}

		r, err := ProcessCert(spec, &tc, PSTARTTLS)

		t.Logf("result is %s", r.String())

		if err == nil {
			t.Errorf("expecting a validation error")
		}

		if r.Success {
			t.Errorf("spec %s should fail validation", spec)
		}

		if r.DaysLeft >= 0 {
			t.Errorf("days left for spec %s is %d, which is suspicious", spec, r.DaysLeft)
		}
	}
}

func TestProcessCert(t *testing.T) {
	current := x509.Certificate{
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * 25 * time.Hour),
	}

	expired := x509.Certificate{
		NotBefore: time.Now().Add(-2 * 24 * time.Hour),
		NotAfter:  time.Now().Add(-1 * 24 * time.Hour),
	}

	future := x509.Certificate{
		NotBefore: time.Now().Add(2 * 24 * time.Hour),
		NotAfter:  time.Now().Add(9 * 24 * time.Hour),
	}

	r := Result{}
	err := Check(&current, &r)

	t.Logf("result is %s", r.String())

	if !r.Success {
		t.Error("current Check() should be successful")
	}

	if r.DaysLeft != 25 {
		t.Errorf("DaysLeft for current %d != 25", r.DaysLeft)
	}

	if err != nil {
		t.Logf("unexpected Check() error %s", err)
		t.Error("current Check() should not return an error")
	}

	err = Check(&expired, &r)

	t.Logf("result is %s", r.String())

	if r.Success {
		t.Error("expired Check() should not be successful")
	}

	if r.DaysLeft != -1 {
		t.Logf("DaysLeft is %d", r.DaysLeft)
		t.Errorf("DaysLeft for expired %d != -1", r.DaysLeft)
	}

	if err != ErrExpired {
		t.Logf("unexpected error %s", err)
		t.Error("checking an expired certificate should return a suitable error")
	}

	err = Check(&future, &r)

	t.Logf("result is %s", r.String())

	if r.Success {
		t.Error("future Check() should not be successful")
	}

	if r.DaysLeft != 9 {
		t.Logf("DaysLeft is %d", r.DaysLeft)
		t.Errorf("DaysLeft for future %d != 9", r.DaysLeft)
	}

	if err != ErrFuture {
		t.Logf("unexpected error %s", err)
		t.Error("checking an future certificate should return a suitable error")
	}

	err = Check(nil, &r)

	t.Logf("result is %s", r.String())

	if r.Success {
		t.Error("nil Check() should not be successful")
	}

	if r.DaysLeft != -1 {
		t.Logf("DaysLeft is %d", r.DaysLeft)
		t.Errorf("DaysLeft for nil %d != -1", r.DaysLeft)
	}

	if err != ErrNil {
		t.Logf("unexpected error %s", err)
		t.Error("checking a nil certificate should return a suitable error")
	}

}
