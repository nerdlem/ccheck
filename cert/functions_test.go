package cert

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestLocal(t *testing.T) {
	for _, spec := range []string{"google-chain.pem"} {

		t.Logf("testing spec %s", spec)

		r, err := ProcessCert(spec)

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

	r, err := ProcessCert("empty.pem")
	if err != ErrNoCerts {
		t.Errorf("empty .pem file gave unexpected error %s", err)
	}
	if r.Success || r.DaysLeft != -1 || r.Cert != nil {
		t.Errorf("unexpected result for empty.pem: %s", r.String())
	}

	r, err = ProcessCert("bad.pem")
	if err == nil {
		t.Errorf("bad .pem should have thrown error")
	}
	if r.Success || r.DaysLeft != -1 || r.Cert != nil {
		t.Errorf("unexpected result for bad.pem: %s", r.String())
	}
}

func TestExternal(t *testing.T) {

	t.Logf("These tests need Internet connectivity")

	for _, spec := range []string{"www.google.com:443", "microsoft.com:443", "apple.com:443"} {

		t.Logf("testing spec %s", spec)

		r, err := ProcessCert(spec)

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

	r, err := Check(&current)

	t.Logf("result is %s", r.String())

	if r.Cert != &current {
		t.Error("incorrect pointer to current cert returned")
	}

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

	r, err = Check(&expired)

	t.Logf("result is %s", r.String())

	if r.Cert != &expired {
		t.Error("incorrect pointer to expired cert returned")
	}

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

	r, err = Check(&future)

	t.Logf("result is %s", r.String())

	if r.Cert != &future {
		t.Error("incorrect pointer to future cert returned")
	}

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

	r, err = Check(nil)

	t.Logf("result is %s", r.String())

	if r.Cert != nil {
		t.Error("incorrect pointer to nil cert returned")
	}

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
