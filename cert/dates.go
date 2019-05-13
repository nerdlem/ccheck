package cert

import (
	"crypto/x509"
	"time"
)

func evalCerts(certs []*x509.Certificate, r *Result, start time.Time) error {
	var err error

	if len(certs) == 0 {
		return ErrNoCerts
	}

	for _, c := range certs {

		if !c.IsCA {
			r.Cert = c
		}

		err = Check(c, r)
		if err != nil {
			break
		}
	}

	r.Delay = time.Now().Sub(start)
	return err
}

// Check validates the expiration dates of the given certificate, returning the
// relevant data.
func Check(c *x509.Certificate, r *Result) error {
	if c == nil {
		r.DaysLeft = -1
		r.Expired = false
		r.Success = false
		return ErrNil
	}

	now := time.Now()

	r.DaysLeft = int(c.NotAfter.Sub(now).Round(time.Hour).Hours() / 24)
	r.Success = true

	if !now.After(c.NotBefore) {
		r.Success = false
		return ErrFuture
	}

	if now.After(c.NotAfter) {
		r.Success = false
		r.Expired = true
		return ErrExpired
	}

	return nil
}
