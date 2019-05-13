package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	tap "github.com/mndrix/tap-go"
	"github.com/nerdlem/ccheck/cert"
	"github.com/spf13/viper"
)

var (
	cSpec               chan Spec
	minDays, numWorkers int
	expired, postgres, quiet, skipVerify,
	tapRequested, jsonRequested, starttls bool
	certFile, inputFile, keyFile, rootFile string
	clientCertificates                     []tls.Certificate
	rootCertPool                           *x509.CertPool
)

// tapOutput produces TAP formatted output. As a side effect, it also
// updates the seenErrors counter.
func tapOutput(c <-chan CertResult) {
	t = tap.New()
	t.Header(0)

	for r := range c {
		if r.Err != nil {
			t.Fail(fmt.Sprintf("%s %s", r.Spec, r.Err))
			seenErrors++
			r.WG.Done()
			continue
		}

		if !r.Result.Success {
			t.Fail(fmt.Sprintf("%s failed (took %0.3f secs)", r.Spec, r.Result.Delay.Seconds()))
			seenErrors++
			r.WG.Done()
			continue
		}

		if minDays != 0 {
			if minDays > r.Result.DaysLeft {
				t.Fail(fmt.Sprintf("%s expires in %d days (took %0.3f secs)",
					r.Spec, r.Result.DaysLeft, r.Result.Delay.Seconds()))
				seenErrors++
			} else {
				t.Pass(fmt.Sprintf("%s expires in %d days (took %0.3f secs)",
					r.Spec, r.Result.DaysLeft, r.Result.Delay.Seconds()))
			}
		} else {
			t.Pass(fmt.Sprintf("%s not expired (took %0.3f secs)", r.Spec, r.Result.Delay.Seconds()))
		}
		r.WG.Done()
	}

	t.AutoPlan()
}

// simpleOutput produces a simple output format. As a side effect, it also
// updates the seenErrors counter.
func simpleOutput(c <-chan CertResult) {
	for r := range c {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", r.Spec, r.Err)
			seenErrors++
			r.WG.Done()
			continue
		}

		if !r.Result.Success {
			fmt.Fprintf(os.Stderr, "%s: failed\n", r.Spec)
			seenErrors++
			r.WG.Done()
			continue
		}

		if minDays != 0 {
			if minDays > r.Result.DaysLeft {
				fmt.Fprintf(os.Stderr, "%s: expires in %d days\n", r.Spec, r.Result.DaysLeft)
				if expired {
					if !quiet {
						fmt.Printf("%s\n", r.Spec)
					}
				} else {
					seenErrors++
				}
				r.WG.Done()
				continue
			}
		}

		if !quiet && !expired {
			fmt.Printf("%s\n", r.Spec)
		}

		r.WG.Done()
	}
}

// setupWorkers launches the required number of workers as per the configuration
// / CLI arguments, setting up the required channels.
func setupWorkers(cons Consumer) chan Spec {
	cSpec = make(chan Spec, 100)
	cCert := make(chan CertResult, 100)

	for i := 0; i < viper.GetInt("check.workers"); i++ {
		go processWorker(cSpec, cCert)
	}

	go cons(cCert)
	return cSpec
}

func jsonCollector(c <-chan CertResult) {
	for r := range c {
		acc := r.Accumulator
		wg := r.WG
		r.Accumulator = nil
		r.WG = nil
		*acc = append(*acc, r)
		wg.Done()
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc")
		viper.AddConfigPath(".")
		viper.SetConfigName("ccheck")
	}

	viper.SetEnvPrefix("ccheck")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()

	// Try to be smart about errors
	if err != nil {
		_, fnfe := err.(viper.ConfigFileNotFoundError)
		if cfgFile != "" || !fnfe {
			panic(fmt.Errorf("invalid config file %s: %s", viper.ConfigFileUsed(), err))
		}
	}
}

// processWorker processes a spec concurrently
func processWorker(s <-chan Spec, c chan<- CertResult) {
	for spec := range s {
		cr := CertResult{Accumulator: spec.Accumulator, Spec: spec.Value, Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05 MST"), WG: spec.WG}
		targetName := (strings.SplitN(spec.Value, ":", 2))[0]

		config := tls.Config{
			Certificates:       clientCertificates,
			InsecureSkipVerify: skipVerify,
			RootCAs:            rootCertPool,
			ServerName:         targetName,
		}

		r, err := cert.ProcessCert(spec.Value, &config, spec.Protocol)

		cr.Result = &r
		if err != nil {
			cr.Err = err
			cr.ErrString = fmt.Sprintf("%s", err)
		} else {
			cr.WG = spec.WG
		}

		c <- cr
	}
}
