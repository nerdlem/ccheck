package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	tap "github.com/mndrix/tap-go"
	"github.com/nerdlem/ccheck/cert"
	"github.com/spf13/viper"
)

var (
	behindProxy, expired, jsonRequested, postgres, quiet,
	skipVerify, starttls, tapRequested bool
	certFile, inputFile, keyFile, rootFile string
	clientCertificates                     []tls.Certificate
	cSpec                                  chan Spec
	minDays, numWorkers                    int
	protocol                               cert.Protocol = cert.PSOCKET
	results                                []CertResult
	rootBytes                              []byte
	rootCertPool                           *x509.CertPool
	specSlice                              []string
	wg                                     sync.WaitGroup
)

func setupProtocol() {
	protocol = cert.PSOCKET

	if postgres {
		protocol = cert.PPG
	} else if starttls {
		protocol = cert.PSTARTTLS
	}
}

func setupSpecSlice(args []string) {

	if len(args) == 0 && inputFile == "" {
		fmt.Fprintf(os.Stderr, "must provide one or more endpoint specs or use --input-file\n")
		os.Exit(2)
	}

	if inputFile == "" {
		specSlice = args
	} else {
		var err error
		specSlice, err = cert.ReadSpecSliceFromFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read input file %s: %s\n", inputFile, err)
		}
	}
}

func setupClientCertificates() {

	if certFile != "" || keyFile != "" {
		if (certFile != "" || keyFile != "") && (certFile == "" || keyFile == "") {
			fmt.Fprintf(os.Stderr, "must specify certificate and key file together\n")
			os.Exit(2)
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading client cert / key: %s\n", err)
			os.Exit(2)
		}

		clientCertificates = append(clientCertificates, cert)
	}
}

func setupRootFile() {

	var err error

	if rootFile == "" {
		rootCertPool = nil
	} else {
		rootCertPool = x509.NewCertPool()

		rootBytes, err = ioutil.ReadFile(rootFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read root cert from %s: %s\n", rootFile, err)
			os.Exit(2)
		}

		if !rootCertPool.AppendCertsFromPEM(rootBytes) {
			fmt.Fprintf(os.Stderr, "failed to append certs from %s\n", rootFile)
			os.Exit(2)
		}
	}

}

// tapOutput produces TAP formatted output. As a side effect, it also
// updates the seenErrors counter.
func tapOutput(c <-chan CertResult) {
	t = tap.New()
	t.Header(0)

	for r := range c {
		if r.Err != nil {
			t.Fail(fmt.Sprintf("%s %s %s", r.Spec, r.Err, r.Result.Protocol.String()))
			seenErrors++
			r.WG.Done()
			continue
		}

		if !r.Result.Success {
			t.Fail(fmt.Sprintf("%s failed (took %0.3f secs) %s", r.Spec, r.Result.Delay.Seconds(), r.Result.Protocol.String()))
			seenErrors++
			r.WG.Done()
			continue
		}

		if minDays != 0 {
			if minDays > r.Result.DaysLeft {
				t.Fail(fmt.Sprintf("%s expires in %d days (took %0.3f secs) %s",
					r.Spec, r.Result.DaysLeft, r.Result.Delay.Seconds(), r.Result.Protocol.String()))
				seenErrors++
			} else {
				t.Pass(fmt.Sprintf("%s expires in %d days (took %0.3f secs) %s",
					r.Spec, r.Result.DaysLeft, r.Result.Delay.Seconds(), r.Result.Protocol.String()))
			}
		} else {
			t.Pass(fmt.Sprintf("%s not expired (took %0.3f secs) %s", r.Spec, r.Result.Delay.Seconds(),
				r.Result.Protocol.String()))
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
			fmt.Fprintf(os.Stderr, "%s: %s, %s\n", r.Spec, r.Err, r.Result.Protocol.String())
			seenErrors++
			r.WG.Done()
			continue
		}

		if !r.Result.Success {
			fmt.Fprintf(os.Stderr, "%s: failed, %s\n", r.Spec, r.Result.Protocol.String())
			seenErrors++
			r.WG.Done()
			continue
		}

		if minDays != 0 {
			if minDays > r.Result.DaysLeft {
				fmt.Fprintf(os.Stderr, "%s: expires in %d days, %s\n", r.Spec, r.Result.DaysLeft, r.Result.Protocol.String())
				if expired {
					if !quiet {
						fmt.Printf("%s %s\n", r.Spec, r.Result.Protocol.String())
					}
				} else {
					seenErrors++
				}
				r.WG.Done()
				continue
			}
		}

		if !quiet && !expired {
			fmt.Printf("%s %s\n", r.Spec, r.Result.Protocol.String())
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
