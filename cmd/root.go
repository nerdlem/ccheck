// Copyright © 2018 Luis E. Muñoz <github@lem.click>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"os"
	"sync"

	"github.com/mndrix/tap-go"
	"github.com/nerdlem/ccheck/cert"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var minDays, numWorkers int
var expired, quiet, tapRequested bool
var inputFile string

// CertResult holds a processed evaluation of a Spec
type CertResult struct {
	// Spec is the certificate specification evaluated.
	Spec string
	// Result is a pointer to the evaluation result
	Result *cert.Result
	// Err contains any error found during evaluation
	Err error
}

var wg sync.WaitGroup

// processWorker processes a spec concurrently
func processWorker(s <-chan string, c chan<- CertResult) {
	for spec := range s {
		cr := CertResult{Spec: spec}
		r, err := cert.ProcessCert(spec)
		if err != nil {
			cr.Err = err
		} else {
			cr.Result = &r
		}

		c <- cr
	}
}

// tapOutput produces TAP formatted output. As a side effect, it also
// updates the seenErrors counter.
func tapOutput(c <-chan CertResult) {
	t := tap.New()
	t.AutoPlan()
	for r := range c {
		if r.Err != nil {
			t.Fail(fmt.Sprintf("%s %s", r.Spec, r.Err))
			seenErrors++
			wg.Done()
			continue
		}

		if !r.Result.Success {
			t.Fail(fmt.Sprintf("%s failed (took %0.3f secs)", r.Spec, r.Result.Delay.Seconds()))
			seenErrors++
			wg.Done()
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
		wg.Done()
	}
}

// simpleOutput produces a simple output format. As a side effect, it also
// updates the seenErrors counter.
func simpleOutput(c <-chan CertResult) {
	for r := range c {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", r.Spec, r.Err)
			seenErrors++
			wg.Done()
			continue
		}

		if !r.Result.Success {
			fmt.Fprintf(os.Stderr, "%s: failed\n", r.Spec)
			seenErrors++
			wg.Done()
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
				wg.Done()
				continue
			}
		}

		if !quiet && !expired {
			fmt.Printf("%s\n", r.Spec)
		}

		wg.Done()
	}
}

var seenErrors int

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "ccheck",
	Short: "X509 certificate checker",
	Long: `Simple SSL certificate expiration checker.

Diagnostics are sent to STDERR. Certificates that pass the given
check criteria are printed on STDOUT. Listing can be supressed
to support scripting applications.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		seenErrors = 0
		var specSlice []string

		if inputFile == "" {
			specSlice = args
		} else {
			var err error
			specSlice, err = cert.ReadSpecSliceFromFile(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot read input file %s: %s", inputFile, err)
			}
		}

		cSpec := make(chan string, 100)
		cCert := make(chan CertResult, 100)

		for i := 0; i < numWorkers; i++ {
			go processWorker(cSpec, cCert)
		}

		if tapRequested {
			go tapOutput(cCert)
		} else {
			go simpleOutput(cCert)
		}

		for _, spec := range specSlice {
			wg.Add(1)
			cSpec <- spec
		}

		wg.Wait()

		if seenErrors > 0 {
			os.Exit(2)
		} else {
			os.Exit(0)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVarP(&inputFile, "input-file", "i", "", "Read cert specs from file")
	RootCmd.PersistentFlags().IntVarP(&numWorkers, "num-workers", "n", 1, "Parallel verification workers")
	RootCmd.PersistentFlags().IntVarP(&minDays, "min-days", "m", 15, "Minimum days left")
	RootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Supress passing cert spec listing on success")
	RootCmd.PersistentFlags().BoolVar(&expired, "show-expired", false, "Match expired or close-to-expiry certs")
	RootCmd.PersistentFlags().BoolVarP(&tapRequested, "tap", "t", false, "Produce TAP output")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}
