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

	"github.com/nerdlem/ccheck/cert"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var minDays int
var expired, quiet bool
var inputFile string

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
		errors := 0
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

		for _, spec := range specSlice {
			r, err := cert.ProcessCert(spec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", spec, err)
				errors++
				continue
			}

			if !r.Success {
				fmt.Fprintf(os.Stderr, "%s: failed\n", spec)
				errors++
				continue
			}

			if minDays != 0 {
				if minDays > r.DaysLeft {
					fmt.Fprintf(os.Stderr, "%s: expires in %d days\n", spec, r.DaysLeft)
					if expired {
						if !quiet {
							fmt.Printf("%s\n", spec)
						}
					} else {
						errors++
					}
					continue
				}
			}

			if !quiet && !expired {
				fmt.Printf("%s\n", spec)
			}
		}

		if errors > 0 {
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
	RootCmd.PersistentFlags().IntVar(&minDays, "min-days", 15, "Minimum days left")
	RootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Supress passing cert spec listing on success")
	RootCmd.PersistentFlags().BoolVar(&expired, "show-expired", false, "Match expired or close-to-expiry certs")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}
