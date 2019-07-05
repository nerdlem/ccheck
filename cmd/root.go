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
	"encoding/json"
	"fmt"
	"os"

	"github.com/mndrix/tap-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var t *tap.T
var seenErrors int

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "ccheck",
	Short: "X509 certificate checker",
	Long: `Simple SSL certificate expiration checker.

Diagnostics are sent to STDERR. Certificates that pass the given
check criteria are printed on STDOUT. Listing can be suppressed
to support scripting applications.

Certificates to check can be specified as the filename of the PEM-encoded
container for the X.509 certificate or a <host:port> tuple resembling a
Go dial string.`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		seenErrors = 0

		if jsonRequested && tapRequested {
			fmt.Fprintf(os.Stderr, "only one of --tap and --json can be specified\n")
			os.Exit(2)
		}

		setupRootFile()
		setupClientCertificates()
		setupSpecSlice(args)
		setupProtocol()

		consumer := simpleOutput

		if tapRequested {
			consumer = tapOutput
		} else if jsonRequested {
			consumer = jsonCollector
		}

		cSpec = setupWorkers(consumer)

		for _, spec := range specSlice {
			wg.Add(1)
			cSpec <- Spec{
				Accumulator: &results,
				Protocol:    protocol,
				Value:       spec,
				WG:          &wg,
			}
		}

		close(cSpec)

		wg.Wait()

		if tapRequested && t != nil {
			t.AutoPlan()
		}

		if jsonRequested {
			b, err := json.Marshal(results)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error marshaling JSON result: %s", err)
				os.Exit(2)
			}

			fmt.Println(string(b))
		}

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
	RootCmd.PersistentFlags().StringVarP(&certFile, "client-cert", "c", "", "Read client cert from file")
	RootCmd.PersistentFlags().StringVarP(&keyFile, "client-key", "k", "", "Read client key from file")
	RootCmd.PersistentFlags().StringVarP(&inputFile, "input-file", "i", "", "Read cert specs from file")
	RootCmd.PersistentFlags().IntVarP(&numWorkers, "num-workers", "n", 1, "Parallel verification workers")
	RootCmd.PersistentFlags().IntVarP(&minDays, "min-days", "m", 15, "Minimum days left")
	RootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Suppress passing cert spec listing on success")
	RootCmd.PersistentFlags().StringVarP(&rootFile, "root-certs", "r", "", "Provide specific root certs for validation")
	RootCmd.PersistentFlags().BoolVar(&expired, "show-expired", false, "Match expired or close-to-expiry certs")
	RootCmd.PersistentFlags().BoolVarP(&skipVerify, "skip-verify", "s", false, "Skip certificate verification")
	RootCmd.PersistentFlags().BoolVarP(&starttls, "starttls", "S", false, "STARTTLS checking")
	RootCmd.PersistentFlags().BoolVarP(&postgres, "postgres", "P", false, "PostgreSQL checking")
	RootCmd.PersistentFlags().BoolVarP(&tapRequested, "tap", "t", false, "Produce TAP output")
	RootCmd.PersistentFlags().BoolVarP(&jsonRequested, "json", "j", false, "Produce JSON output")

	viper.BindPFlag("tls.skip_verify", RootCmd.PersistentFlags().Lookup("skip-verify"))
	viper.BindPFlag("tls.client_cert_pem", RootCmd.PersistentFlags().Lookup("client-cert"))
	viper.BindPFlag("tls.client_key_pem", RootCmd.PersistentFlags().Lookup("client-key"))
	viper.BindPFlag("tls.root_certs_pem", RootCmd.PersistentFlags().Lookup("root-certs"))

	viper.BindPFlag("check.workers", RootCmd.PersistentFlags().Lookup("num-workers"))
	viper.BindPFlag("check.min_days", RootCmd.PersistentFlags().Lookup("min-days"))

	viper.SetDefault("check.workers", "1")
	viper.SetDefault("check.min_days", "15")

	viper.SetDefault("server.behind_proxy", "false")
	viper.SetDefault("server.bind", "127.0.0.1:1981")
	viper.SetDefault("server.http_idle", "30s")
	viper.SetDefault("server.http_read", "15s")
	viper.SetDefault("server.http_write", "15s")
	viper.SetDefault("server.prefix", "")

	viper.SetDefault("timeout.http_idle", "30s")
	viper.SetDefault("timeout.http_read", "15s")
	viper.SetDefault("timeout.http_write", "15s")
	viper.SetDefault("timeout.idle_conn", "60s")
	viper.SetDefault("timeout.server_request", "60s")
	viper.SetDefault("timeout.smtp_connect", "5s")
	viper.SetDefault("timeout.smtp_ehlo", "10s")
	viper.SetDefault("timeout.smtp_greeting", "10s")
	viper.SetDefault("timeout.smtp_noop", "10s")
	viper.SetDefault("timeout.smtp_quit", "10s")
	viper.SetDefault("timeout.smtp_starttls", "10s")
	viper.SetDefault("timeout.smtp_tls", "10s")
	viper.SetDefault("timeout.tls_handshake", "10s")

	viper.SetDefault("tls.client_cert_pem", "")
	viper.SetDefault("tls.client_key_pem", "")
	viper.SetDefault("tls.root_certs_pem", "")
	viper.SetDefault("tls.skip_verify", "true")
}
