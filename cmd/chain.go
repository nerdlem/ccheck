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

	"github.com/spf13/cobra"
)

// chainOutput produces the chain format output to STDERR
func chainOutput(c <-chan CertResult) {
	for r := range c {
		if r.ErrString != "" {
			fmt.Printf("- spec %s %s\n", r.Spec, r.ErrString)
			wg.Done()
			continue
		}

		if r.Result.VerifiedChains == nil {
			fmt.Printf("- spec %s has nil verified chain\n", r.Spec)
			wg.Done()
			continue
		}

		fmt.Printf("* spec %s\n", r.Spec)

		if r.Result.TLSVersion != "" {
			fmt.Printf("  TLS version: %s\n", r.Result.TLSVersion)
		}

		if r.Result.CipherSuite != "" {
			fmt.Printf("  Cipher suite: %s\n", r.Result.CipherSuite)
		}

		for i, ch := range *r.Result.VerifiedChains {
			fmt.Printf("  [chain %d]\n", i)
			for j, ce := range ch {
				fmt.Printf("    [cert %d.%d]\n", i, j)
				fmt.Printf("      Subject: %s\n", ce.Subject.String())
				fmt.Printf("      Issuer: %s\n", ce.Issuer.String())
				fmt.Printf("      Serial: %s\n", ce.SerialNumber)
				fmt.Printf("      Dates: %s to %s\n", ce.NotBefore, ce.NotAfter)
				fmt.Printf("      Signature Algorithm: %s\n", ce.SignatureAlgorithm.String())
				fmt.Printf("      CA: %t\n", ce.IsCA)
				for _, name := range ce.DNSNames {
					fmt.Printf("        DNS: %s\n", name)
				}
			}
		}

		wg.Done()
	}
}

// chainCmd represents the chain command
var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Dump information about the certificate chain",
	Long: `This command allows dumping the certificate chain as returned via any
of the supported mechanisms — reference to certificate file to
network endpoint specification.`,
	Run: func(cmd *cobra.Command, args []string) {
		setupSpecSlice(args)
		setupRootFile()
		setupClientCertificates()
		setupProtocol()

		cSpec = setupWorkers(chainOutput)

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

	},
}

func init() {
	RootCmd.AddCommand(chainCmd)
}
