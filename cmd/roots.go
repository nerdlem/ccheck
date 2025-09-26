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
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootListCmd represents the server command
var rootListCmd = &cobra.Command{
	Use:   "roots",
	Short: "Enumerate trusted / known CA Roots",
	Long:  `Provides a list of the known CA Roots used by the current configuration.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		setupRootFile()

		subj := len(rootCertPool.Subjects())

		if rootFile == "" && subj == 0 {
			fmt.Printf("using system root CA certificates\n")
		} else {
			fmt.Printf("%d trusted root CA certificates:\n", subj)
			for i, s := range rootCertPool.Subjects() {

				var rdn pkix.RDNSequence
				if _, err := asn1.Unmarshal(s, &rdn); err != nil {
					panic(err)
				}
				var name pkix.Name
				name.FillFromRDNSequence(&rdn)

				fmt.Printf("  [%d] %s\n", i, name.String())
			}
		}

		os.Exit(0)
	},
}

func init() {
	RootCmd.AddCommand(rootListCmd)
}
