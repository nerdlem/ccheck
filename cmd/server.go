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
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/nerdlem/ccheck/cert"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile, prefix, serverBind string

type errMessage struct {
	Error string `json:"error"`
}

func handleTLS(w http.ResponseWriter, r *http.Request) {
	var wantJSON bool
	protocol := cert.PSOCKET
	vars := mux.Vars(r)

	accept := strings.ToLower((r.Header.Get("Accept")))

	switch accept {
	case "*/*", "application/json":
		w.Header().Add("Content-Type", "application/json")
		wantJSON = true
	case "application/text", "text/plain":
		w.Header().Add("Content-Type", accept)
		wantJSON = false
	default:
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		payload, _ := json.Marshal(errMessage{
			Error: "only Content-Type application/json or application/text are supported",
		})
		fmt.Fprintf(w, "%s\n\n", string(payload))
		return
	}

	switch vars["protocol"] {
	case "postgres":
		protocol = cert.PPG
	case "plain":
		protocol = cert.PSOCKET
	case "starttls":
		protocol = cert.PSTARTTLS
	default:
		msg := fmt.Sprintf("unsupported protocol %s", vars["protocol"])
		if wantJSON {
			w.Header().Add("Content-Type", accept)
			w.WriteHeader(http.StatusBadRequest)
			payload, _ := json.Marshal(errMessage{
				Error: msg,
			})
			fmt.Fprintf(w, "%s\n\n", string(payload))
			return
		}

		w.Header().Add("Content-Type", accept)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%s\n\n", msg)
		return
	}

	domains := strings.Split(vars["speclist"], ",")
	res := []CertResult{}
	var wg sync.WaitGroup

	for _, d := range domains {
		wg.Add(1)
		cSpec <- Spec{
			Accumulator: &res,
			Protocol:    protocol,
			Value:       d,
			WG:          &wg,
		}
	}

	wg.Wait()

	_ = protocol
	w.WriteHeader(http.StatusOK)

	if wantJSON {
		payload, _ := json.Marshal(res)
		fmt.Fprintf(w, "%s\n\n", string(payload))
		return
	}

	fmt.Fprintf(w, "%s\n\n", "null")
}

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "TLS Certificate Checking Server",
	Long:  `Connects to the specified TLS endpoint and validates the certificates.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		r := mux.NewRouter()
		r.HandleFunc(fmt.Sprintf("%s/{protocol}/{speclist}",
			viper.GetString("server.prefix")),
			handleTLS).Methods("GET")

		var h http.Handler

		if viper.GetBool("server.behind_proxy") {
			fmt.Fprintln(os.Stderr, "Running in behind-proxy mode")
			h = handlers.ProxyHeaders(r)
		} else {
			h = r
		}

		contentType := handlers.ContentTypeHandler(h, "application/json", "text/plain")
		loggedRouter := handlers.LoggingHandler(os.Stderr, contentType)

		srv := &http.Server{
			Addr:         viper.GetString("server.bind"),
			Handler:      loggedRouter,
			IdleTimeout:  viper.GetDuration("server.http_idle"),
			ReadTimeout:  viper.GetDuration("server.http_read"),
			WriteTimeout: viper.GetDuration("server.http_write"),
		}

		cSpec = setupWorkers(jsonCollector)

		log.Fatal(srv.ListenAndServe())
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVar(&cfgFile, "config", "", "config file (default is /etc/ccheck.toml)")

	serverCmd.Flags().BoolVarP(&behindProxy, "behind-proxy", "B", false, "whether operating behind a proxy")
	viper.BindPFlag("server.behind_proxy", serverCmd.Flags().Lookup("behind-proxy"))

	serverCmd.Flags().StringVar(&serverBind, "bind", "127.0.0.1:1980", "where the server will be listening")
	viper.BindPFlag("server.bind", serverCmd.Flags().Lookup("bind"))

	serverCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for HTTP requests")
	viper.BindPFlag("server.prefix", serverCmd.Flags().Lookup("prefix"))
}
