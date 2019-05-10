// © 2015-2019 Luis E. Muñoz. All rights reserved.
// This file is part of lem.click/mtaststool.

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
	res := make([]CertResult, len(domains))
	var wg sync.WaitGroup

	for _, d := range domains {
		wg.Add(1)
		cSpec <- Spec{Value: d, Accumulator: &res, WG: &wg}
	}

	wg.Wait()

	_ = wantJSON
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

		loggedRouter := handlers.LoggingHandler(os.Stdout, r)

		srv := &http.Server{
			Addr:         viper.GetString("server.bind"),
			Handler:      loggedRouter,
			IdleTimeout:  viper.GetDuration("server.http_idle"),
			ReadTimeout:  viper.GetDuration("server.http_read"),
			WriteTimeout: viper.GetDuration("server.http_write"),
		}

		cSpec = setupWorkers()

		log.Fatal(srv.ListenAndServe())
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVar(&cfgFile, "config", "", "config file (default is /etc/ccheck.toml)")

	serverCmd.Flags().StringVar(&serverBind, "bind", "127.0.0.1:1980", "where the server will be listening")
	viper.BindPFlag("server.bind", serverCmd.Flags().Lookup("bind"))

	serverCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for HTTP requests")
	viper.BindPFlag("server.prefix", serverCmd.Flags().Lookup("prefix"))
}
