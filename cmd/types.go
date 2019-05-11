package cmd

import (
	"sync"

	"github.com/nerdlem/ccheck/cert"
)

// CertResult holds a processed evaluation of a Spec
type CertResult struct {
	// Spec is the certificate specification evaluated.
	Spec string `json:"spec"`
	// Result is a pointer to the evaluation result
	Result *cert.Result `json:"result"`
	// Err contains any error found during evaluation
	Err error `json:"error"`
	// Timestamp for the result
	Timestamp string `json:"timestamp"`
	// Accumulator points to the array where results should be placed
	Accumulator *[]CertResult `json:"-"`
	// WG is used for synchronization
	WG *sync.WaitGroup `json:"-"`
}

// Spec holds a spec along with the location of a slice where the result of the
// evaluation must be stored.
type Spec struct {
	Value       string        `json:"value"`
	Protocol    cert.Protocol `json:"protocol"`
	Accumulator *[]CertResult `json:"-"`
	// WG is used for synchronization
	WG *sync.WaitGroup `json:"-"`
}

// Consumer is a function that consume CertResult objects via an input channel
type Consumer func(<-chan CertResult)
