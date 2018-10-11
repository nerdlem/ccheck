[![GoDoc](https://godoc.org/github.com/nerdlem/tlsa?status.svg)](https://godoc.org/github.com/nerdlem/ccheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/nerdlem/ccheck)](https://goreportcard.com/report/github.com/nerdlem/ccheck)
[![Build Status](https://travis-ci.org/nerdlem/ccheck.svg?branch=master)](https://travis-ci.org/nerdlem/ccheck)

# ccheck, simple X509 certificate checker

This tool simplifies handling of PEM certificates. It allows for easy filtering of certificates based on the days until expiration. It's use is reminiscent of the `grep` utility.

Check whether a given certificate will expire _soon_, or within 10,000 days as in this example. Also whether the certificate is valid for the DNS name provided, is applicable:

```
$ ccheck --min-days 10000 google.com:443 || echo The end is near
google.com:443: expires in 1160 days
The end is near
```

Certificates can also be placed in local files:

```
$ ccheck ./cert/google-chain.pem && echo all is fine
./cert/google-chain.pem
all is fine
```

Errors are sent to `STDERR`, the listing of certificates that satisfy the given criteria is sent to `STDOUT` but can be suppressed by using `--quiet` in the command line.

Specifying 0 days with `min-days` disables the expiration checking.
