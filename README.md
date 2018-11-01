[![GoDoc](https://godoc.org/github.com/nerdlem/tlsa?status.svg)](https://godoc.org/github.com/nerdlem/ccheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/nerdlem/ccheck)](https://goreportcard.com/report/github.com/nerdlem/ccheck)
[![Build Status](https://travis-ci.org/nerdlem/ccheck.svg?branch=master)](https://travis-ci.org/nerdlem/ccheck)

# ccheck, simple X509 certificate checker with TAP output

This tool simplifies handling of PEM certificates. It allows for easy filtering of certificates based on the days until expiration. It's use is reminiscent of the `grep` utility.

It can produce [Test Anything Protocol](http://testanything.org/) which makes this tool useful as part of test suites that deal with TLS certificate expiration.

## Examples

Errors are sent to `STDERR`, the listing of certificates that satisfy the given criteria is sent to `STDOUT` but can be suppressed by using `--quiet` in the command line. TAP output is triggered by the `--tap` command line option.

### TAP — Test Anything Protocol — support

TAP-formatted test results provide output that can be captured by more elaborate test suites:

```
$ ccheck --input-file certificate.list --tap --num-workers 6
1..0
not ok 1 - losmunoz.com:443 x509: certificate is valid for *.athena.pics, athena.pics, not losmunoz.com
ok 2 - lem.click:443 expires in 37 days (took 0.350 secs)
ok 3 - lem.link:443 expires in 37 days (took 0.350 secs)
ok 4 - quad.click:443 expires in 37 days (took 0.351 secs)
ok 5 - libertad.link:443 expires in 31 days (took 0.351 secs)
ok 6 - esmtp.email:443 expires in 30 days (took 0.351 secs)
ok 7 - google.com:443 expires in 67 days (took 0.053 secs)
ok 8 - cert/google-chain.pem expires in 46 days (took 0.000 secs)
ok 9 - allaboutworms.com:443 expires in 69 days (took 0.186 secs)
ok 10 - outlook.com:443 expires in 638 days (took 0.152 secs)
ok 11 - isipp.com:443 expires in 69 days (took 0.186 secs)
ok 12 - suretymail.com:443 expires in 69 days (took 0.187 secs)
ok 13 - tupsiquiatra.expert:443 expires in 31 days (took 0.244 secs)
```

### Custom certificate expiration check

Check whether a given certificate will expire _soon_, or within 10,000 days as in this example. Also whether the certificate is valid for the DNS name provided, is applicable:

```
$ ccheck --min-days 10000 google.com:443 || echo The end is near
google.com:443: expires in 1160 days
The end is near
```

Specifying 0 days with `--min-days` disables the expiration checking.

### Certificate validation

By default, `ccheck` verifies that the certificate is valid for the domain name being used for testing. This can be disabled with the `--skip-verify` option:

```
$ go run main.go losmunoz.com:443 || echo failed
losmunoz.com:443: x509: certificate is valid for *.athena.pics, athena.pics, not losmunoz.com
exit status 2
failed

$ go run main.go --skip-verify losmunoz.com:443 || echo failed
losmunoz.com:443
```

### Custom client certificate, custom Root CA processing

The `--client-cert` and `--client-key` allows for the specification of a custom client certificate pair.

```
$ ccheck --tap my.server:9990
1..0
not ok 1 - my.server:9990 remote error: tls: handshake failure
exit status 2

$ ccheck --tap --client-cert client.crt --client-key client.pem my.server:9990
1..0
ok 1 - my.server:9990 expires in 117 days (took 0.059 secs)
```

`--root-certs` allows for specifying custom root CA certificates for validation of the received server certificate.

```
$ ccheck --tap --root-certs my-custom-CA.crt www.google.com:443
1..0
not ok 1 - www.google.com:443 x509: certificate signed by unknown authority
exit status 2
```

### Certificates in local PEM files

Certificates can also be placed in local files:

```
$ ccheck ./cert/google-chain.pem && echo all is fine
./cert/google-chain.pem
all is fine
```

### Specify list of certificates to check via a file

To ease testing, a list of certificate specs can be placed on a file:

```
$ ccheck --input-file certificate.list
lem.click:443
lem.link:443
losmunoz.com:443: x509: certificate is valid for *.athena.pics, athena.pics, not losmunoz.com
quad.click:443
esmtp.email:443
libertad.link:443
allaboutworms.com:443
google.com:443
isipp.com:443
outlook.com:443
suretymail.com:443
tupsiquiatra.expert:443
cert/google-chain.pem
```

### Parallel checks for faster processing

Checks can be made in parallel, using the `--num-workers` command line option. See the difference.

```
$ time ccheck -i certificate.list > /dev/null

real	0m2.348s
user	0m0.092s
sys	0m0.029s

$ time ccheck -i certificate.list --num-workers 6 > /dev/null

real	0m0.595s
user	0m0.092s
sys	0m0.026s
```
