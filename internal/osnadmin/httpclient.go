/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package osnadmin

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
)

// httpClient returns a client that trusts caCerts, or the system roots when caCerts is empty. When
// a CA needs pkixext, each connection verifies the orderer with pkixext.ClientConfigFor.
func httpClient(caCerts []*x509.Certificate, tlsClientCert tls.Certificate, timeShift time.Duration) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsClientCert},
	}
	if len(caCerts) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		for _, cert := range caCerts {
			tlsConfig.RootCAs.AddCert(cert)
		}
	}

	if timeShift > 0 {
		tlsConfig.Time = func() time.Time {
			return time.Now().Add((-1) * timeShift)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if pkixext.HasExternal(caCerts) {
		transport.DialTLSContext = pkixext.DialTLSContext(tlsConfig, caCerts)
	}
	return &http.Client{
		Transport: transport,
	}
}

func httpDo(req *http.Request, caCerts []*x509.Certificate, tlsClientCert tls.Certificate) (*http.Response, error) {
	return httpDoTimeShift(req, caCerts, tlsClientCert, 0)
}

func httpDoTimeShift(req *http.Request, caCerts []*x509.Certificate, tlsClientCert tls.Certificate, timeShift time.Duration) (*http.Response, error) {
	client := httpClient(caCerts, tlsClientCert, timeShift)
	return client.Do(req)
}

func httpGet(url string, caCerts []*x509.Certificate, tlsClientCert tls.Certificate) (*http.Response, error) {
	return httpGetTimeShift(url, caCerts, tlsClientCert, 0)
}

func httpGetTimeShift(url string, caCerts []*x509.Certificate, tlsClientCert tls.Certificate, timeShift time.Duration) (*http.Response, error) {
	client := httpClient(caCerts, tlsClientCert, timeShift)
	return client.Get(url)
}
