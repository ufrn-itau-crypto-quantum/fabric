/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabhttp

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric/internal/pkg/comm"
)

type TLS struct {
	Enabled            bool
	CertFile           string
	KeyFile            string
	ClientCertRequired bool
	ClientCACertFiles  []string
	TimeShift          time.Duration
}

// Config returns the server TLS configuration, or nil when TLS is disabled. When a client CA needs
// pkixext, client certificates are verified by pkixext.ConfigureServerVerification and connection
// states carry no VerifiedChains; ExternalClientVerification reports that case.
func (t TLS) Config() (*tls.Config, error) {
	var tlsConfig *tls.Config

	if t.Enabled {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caPEMs, err := t.clientCAPEMs()
		if err != nil {
			return nil, err
		}
		for _, caPem := range caPEMs {
			caCertPool.AppendCertsFromPEM(caPem)
		}
		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			CipherSuites: comm.DefaultTLSCipherSuites,
			ClientCAs:    caCertPool,
		}
		if t.TimeShift > 0 {
			tlsConfig.Time = func() time.Time {
				return time.Now().Add((-1) * t.TimeShift)
			}
		}

		if t.ClientCertRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
		if roots, err := pkixext.ParseCertificatesPEM(caPEMs...); err == nil && pkixext.HasExternal(roots) {
			pkixext.ConfigureServerVerification(tlsConfig, roots)
		}
	}

	return tlsConfig, nil
}

func (t TLS) clientCAPEMs() ([][]byte, error) {
	var pems [][]byte
	for _, caPath := range t.ClientCACertFiles {
		caPem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pems = append(pems, caPem)
	}
	return pems, nil
}

// ExternalClientVerification reports whether Config verifies client certificates with pkixext. A
// CA file that cannot be read counts as false.
func (t TLS) ExternalClientVerification() bool {
	if !t.Enabled {
		return false
	}
	pems, err := t.clientCAPEMs()
	if err != nil {
		return false
	}
	roots, err := pkixext.ParseCertificatesPEM(pems...)
	return err == nil && pkixext.HasExternal(roots)
}
