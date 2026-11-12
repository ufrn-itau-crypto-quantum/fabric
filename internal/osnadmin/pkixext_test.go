/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package osnadmin_test

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/hyperledger/fabric/common/fabhttp"
	"github.com/hyperledger/fabric/internal/osnadmin"
	"github.com/stretchr/testify/require"
)

// TestJoinWithExternalTLSChain runs a channel join against an orderer admin endpoint whose TLS PKI is
// SLH-DSA with ML-DSA leaves, as with an SLH-DSA identity. The orderer is addressed by IP, as the
// runner does.
func TestJoinWithExternalTLSChain(t *testing.T) {
	org, err := pkixexttest.NewTLSPKI("orderer-org", slhdsa.SHA2_128f)
	require.NoError(t, err)
	other, err := pkixexttest.NewTLSPKI("other-org", slhdsa.SHA2_128f)
	require.NoError(t, err)

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	serverCert, serverKey, err := org.IssueLeaf("orderer0")
	require.NoError(t, err)
	tlsOpts := fabhttp.TLS{
		Enabled:            true,
		CertFile:           write("server.crt", serverCert),
		KeyFile:            write("server.key", serverKey),
		ClientCertRequired: true,
		ClientCACertFiles:  []string{write("ca.pem", org.AnchorsPEM())},
	}
	require.True(t, tlsOpts.ExternalClientVerification())

	server := fabhttp.NewServer(fabhttp.Options{ListenAddress: "127.0.0.1:0", TLS: tlsOpts})
	server.RegisterHandler("/participation/v1/channels", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}), true)
	require.NoError(t, server.Start())
	defer server.Stop()
	url := "https://" + server.Addr()

	anchors, err := pkixext.ParseCertificatesPEM(org.AnchorsPEM())
	require.NoError(t, err)
	clientPair := func(p *pkixexttest.TLSPKI) tls.Certificate {
		certPEM, keyPEM, err := p.IssueLeaf("admin")
		require.NoError(t, err)
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		return pair
	}

	resp, err := osnadmin.Join(url, []byte("block"), anchors, clientPair(org))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	_, err = osnadmin.Join(url, []byte("block"), anchors, clientPair(other))
	require.Error(t, err, "a client of another PKI must be refused in the handshake")

	otherAnchors, err := pkixext.ParseCertificatesPEM(other.AnchorsPEM())
	require.NoError(t, err)
	_, err = osnadmin.Join(url, []byte("block"), otherAnchors, clientPair(org))
	require.ErrorContains(t, err, "unknown authority")
}
