//go:build tlsext

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm_test

import (
	"crypto"
	"encoding/pem"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/stretchr/testify/require"
)

// slhdsaLeaf returns the PEM certificate and PKCS #8 key of an SLH-DSA-SHA2-128f leaf for host.
func (p extTLSPKI) slhdsaLeaf(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	require.NoError(t, err)
	cert, err := p.IssueLeafFor(host, key.Public())
	require.NoError(t, err)
	keyDER, err := slhdsa.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pkixexttest.PEM(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// TestSLHDSATLSLeaf runs gRPC with mutual TLS whose leaves are SLH-DSA on both sides, the default
// of phase 10, which needs the go-tlsext toolchain and the tlsext tag.
func TestSLHDSATLSLeaf(t *testing.T) {
	require.Contains(t, pkixext.TLSSchemesLog(), "SLH-DSA-SHA2-128f(0x0912)")
	org1 := newExtTLSPKI(t, "org1")
	serverCert, serverKey := org1.slhdsaLeaf(t, "localhost")
	clientCert, clientKey := org1.slhdsaLeaf(t, "peer0.org1")

	srv, address := startExtServer(t, comm.SecureOptions{
		UseTLS: true, RequireClientCert: true,
		Certificate: serverCert, Key: serverKey,
		ClientRootCAs: org1.anchors(),
	})
	require.True(t, srv.MutualTLSRequired())
	client := comm.SecureOptions{UseTLS: true, RequireClientCert: true, Certificate: clientCert, Key: clientKey, ServerRootCAs: org1.anchors()}
	require.NoError(t, dialExt(t, address, client))

	client.ServerRootCAs = newExtTLSPKI(t, "org2").anchors()
	require.ErrorContains(t, dialExt(t, address, client), "unknown authority")
}

// compositeLeaf returns the PEM certificate and PKCS #8 key of a leaf of the composite pair alg
// for host.
func (p extTLSPKI) compositeLeaf(t *testing.T, host string, alg composite.Algorithm) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := composite.GenerateKey(alg)
	require.NoError(t, err)
	cert, err := p.IssueLeafFor(host, key.Public())
	require.NoError(t, err)
	keyDER, err := composite.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pkixexttest.PEM(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// TestCompositeTLSLeaf runs gRPC with mutual TLS over a composite chain with composite leaves, so
// that both CertificateVerify messages are composite.
func TestCompositeTLSLeaf(t *testing.T) {
	alg, err := composite.AlgorithmByOID(composite.OIDMLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	require.Contains(t, pkixext.TLSSchemesLog(), "mldsa44_ecdsa_p256_sha256(0xfe40)")
	newPKI := func(org string) extTLSPKI {
		p, err := pkixexttest.NewTLSPKIWith(org, func() (crypto.Signer, error) { return composite.GenerateKey(alg) })
		require.NoError(t, err)
		return extTLSPKI{p}
	}
	org1 := newPKI("org1")
	serverCert, serverKey := org1.compositeLeaf(t, "localhost", alg)
	clientCert, clientKey := org1.compositeLeaf(t, "peer0.org1", alg)

	srv, address := startExtServer(t, comm.SecureOptions{
		UseTLS: true, RequireClientCert: true,
		Certificate: serverCert, Key: serverKey,
		ClientRootCAs: org1.anchors(),
	})
	require.True(t, srv.MutualTLSRequired())
	client := comm.SecureOptions{UseTLS: true, RequireClientCert: true, Certificate: clientCert, Key: clientKey, ServerRootCAs: org1.anchors()}
	require.NoError(t, dialExt(t, address, client))

	client.ServerRootCAs = newPKI("org2").anchors()
	require.ErrorContains(t, dialExt(t, address, client), "unknown authority")
}
