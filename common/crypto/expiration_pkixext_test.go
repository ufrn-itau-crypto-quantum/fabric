/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/require"
)

// TestCertificatesWithSamePublicKeyExternal compares leaves whose keys crypto/x509 does not parse,
// as etcdraft does to find its own TLS certificate among the consenters.
func TestCertificatesWithSamePublicKeyExternal(t *testing.T) {
	alg, err := composite.AlgorithmByOID(composite.OIDMLDSA44ECDSAP256SHA256)
	require.NoError(t, err)
	generators := map[string]func() (crypto.Signer, error){
		"SLH-DSA":   func() (crypto.Signer, error) { return slhdsa.GenerateKey(slhdsa.SHA2_128f) },
		"composite": func() (crypto.Signer, error) { return composite.GenerateKey(alg) },
	}
	for name, generate := range generators {
		t.Run(name, func(t *testing.T) {
			pki, err := pkixexttest.NewTLSPKI("org1", slhdsa.SHA2_128f)
			require.NoError(t, err)
			key, err := generate()
			require.NoError(t, err)
			other, err := generate()
			require.NoError(t, err)
			cert1, err := pki.IssueLeafFor("orderer0", key.Public())
			require.NoError(t, err)
			cert2, err := pki.IssueLeafFor("orderer0", key.Public())
			require.NoError(t, err)
			cert3, err := pki.IssueLeafFor("orderer1", other.Public())
			require.NoError(t, err)
			require.NotEqual(t, cert1.Raw, cert2.Raw)
			require.NoError(t, CertificatesWithSamePublicKey(cert1.Raw, cert2.Raw))
			require.ErrorIs(t, CertificatesWithSamePublicKey(cert1.Raw, cert3.Raw), ErrPubKeyMismatch)
		})
	}
}
