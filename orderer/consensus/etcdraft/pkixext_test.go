/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"crypto/x509"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	etcdraftproto "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/stretchr/testify/require"
)

// TestVerifyConfigMetadataExternalTLSChain covers consenters whose TLS chain is SLH-DSA with ML-DSA
// leaves: they are accepted against the TLS CAs of the channel only when those are also given as
// lists, since crypto/x509 cannot verify SLH-DSA signatures.
func TestVerifyConfigMetadataExternalTLSChain(t *testing.T) {
	org, err := pkixexttest.NewTLSPKI("orderer-org", slhdsa.SHA2_128f)
	require.NoError(t, err)
	other, err := pkixexttest.NewTLSPKI("other-org", slhdsa.SHA2_128f)
	require.NoError(t, err)

	consenter := func(p *pkixexttest.TLSPKI, host string) *etcdraftproto.Consenter {
		cert, _, err := p.IssueLeaf(host)
		require.NoError(t, err)
		return &etcdraftproto.Consenter{Host: host, Port: 7050, ClientTlsCert: cert, ServerTlsCert: cert}
	}
	metadata := func(consenters ...*etcdraftproto.Consenter) *etcdraftproto.ConfigMetadata {
		return &etcdraftproto.ConfigMetadata{
			Options: &etcdraftproto.Options{
				TickInterval: "500ms", ElectionTick: 10, HeartbeatTick: 1, MaxInflightBlocks: 5,
			},
			Consenters: consenters,
		}
	}
	cas := tlsCACerts{roots: []*x509.Certificate{org.Root}, intermediates: []*x509.Certificate{org.Intermediate}}
	pools := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	pools.Roots.AddCert(org.Root)
	pools.Intermediates.AddCert(org.Intermediate)
	require.True(t, pkixext.HasExternal(cas.roots))

	good := metadata(consenter(org, "orderer0"), consenter(org, "orderer1"))
	require.NoError(t, verifyConfigMetadata(good, pools, cas))

	err = verifyConfigMetadata(metadata(consenter(org, "orderer0"), consenter(other, "orderer9")), pools, cas)
	require.ErrorContains(t, err, "consenter orderer9:7050 has invalid certificate")

	err = VerifyConfigMetadata(good, pools)
	require.ErrorContains(t, err, "verifying tls client cert")
}
