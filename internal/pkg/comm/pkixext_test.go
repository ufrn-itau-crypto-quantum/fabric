/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm_test

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext/pkixexttest"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/comm/testpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// newExtTLSPKI returns the TLS CA of org: an SLH-DSA root and intermediate issuing ML-DSA-44 leaves.
func newExtTLSPKI(t *testing.T, org string) extTLSPKI {
	t.Helper()
	p, err := pkixexttest.NewTLSPKI(org, slhdsa.SHA2_128f)
	require.NoError(t, err)
	return extTLSPKI{p}
}

type extTLSPKI struct{ *pkixexttest.TLSPKI }

func (p extTLSPKI) anchors() [][]byte {
	return [][]byte{p.AnchorsPEM()}
}

func (p extTLSPKI) leaf(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM, err := p.IssueLeaf(host)
	require.NoError(t, err)
	return certPEM, keyPEM
}

func startExtServer(t *testing.T, secOpts comm.SecureOptions) (*comm.GRPCServer, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := comm.NewGRPCServerFromListener(lis, comm.ServerConfig{SecOpts: secOpts})
	require.NoError(t, err)
	testpb.RegisterEchoServiceServer(srv.Server(), &echoServer{})
	go srv.Start()
	t.Cleanup(srv.Stop)
	_, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)
	return srv, net.JoinHostPort("localhost", port)
}

func echo(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := testpb.NewEchoServiceClient(conn).EchoCall(ctx, &testpb.Echo{Payload: []byte("ping")})
	return err
}

func dialExt(t *testing.T, address string, secOpts comm.SecureOptions) error {
	t.Helper()
	conn, err := comm.ClientConfig{SecOpts: secOpts, DialTimeout: 5 * time.Second, AsyncConnect: true}.Dial(address)
	if err != nil {
		return err
	}
	defer conn.Close()
	return echo(conn)
}

func TestExternalTLSChain(t *testing.T) {
	org1 := newExtTLSPKI(t, "org1")
	org2 := newExtTLSPKI(t, "org2")
	serverCert, serverKey := org1.leaf(t, "localhost")
	clientCert, clientKey := org1.leaf(t, "peer0.org1")
	strangerCert, strangerKey := org2.leaf(t, "peer0.org2")

	srv, address := startExtServer(t, comm.SecureOptions{
		UseTLS: true, RequireClientCert: true,
		Certificate: serverCert, Key: serverKey,
		ClientRootCAs: org1.anchors(),
	})
	require.True(t, srv.MutualTLSRequired())
	client := func(cert, key []byte, roots [][]byte) comm.SecureOptions {
		return comm.SecureOptions{UseTLS: true, RequireClientCert: cert != nil, Certificate: cert, Key: key, ServerRootCAs: roots}
	}

	t.Run("mutual TLS", func(t *testing.T) {
		require.NoError(t, dialExt(t, address, client(clientCert, clientKey, org1.anchors())))
	})
	t.Run("client without certificate", func(t *testing.T) {
		require.Error(t, dialExt(t, address, client(nil, nil, org1.anchors())))
	})
	t.Run("client of another PKI", func(t *testing.T) {
		require.Error(t, dialExt(t, address, client(strangerCert, strangerKey, org1.anchors())))
	})
	t.Run("server of another PKI", func(t *testing.T) {
		err := dialExt(t, address, client(clientCert, clientKey, org2.anchors()))
		require.ErrorContains(t, err, "unknown authority")
	})
	t.Run("server addressed by IP", func(t *testing.T) {
		ipAddress := strings.Replace(address, "localhost", "127.0.0.1", 1)
		require.NoError(t, dialExt(t, ipAddress, client(clientCert, clientKey, org1.anchors())))
	})
	t.Run("server name mismatch", func(t *testing.T) {
		opts := client(clientCert, clientKey, org1.anchors())
		opts.ServerNameOverride = "orderer.org1"
		require.ErrorContains(t, dialExt(t, address, opts), "orderer.org1")
	})
	t.Run("client roots replaced by the channel", func(t *testing.T) {
		require.NoError(t, srv.SetClientRootCAs(org2.anchors()))
		require.Error(t, dialExt(t, address, client(clientCert, clientKey, org1.anchors())))
		require.NoError(t, dialExt(t, address, client(strangerCert, strangerKey, org1.anchors())))
		require.NoError(t, srv.SetClientRootCAs(append(org1.anchors(), org2.anchors()...)))
		require.NoError(t, dialExt(t, address, client(clientCert, clientKey, org1.anchors())))
	})
}

func TestExternalTLSChainPeerCredentials(t *testing.T) {
	org1 := newExtTLSPKI(t, "org1")
	serverCert, serverKey := org1.leaf(t, "localhost")
	clientCert, clientKey := org1.leaf(t, "peer0.org1")
	_, address := startExtServer(t, comm.SecureOptions{
		UseTLS: true, RequireClientCert: true,
		Certificate: serverCert, Key: serverKey,
		ClientRootCAs: org1.anchors(),
	})

	cs := comm.NewCredentialSupport(org1.anchors()...)
	pair, err := tls.X509KeyPair(clientCert, clientKey)
	require.NoError(t, err)
	cs.SetClientCertificate(pair)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(cs.GetPeerCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, echo(conn))

	unknown := comm.NewCredentialSupport(newExtTLSPKI(t, "org2").anchors()...)
	unknown.SetClientCertificate(pair)
	conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(unknown.GetPeerCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	err = echo(conn)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "unknown authority"), err.Error())
}
