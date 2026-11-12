/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"google.golang.org/grpc/credentials"
)

var (
	ErrClientHandshakeNotImplemented = errors.New("core/comm: client handshakes are not implemented with serverCreds")
	ErrServerHandshakeNotImplemented = errors.New("core/comm: server handshakes are not implemented with clientCreds")
	ErrOverrideHostnameNotSupported  = errors.New("core/comm: OverrideServerName is not supported")

	// alpnProtoStr are the specified application level protocols for gRPC.
	alpnProtoStr = []string{"h2"}

	// Logger for TLS client connections
	tlsClientLogger = flogging.MustGetLogger("comm.tls")
)

// NewServerTransportCredentials returns a new initialized
// grpc/credentials.TransportCredentials
func NewServerTransportCredentials(
	serverConfig *TLSConfig,
	logger *flogging.FabricLogger) credentials.TransportCredentials {
	// NOTE: unlike the default grpc/credentials implementation, we do not
	// clone the tls.Config which allows us to update it dynamically
	serverConfig.config.NextProtos = alpnProtoStr
	serverConfig.config.MinVersion = tls.VersionTLS12

	if logger == nil {
		logger = tlsClientLogger
	}

	return &serverCreds{
		serverConfig: serverConfig,
		logger:       logger,
	}
}

// serverCreds is an implementation of grpc/credentials.TransportCredentials.
type serverCreds struct {
	serverConfig *TLSConfig
	logger       *flogging.FabricLogger
}

// TLSConfig is the server TLS configuration, shared by handshakes and updated in place. clientRoots
// lists the certificates of config.ClientCAs, and externalRoots is set when one of them needs
// pkixext to verify client chains.
type TLSConfig struct {
	config        *tls.Config
	lock          sync.RWMutex
	clientRoots   []*x509.Certificate
	externalRoots bool
}

func NewTLSConfig(config *tls.Config) *TLSConfig {
	return &TLSConfig{
		config: config,
	}
}

func (t *TLSConfig) Config() tls.Config {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.config != nil {
		return *t.config.Clone()
	}

	return tls.Config{}
}

// handshakeConfig returns the configuration of one server handshake: a copy of the configuration
// in which, when the client roots need pkixext, client certificates are verified by
// pkixext.ConfigureServerVerification instead of crypto/x509.
func (t *TLSConfig) handshakeConfig() *tls.Config {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.config == nil {
		return &tls.Config{}
	}
	config := t.config.Clone()
	if t.externalRoots {
		pkixext.ConfigureServerVerification(config, t.clientRoots)
	}
	return config
}

func (t *TLSConfig) AddClientRootCA(cert *x509.Certificate) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs.AddCert(cert)
	t.clientRoots = append(t.clientRoots, cert)
	t.externalRoots = pkixext.HasExternal(t.clientRoots)
}

// SetClientCAs replaces the client roots with certPool. Since a pool cannot be listed, client
// certificates are then verified by crypto/x509 only; SetClientRoots keeps pkixext available.
func (t *TLSConfig) SetClientCAs(certPool *x509.CertPool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs = certPool
	t.clientRoots = nil
	t.externalRoots = false
}

// SetClientRoots replaces the client roots with certs.
func (t *TLSConfig) SetClientRoots(certs []*x509.Certificate) {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs = certPool
	t.clientRoots = certs
	t.externalRoots = pkixext.HasExternal(certs)
}

// ClientHandshake is not implemented for `serverCreds`.
func (sc *serverCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrClientHandshakeNotImplemented
}

// ServerHandshake does the authentication handshake for servers.
func (sc *serverCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := tls.Server(rawConn, sc.serverConfig.handshakeConfig())
	l := sc.logger.With("remote address", conn.RemoteAddr().String())
	start := time.Now()
	if err := conn.Handshake(); err != nil {
		l.Errorf("Server TLS handshake failed in %s with error %s", time.Since(start), err)
		return nil, nil, err
	}
	l.Debugf("Server TLS handshake completed in %s", time.Since(start))
	return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
}

// Info provides the ProtocolInfo of this TransportCredentials.
func (sc *serverCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
	}
}

// Clone makes a copy of this TransportCredentials.
func (sc *serverCreds) Clone() credentials.TransportCredentials {
	sc.serverConfig.lock.RLock()
	clientRoots, externalRoots := sc.serverConfig.clientRoots, sc.serverConfig.externalRoots
	sc.serverConfig.lock.RUnlock()
	config := sc.serverConfig.Config()
	serverConfig := NewTLSConfig(&config)
	serverConfig.clientRoots, serverConfig.externalRoots = clientRoots, externalRoots
	return NewServerTransportCredentials(serverConfig, sc.logger)
}

// OverrideServerName overrides the server name used to verify the hostname
// on the returned certificates from the server.
func (sc *serverCreds) OverrideServerName(string) error {
	return ErrOverrideHostnameNotSupported
}

// DynamicClientCredentials are client credentials over a TLS configuration that may change between
// connections. When ExternalRoots is set, each connection verifies the server chain against it with
// pkixext, using the dialed authority as the server name when TLSConfig has none.
type DynamicClientCredentials struct {
	TLSConfig     *tls.Config
	ExternalRoots []*x509.Certificate
}

func (dtc *DynamicClientCredentials) latestConfig() *tls.Config {
	return dtc.TLSConfig.Clone()
}

func (dtc *DynamicClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	l := tlsClientLogger.With("remote address", rawConn.RemoteAddr().String())
	config := dtc.latestConfig()
	if dtc.ExternalRoots != nil {
		config = pkixext.ClientConfigFor(config, dtc.ExternalRoots, authority)
	}
	creds := credentials.NewTLS(config)
	start := time.Now()
	conn, auth, err := creds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		l.Errorf("Client TLS handshake failed after %s with error: %s", time.Since(start), err)
	} else {
		l.Debugf("Client TLS handshake completed in %s", time.Since(start))
	}
	return conn, auth, err
}

func (dtc *DynamicClientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrServerHandshakeNotImplemented
}

func (dtc *DynamicClientCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(dtc.latestConfig()).Info()
}

func (dtc *DynamicClientCredentials) Clone() credentials.TransportCredentials {
	if dtc.ExternalRoots != nil {
		return &DynamicClientCredentials{TLSConfig: dtc.latestConfig(), ExternalRoots: dtc.ExternalRoots}
	}
	return credentials.NewTLS(dtc.latestConfig())
}

func (dtc *DynamicClientCredentials) OverrideServerName(name string) error {
	dtc.TLSConfig.ServerName = name
	return nil
}
