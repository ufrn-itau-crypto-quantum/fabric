/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixext

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"slices"
	"time"

	"github.com/pkg/errors"
)

// X509KeyPair is tls.X509KeyPair that also accepts a PKCS #8 key of a registered scheme, which
// crypto/x509 does not parse. Every CERTIFICATE block of certPEM goes into the chain, leaf first,
// and the key must match the public key of the leaf.
func X509KeyPair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err == nil {
		return pair, nil
	}
	var block *pem.Block
	for rest := keyPEM; ; {
		block, rest = pem.Decode(rest)
		if block == nil {
			return tls.Certificate{}, err
		}
		if block.Type == "PRIVATE KEY" {
			break
		}
	}
	key, extErr := ParsePKCS8PrivateKey(block.Bytes)
	if extErr != nil {
		return tls.Certificate{}, err
	}
	certs, certErr := ParseCertificatesPEM(certPEM)
	if certErr != nil {
		return tls.Certificate{}, certErr
	}
	if len(certs) == 0 {
		return tls.Certificate{}, errors.New("No certificate in the TLS certificate file")
	}
	spki, mErr := MarshalPKIXPublicKey(key.Public())
	if mErr != nil {
		return tls.Certificate{}, mErr
	}
	if !bytes.Equal(spki, certs[0].RawSubjectPublicKeyInfo) {
		return tls.Certificate{}, errors.New("Private key does not match the public key of the TLS certificate")
	}
	pair = tls.Certificate{PrivateKey: key, Leaf: certs[0]}
	for _, cert := range certs {
		pair.Certificate = append(pair.Certificate, cert.Raw)
	}
	return pair, nil
}

// LoadX509KeyPair is X509KeyPair over files.
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return X509KeyPair(certPEM, keyPEM)
}

// TLSVerifyOptions are the options of VerifyTLSPeer. KeyUsage is the role the peer certificate must
// allow: ServerAuth when verifying a server, ClientAuth when verifying a client.
type TLSVerifyOptions struct {
	Roots         []*x509.Certificate
	Intermediates []*x509.Certificate
	DNSName       string
	KeyUsage      x509.ExtKeyUsage
	CurrentTime   time.Time
}

// VerifyTLSPeer verifies the certificate list received in a TLS handshake, leaf first, and returns
// the verified chains. The certificates after the leaf are added to opts.Intermediates, and the
// leaf chain is verified with VerifyChain, so any link may be signed with a registered scheme. When
// DNSName is set, the leaf must also match it as in x509.Certificate.VerifyHostname.
func VerifyTLSPeer(rawCerts [][]byte, opts TLSVerifyOptions) ([][]*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("Peer presented no certificate")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to parse the peer certificate")
		}
		certs[i] = cert
	}
	chains, err := VerifyChain(certs[0], VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: append(slices.Clone(opts.Intermediates), certs[1:]...),
		CurrentTime:   opts.CurrentTime,
		KeyUsages:     []x509.ExtKeyUsage{opts.KeyUsage},
	})
	if err != nil {
		return nil, err
	}
	if opts.DNSName != "" {
		if err := certs[0].VerifyHostname(opts.DNSName); err != nil {
			return nil, err
		}
	}
	return chains, nil
}

// HasExternal reports whether any of certs has a key of a registered scheme or is signed with one,
// which is when crypto/x509 cannot verify chains through it.
func HasExternal(certs []*x509.Certificate) bool {
	return slices.ContainsFunc(certs, func(cert *x509.Certificate) bool {
		return IsSignedWithExternal(cert) || IsExternalPublicKey(cert.RawSubjectPublicKeyInfo)
	})
}

// ParseCertificatesPEM returns every CERTIFICATE block of the PEM inputs, in order.
func ParseCertificatesPEM(pemCerts ...[]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rest := range pemCerts {
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.WithMessage(err, "Failed to parse a trusted certificate")
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// ConfigureClientVerification makes cfg verify the server with VerifyTLSPeer against roots instead
// of crypto/x509. Roots and intermediates both go in roots, as anchors.
//
// The verification runs in VerifyConnection, with InsecureSkipVerify set, and checks the hostname
// against the SNI of the connection or, when there is none, against cfg.ServerName; a connection to
// an IP address therefore needs cfg.ServerName, which ClientConfigFor sets. The VerifyPeerCertificate and VerifyConnection
// already in cfg run afterwards, the former with the verified chains. The callbacks survive Clone,
// so the configuration may be cloned per connection.
func ConfigureClientVerification(cfg *tls.Config, roots []*x509.Certificate) {
	roots = slices.Clone(roots)
	serverName := cfg.ServerName
	now := cfg.Time
	verifyPeer := cfg.VerifyPeerCertificate
	verifyConnection := cfg.VerifyConnection

	cfg.InsecureSkipVerify = true
	cfg.RootCAs = nil
	cfg.VerifyPeerCertificate = nil
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		name := cs.ServerName
		if name == "" {
			name = serverName
		}
		if name == "" {
			return errors.New("A server name is required to verify a server certificate")
		}
		rawCerts := make([][]byte, len(cs.PeerCertificates))
		for i, cert := range cs.PeerCertificates {
			rawCerts[i] = cert.Raw
		}
		opts := TLSVerifyOptions{Roots: roots, DNSName: name, KeyUsage: x509.ExtKeyUsageServerAuth}
		if now != nil {
			opts.CurrentTime = now()
		}
		chains, err := VerifyTLSPeer(rawCerts, opts)
		if err != nil {
			return errors.WithMessage(err, "Failed to verify the server certificate")
		}
		if verifyPeer != nil {
			if err := verifyPeer(rawCerts, chains); err != nil {
				return err
			}
		}
		if verifyConnection != nil {
			return verifyConnection(cs)
		}
		return nil
	}
}

// ClientConfigFor returns a copy of cfg for one connection to addr, a host or host:port, configured
// by ConfigureClientVerification. When cfg has no ServerName, the host of addr becomes it, so a
// connection to an IP address is checked against the IP addresses of the certificate.
func ClientConfigFor(cfg *tls.Config, roots []*x509.Certificate, addr string) *tls.Config {
	conn := cfg.Clone()
	if conn.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		conn.ServerName = host
	}
	ConfigureClientVerification(conn, roots)
	return conn
}

// DialTLSContext returns a function for http.Transport.DialTLSContext that opens each connection
// with ClientConfigFor(cfg, roots, addr).
func DialTLSContext(cfg *tls.Config, roots []*x509.Certificate) func(ctx context.Context, network, addr string) (net.Conn, error) {
	roots = slices.Clone(roots)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{Config: ClientConfigFor(cfg, roots, addr)}
		return dialer.DialContext(ctx, network, addr)
	}
}

// ConfigureServerVerification makes cfg verify client certificates with VerifyTLSPeer against roots
// instead of crypto/x509. RequireAndVerifyClientCert becomes RequireAnyClientCert and
// VerifyClientCertIfGiven becomes RequestClientCert, with the verification moved to
// VerifyPeerCertificate; the VerifyPeerCertificate already in cfg runs afterwards with the verified
// chains. The other ClientAuth values verify nothing and are left unchanged.
//
// A connection state of such a server has no VerifiedChains: every certificate in PeerCertificates
// was verified during the handshake.
func ConfigureServerVerification(cfg *tls.Config, roots []*x509.Certificate) {
	switch cfg.ClientAuth {
	case tls.RequireAndVerifyClientCert:
		cfg.ClientAuth = tls.RequireAnyClientCert
	case tls.VerifyClientCertIfGiven:
		cfg.ClientAuth = tls.RequestClientCert
	default:
		return
	}
	roots = slices.Clone(roots)
	now := cfg.Time
	verifyPeer := cfg.VerifyPeerCertificate

	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		opts := TLSVerifyOptions{Roots: roots, KeyUsage: x509.ExtKeyUsageClientAuth}
		if now != nil {
			opts.CurrentTime = now()
		}
		chains, err := VerifyTLSPeer(rawCerts, opts)
		if err != nil {
			return errors.WithMessage(err, "Failed to verify the client certificate")
		}
		if verifyPeer != nil {
			return verifyPeer(rawCerts, chains)
		}
		return nil
	}
}
