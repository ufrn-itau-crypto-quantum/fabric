/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkixexttest

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
)

var serial atomic.Int64

// TLSPKI is the TLS CA of an organization: a root and an intermediate that issue the leaves, by
// default with ML-DSA-44 keys.
type TLSPKI struct {
	Root, Intermediate *x509.Certificate
	intermediateKey    crypto.Signer
}

func template(name string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: []byte(name),
	}
}

// NewTLSPKI creates the root and intermediate of org with SLH-DSA keys of the parameter set ps, as
// the runner sets them up for an SLH-DSA identity.
func NewTLSPKI(org string, ps slhdsa.ParameterSet) (*TLSPKI, error) {
	return NewTLSPKIWith(org, func() (crypto.Signer, error) { return slhdsa.GenerateKey(ps) })
}

// NewTLSPKIWith creates the root and intermediate of org with keys from generate, of any algorithm
// that crypto/x509 or a registered scheme encodes.
func NewTLSPKIWith(org string, generate func() (crypto.Signer, error)) (*TLSPKI, error) {
	rootKey, err := generate()
	if err != nil {
		return nil, err
	}
	rootTpl := template(org + "-tlsroot")
	rootTpl.IsCA, rootTpl.BasicConstraintsValid, rootTpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
	root, err := CreateCertificate(rootTpl, nil, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	interKey, err := generate()
	if err != nil {
		return nil, err
	}
	interTpl := template(org + "-tlsinter")
	interTpl.IsCA, interTpl.BasicConstraintsValid, interTpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
	inter, err := CreateCertificate(interTpl, root, interKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	return &TLSPKI{Root: root, Intermediate: inter, intermediateKey: interKey}, nil
}

// AnchorsPEM returns the root and the intermediate as one PEM bundle, which is what a peer of the
// organization trusts.
func (p *TLSPKI) AnchorsPEM() []byte {
	return append(PEM(p.Root), PEM(p.Intermediate)...)
}

// IssueLeaf issues an ML-DSA-44 leaf for host, valid for 127.0.0.1 too and for both TLS roles, and
// returns its certificate and PKCS #8 key in PEM.
func (p *TLSPKI) IssueLeaf(host string) (certPEM, keyPEM []byte, err error) {
	return p.IssueLeafWith(host, mldsa.MLDSA44())
}

// IssueLeafWith is IssueLeaf with the ML-DSA parameter set of the leaf.
func (p *TLSPKI) IssueLeafWith(host string, params mldsa.Parameters) (certPEM, keyPEM []byte, err error) {
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, nil, err
	}
	cert, err := p.IssueLeafFor(host, key.Public())
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return PEM(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// IssueLeafFor issues a leaf for host, valid for 127.0.0.1 too and for both TLS roles, with the
// public key pub of any algorithm that crypto/x509 or a registered scheme encodes.
func (p *TLSPKI) IssueLeafFor(host string, pub crypto.PublicKey) (*x509.Certificate, error) {
	tpl := template(host)
	tpl.DNSNames = []string{host}
	tpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	tpl.KeyUsage = x509.KeyUsageDigitalSignature
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	return CreateCertificate(tpl, p.Intermediate, pub, p.intermediateKey)
}

func PEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
