/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// altTestCA is a hybrid issuer: a conventional key backing the SubjectPublicKeyInfo and an
// ML-DSA key carried in the altSubjectPublicKeyInfo extension.
type altTestCA struct {
	cert      *x509.Certificate
	classical crypto.Signer
	alt       *mldsa.PrivateKey
}

func newAltTestCA(t *testing.T, params mldsa.Parameters) *altTestCA {
	t.Helper()
	classical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alt, err := mldsa.GenerateKey(params)
	require.NoError(t, err)

	ca := &altTestCA{classical: classical, alt: alt}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "alt-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca.cert = ca.issue(t, template, classical.Public(), nil)
	return ca
}

// issue signs a certificate carrying the alternative signature of the CA. It goes through
// x509.CreateCertificate twice, because the signature covers a PreTBSCertificate that excludes
// the altSignatureValue extension: the first pass produces exactly those bytes, and the second
// pass adds the extension without disturbing them.
func (ca *altTestCA) issue(t *testing.T, template *x509.Certificate, subjectPub any, parent *altTestCA) *x509.Certificate {
	t.Helper()
	issuerCert := template
	if parent != nil {
		issuerCert = parent.cert
	}
	signingCA := ca
	if parent != nil {
		signingCA = parent
	}

	altSPKI, err := x509.MarshalPKIXPublicKey(ca.alt.Public())
	require.NoError(t, err)
	algorithmDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: mldsaOID(t, signingCA.alt)})
	require.NoError(t, err)

	template.ExtraExtensions = []pkix.Extension{
		{Id: oidAltSubjectPublicKeyInfo, Value: altSPKI},
		{Id: oidAltSignatureAlgorithm, Value: algorithmDER},
	}
	firstPass, err := x509.CreateCertificate(rand.Reader, template, issuerCert, subjectPub, signingCA.classical)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(firstPass)
	require.NoError(t, err)

	preTBS, err := preTBSCertificate(parsed)
	require.NoError(t, err)
	altSignature, err := signingCA.alt.Sign(rand.Reader, preTBS, crypto.Hash(0))
	require.NoError(t, err)
	value, err := asn1.Marshal(asn1.BitString{Bytes: altSignature, BitLength: len(altSignature) * 8})
	require.NoError(t, err)

	template.ExtraExtensions = append(template.ExtraExtensions,
		pkix.Extension{Id: oidAltSignatureValue, Value: value})
	secondPass, err := x509.CreateCertificate(rand.Reader, template, issuerCert, subjectPub, signingCA.classical)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(secondPass)
	require.NoError(t, err)
	return cert
}

func (ca *altTestCA) issueLeaf(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &altTestCA{classical: subject, alt: ca.alt}
	return leaf.issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, subject.Public(), ca)
}

func mldsaOID(t *testing.T, key *mldsa.PrivateKey) asn1.ObjectIdentifier {
	t.Helper()
	switch key.Public().(*mldsa.PublicKey).Parameters() {
	case mldsa.MLDSA44():
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	case mldsa.MLDSA65():
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	default:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	}
}

func classicalCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "classical-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func TestValidateAlternativeChain(t *testing.T) {
	for name, params := range map[string]mldsa.Parameters{
		"ml-dsa-44": mldsa.MLDSA44(), "ml-dsa-65": mldsa.MLDSA65(), "ml-dsa-87": mldsa.MLDSA87(),
	} {
		t.Run(name, func(t *testing.T) {
			ca := newAltTestCA(t, params)
			leaf := ca.issueLeaf(t, "peer0")

			require.True(t, hasAlternativeSignature(leaf))
			assert.NoError(t, validateAlternativeChain([]*x509.Certificate{leaf, ca.cert}))
		})
	}
}

// TestValidateAlternativeChainIgnoresAClassicalRoot is the backwards-compatibility guarantee:
// an MSP rooted at a conventional CA must keep validating unchanged.
func TestValidateAlternativeChainIgnoresAClassicalRoot(t *testing.T) {
	root, key := classicalCert(t)
	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "classical-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, root, subject.Public(), key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	assert.NoError(t, validateAlternativeChain([]*x509.Certificate{leaf, root}))
	assert.NoError(t, validateAlternativeChain([]*x509.Certificate{root}))
}

// TestValidateAlternativeChainRejectsStrippedExtensions is the point of anchoring the
// requirement on the root: an attacker who removes the extensions must not be able to downgrade
// the certificate to the conventional signature alone.
func TestValidateAlternativeChainRejectsStrippedExtensions(t *testing.T) {
	ca := newAltTestCA(t, mldsa.MLDSA44())

	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "stripped"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, ca.cert, subject.Public(), ca.classical)
	require.NoError(t, err)
	stripped, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	require.NoError(t, stripped.CheckSignatureFrom(ca.cert), "a assinatura convencional e valida")
	assert.Error(t, validateAlternativeChain([]*x509.Certificate{stripped, ca.cert}),
		"uma raiz hibrida deve exigir a assinatura alternativa")
}

// TestValidateAlternativeChainRejectsAForeignIssuer covers the binding between the signature and
// the issuer's alternative key.
func TestValidateAlternativeChainRejectsAForeignIssuer(t *testing.T) {
	ca := newAltTestCA(t, mldsa.MLDSA44())
	other := newAltTestCA(t, mldsa.MLDSA44())
	leaf := ca.issueLeaf(t, "peer0")

	assert.Error(t, validateAlternativeChain([]*x509.Certificate{leaf, other.cert}))
}

// TestValidateAlternativeChainRejectsALevelMismatch covers an issuer that rotated its
// alternative key to a different parameter set.
func TestValidateAlternativeChainRejectsALevelMismatch(t *testing.T) {
	ca := newAltTestCA(t, mldsa.MLDSA44())
	other := newAltTestCA(t, mldsa.MLDSA87())
	leaf := ca.issueLeaf(t, "peer0")

	err := validateAlternativeChain([]*x509.Certificate{leaf, other.cert})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ML-DSA-44")
}

// TestAlternativeSignatureCoversTheCertificate checks that the signature is over the content and
// not only over the extensions carrying it.
func TestAlternativeSignatureCoversTheCertificate(t *testing.T) {
	ca := newAltTestCA(t, mldsa.MLDSA44())
	leaf := ca.issueLeaf(t, "peer0")

	// The byte has to be flipped inside a field the PreTBSCertificate keeps. Flipping the last
	// byte of the tbsCertificate would change only the altSignatureValue extension, which the
	// PreTBSCertificate drops by definition, and the signature would still verify.
	tampered := *leaf
	tampered.RawTBSCertificate = append([]byte(nil), leaf.RawTBSCertificate...)
	offset := bytes.Index(tampered.RawTBSCertificate, leaf.RawSubject)
	require.GreaterOrEqual(t, offset, 0)
	tampered.RawTBSCertificate[offset+len(leaf.RawSubject)-1] ^= 0x01

	assert.Error(t, verifyAlternativeSignature(&tampered, ca.cert))
}

func TestPreTBSCertificateDropsTheRightParts(t *testing.T) {
	ca := newAltTestCA(t, mldsa.MLDSA44())
	leaf := ca.issueLeaf(t, "peer0")

	pre, err := preTBSCertificate(leaf)
	require.NoError(t, err)

	assert.Less(t, len(pre), len(leaf.RawTBSCertificate))

	signature, found, err := altSignatureValue(leaf)
	require.NoError(t, err)
	require.True(t, found)
	assert.NotContains(t, string(pre), string(signature), "a assinatura alternativa deve sair")

	for name, field := range map[string][]byte{
		"subject": leaf.RawSubject,
		"issuer":  leaf.RawIssuer,
		"spki":    leaf.RawSubjectPublicKeyInfo,
	} {
		assert.Contains(t, string(pre), string(field), "%s deve permanecer", name)
	}
}

func TestAltSignatureExtensionsRejectMalformedValues(t *testing.T) {
	cert := &x509.Certificate{Extensions: []pkix.Extension{
		{Id: oidAltSignatureAlgorithm, Value: []byte{0x02, 0x01, 0x00}},
		{Id: oidAltSignatureValue, Value: []byte{0x02, 0x01, 0x00}},
	}}

	_, found, err := altSignatureLevel(cert)
	assert.True(t, found)
	assert.Error(t, err)

	_, found, err = altSignatureValue(cert)
	assert.True(t, found)
	assert.Error(t, err)
}

// TestValidateAlternativeChainWithAnIntermediateAnchor covers an MSP that trusts an intermediate
// CA without holding the root. The anchor is not self-signed, so its own alternative signature
// was made by a key outside the chain and cannot be verified here -- but everything below it
// still must be.
func TestValidateAlternativeChainWithAnIntermediateAnchor(t *testing.T) {
	root := newAltTestCA(t, mldsa.MLDSA44())
	intermediate := newAltIntermediate(t, root)
	leaf := intermediate.issueLeaf(t, "peer0")

	assert.NoError(t, validateAlternativeChain([]*x509.Certificate{leaf, intermediate.cert}))
	assert.NoError(t, validateAlternativeChain([]*x509.Certificate{leaf, intermediate.cert, root.cert}))

	// The chain below the anchor is still enforced.
	stripped := *leaf
	stripped.Extensions = nil
	assert.Error(t, validateAlternativeChain([]*x509.Certificate{&stripped, intermediate.cert}))
}

func newAltIntermediate(t *testing.T, parent *altTestCA) *altTestCA {
	t.Helper()
	classical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alt, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	ca := &altTestCA{classical: classical, alt: alt}
	ca.cert = ca.issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(6),
		Subject:               pkix.Name{CommonName: "alt-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, classical.Public(), parent)
	return ca
}
