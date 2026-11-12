/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func newSLHDSAKey(t *testing.T, ps slhdsa.ParameterSet) *slhdsa.PrivateKey {
	t.Helper()
	key, err := slhdsa.GenerateKey(ps)
	require.NoError(t, err)
	return key
}

func newCompositeSLHDSAKey(t *testing.T, ps slhdsa.ParameterSet) *composite.PrivateKey {
	t.Helper()
	alg, err := composite.AlgorithmForSLHDSA(ps)
	require.NoError(t, err)
	key, err := composite.GenerateKey(alg)
	require.NoError(t, err)
	return key
}

// issueExtTestCert issues tpl for subject, signed by signer on behalf of parent (nil for
// self-signed). Subject and signer may be of any pkixext scheme or ECDSA. crypto/x509 builds the
// TBS with a throwaway key; the SPKI, the signature algorithm and the signature are then replaced.
func issueExtTestCert(t *testing.T, tpl, parent *x509.Certificate, subject crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	compositeTestSerial++
	tpl.SerialNumber = big.NewInt(compositeTestSerial)
	tpl.NotBefore = time.Now().Add(-time.Hour)
	tpl.NotAfter = time.Now().Add(24 * time.Hour)
	if parent == nil {
		parent = tpl
	}
	throwaway := newECDSAKey(t)
	spki, _ := pkixext.MarshalPKIXPublicKey(subject)
	sigAlg, _ := pkixext.AlgorithmIdentifier(signer.Public())
	goSubject, goSigner := subject, signer
	if spki != nil {
		goSubject = throwaway.Public()
	}
	if sigAlg != nil {
		goSigner = throwaway
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, goSubject, goSigner)
	require.NoError(t, err)
	if spki == nil && sigAlg == nil {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	var outer compositeOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	fields := splitSequence(t, outer.TBS.FullBytes)
	if spki != nil {
		fields[6] = spki
	}
	if sigAlg != nil {
		fields[2] = sigAlg
		outer.SignatureAlgorithm = asn1.RawValue{FullBytes: sigAlg}
	}
	tbs := joinSequence(t, fields)
	var signature []byte
	if sigAlg != nil {
		signature, err = signer.Sign(rand.Reader, tbs, nil)
	} else {
		sum := sha256.Sum256(tbs)
		signature, err = signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	}
	require.NoError(t, err)
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	der, err = asn1.Marshal(outer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func extTestCRL(t *testing.T, issuer *x509.Certificate, signer crypto.Signer, revoked ...*big.Int) []byte {
	t.Helper()
	var list []pkix.RevokedCertificate
	for _, serial := range revoked {
		list = append(list, pkix.RevokedCertificate{SerialNumber: serial, RevocationTime: time.Now()})
	}
	//nolint:staticcheck
	der, err := issuer.CreateCRL(rand.Reader, newECDSAKey(t), list, time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	var outer compositeOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	fields := splitSequence(t, outer.TBS.FullBytes)
	fields[1], err = pkixext.AlgorithmIdentifier(signer.Public())
	require.NoError(t, err)
	tbs := joinSequence(t, fields)
	signature, err := signer.Sign(rand.Reader, tbs, nil)
	require.NoError(t, err)
	der, err = asn1.Marshal(compositeOuter{
		TBS:                asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: asn1.RawValue{FullBytes: fields[1]},
		Signature:          asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	require.NoError(t, err)
	return der
}

// writeExtMSPDir writes a local MSP whose identity key may be SLH-DSA, composite or ECDSA.
func writeExtMSPDir(t *testing.T, root *x509.Certificate, intermediates []*x509.Certificate, leaf *x509.Certificate, leafKey crypto.Signer, crls ...[]byte) string {
	t.Helper()
	if key, ok := leafKey.(*slhdsa.PrivateKey); ok {
		dir := writeCompositeMSPDir(t, root, intermediates, leaf, newECDSAKey(t), crls...)
		keyDER, err := slhdsa.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		writePEM(t, filepath.Join(dir, "keystore", "key.pem"), "PRIVATE KEY", keyDER)
		return dir
	}
	return writeCompositeMSPDir(t, root, intermediates, leaf, leafKey, crls...)
}

func deserializeTestIdentity(t *testing.T, msp MSP, cert *x509.Certificate) Identity {
	t.Helper()
	serialized, err := proto.Marshal(&m.SerializedIdentity{
		Mspid:   "SampleOrg",
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	})
	require.NoError(t, err)
	id, err := msp.DeserializeIdentity(serialized)
	require.NoError(t, err)
	return id
}

// TestSLHDSAIdentity covers an MSP with SLH-DSA material: the CA signs with SLH-DSA-SHA2-128f and the
// identity key is pure SLH-DSA or composite SLH-DSA, which must sign the full message.
func TestSLHDSAIdentity(t *testing.T) {
	caKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	ca := issueExtTestCert(t, compositeCATemplate("slhdsa-ca"), nil, caKey.PublicKey(), caKey)
	msg := []byte("a message signed by an SLH-DSA identity")
	digest := sha256.Sum256(msg)

	for name, signerKey := range map[string]crypto.Signer{
		"SLH-DSA-SHA2-128s":           newSLHDSAKey(t, slhdsa.SHA2_128s),
		"SLH-DSA-SHA2-128f":           newSLHDSAKey(t, slhdsa.SHA2_128f),
		"composite SLH-DSA-SHA2-128f": newCompositeSLHDSAKey(t, slhdsa.SHA2_128f),
	} {
		t.Run(name, func(t *testing.T) {
			leaf := issueExtTestCert(t, compositeLeafTemplate("slhdsa-identity"), ca, signerKey.Public(), caKey)
			thisMSP := getLocalMSPWithVersion(t, writeExtMSPDir(t, ca, nil, leaf, signerKey), MSPv3_0)
			id, err := thisMSP.GetDefaultSigningIdentity()
			require.NoError(t, err, "an SLH-DSA identity must be usable")
			require.NoError(t, thisMSP.Validate(id.GetPublicVersion()), "the algorithm gate must admit SLH-DSA")
			require.True(t, signsFullMessage(leaf.PublicKeyAlgorithm, leaf))

			sig, err := id.Sign(msg)
			require.NoError(t, err)
			assert.NoError(t, id.Verify(msg, sig))
			assert.Error(t, id.Verify([]byte("another message"), sig))

			switch k := signerKey.(type) {
			case *slhdsa.PrivateKey:
				assert.NoError(t, slhdsa.Verify(k.PublicKey(), msg, sig, nil), "SLH-DSA must sign the full message")
				assert.Error(t, slhdsa.Verify(k.PublicKey(), digest[:], sig, nil))
			case *composite.PrivateKey:
				assert.NoError(t, composite.Verify(k.PublicKey(), msg, sig, nil), "composite must sign the full message")
				assert.Error(t, composite.Verify(k.PublicKey(), digest[:], sig, nil))
			}
		})
	}
}

func TestSLHDSAIdentityRejectedBeforeV3(t *testing.T) {
	caKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	ca := issueExtTestCert(t, compositeCATemplate("slhdsa-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	leaf := issueExtTestCert(t, compositeLeafTemplate("slhdsa-identity"), ca, signerKey.PublicKey(), caKey)

	_, err := getLocalMSPWithVersionAndError(t, writeExtMSPDir(t, ca, nil, leaf, signerKey), MSPv1_4_3)
	require.ErrorContains(t, err, "is not supported", "MSPv1_4_3 must not admit SLH-DSA")
}

// TestSLHDSAIntermediateCA covers an SLH-DSA root and intermediate, with the identity issued by the
// intermediate. An identity issued directly by the root is refused.
func TestSLHDSAIntermediateCA(t *testing.T) {
	rootKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	root := issueExtTestCert(t, compositeCATemplate("slhdsa-root"), nil, rootKey.PublicKey(), rootKey)
	interKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	inter := issueExtTestCert(t, compositeCATemplate("slhdsa-intermediate"), root, interKey.PublicKey(), rootKey)
	signerKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	leaf := issueExtTestCert(t, compositeLeafTemplate("slhdsa-identity"), inter, signerKey.PublicKey(), interKey)

	thisMSP := getLocalMSPWithVersion(t, writeExtMSPDir(t, root, []*x509.Certificate{inter}, leaf, signerKey), MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))
	chain, err := thisMSP.(*bccspmsp).getCertificationChain(id.GetPublicVersion())
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.True(t, chain[1].Equal(inter))
	assert.True(t, chain[2].Equal(root))

	fromRoot := issueExtTestCert(t, compositeLeafTemplate("issued-by-root"), root, newSLHDSAKey(t, slhdsa.SHA2_128f).PublicKey(), rootKey)
	require.ErrorContains(t, thisMSP.Validate(deserializeTestIdentity(t, thisMSP, fromRoot)), "should be a leaf of the certification tree")
}

// TestSLHDSAMixedSchemes covers a composite SLH-DSA root over an SLH-DSA intermediate that issues a
// Composite ML-DSA identity: each link is verified by the scheme of its own signature.
func TestSLHDSAMixedSchemes(t *testing.T) {
	rootKey := newCompositeSLHDSAKey(t, slhdsa.SHA2_128f)
	root := issueExtTestCert(t, compositeCATemplate("composite-slhdsa-root"), nil, rootKey.PublicKey(), rootKey)
	interKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	inter := issueExtTestCert(t, compositeCATemplate("slhdsa-intermediate"), root, interKey.PublicKey(), rootKey)
	signerKey := newCompositeKey(t, 44)
	leaf := issueExtTestCert(t, compositeLeafTemplate("mldsa-composite-identity"), inter, signerKey.PublicKey(), interKey)

	thisMSP := getLocalMSPWithVersion(t, writeExtMSPDir(t, root, []*x509.Certificate{inter}, leaf, signerKey), MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))
	msg := []byte("a message signed under a mixed chain")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	assert.NoError(t, id.Verify(msg, sig))
}

func TestSLHDSAIdentityFromOtherCA(t *testing.T) {
	caKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	ca := issueExtTestCert(t, compositeCATemplate("slhdsa-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	leaf := issueExtTestCert(t, compositeLeafTemplate("slhdsa-identity"), ca, signerKey.PublicKey(), caKey)
	thisMSP := getLocalMSPWithVersion(t, writeExtMSPDir(t, ca, nil, leaf, signerKey), MSPv3_0)

	otherKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	other := issueExtTestCert(t, compositeCATemplate("slhdsa-ca"), nil, otherKey.PublicKey(), otherKey)
	outsider := issueExtTestCert(t, compositeLeafTemplate("outsider"), other, newSLHDSAKey(t, slhdsa.SHA2_128f).PublicKey(), otherKey)
	require.ErrorContains(t, thisMSP.Validate(deserializeTestIdentity(t, thisMSP, outsider)), "unknown authority")
}

// TestSLHDSARevocation covers the SLH-DSA CRL: the one of the CA revokes the identity, and one
// signed by another key is ignored.
func TestSLHDSARevocation(t *testing.T) {
	caKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	ca := issueExtTestCert(t, compositeCATemplate("slhdsa-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	leaf := issueExtTestCert(t, compositeLeafTemplate("slhdsa-identity"), ca, signerKey.PublicKey(), caKey)
	other := issueExtTestCert(t, compositeLeafTemplate("other-identity"), ca, newSLHDSAKey(t, slhdsa.SHA2_128f).PublicKey(), caKey)

	crl := extTestCRL(t, ca, caKey, other.SerialNumber)
	thisMSP := getLocalMSPWithVersion(t, writeExtMSPDir(t, ca, nil, leaf, signerKey, crl), MSPv3_0)
	require.NoError(t, thisMSP.Validate(deserializeTestIdentity(t, thisMSP, leaf)))
	require.ErrorContains(t, thisMSP.Validate(deserializeTestIdentity(t, thisMSP, other)), "revoked")

	forged := extTestCRL(t, ca, newSLHDSAKey(t, slhdsa.SHA2_128f), other.SerialNumber)
	forgedMSP := getLocalMSPWithVersion(t, writeExtMSPDir(t, ca, nil, leaf, signerKey, forged), MSPv3_0)
	require.NoError(t, forgedMSP.Validate(deserializeTestIdentity(t, forgedMSP, other)))
}

// TestSLHDSATLSCAs covers an MSP whose TLS root and intermediate are SLH-DSA, next to an ECDSA
// identity chain. MSP v3 validates the TLS intermediate through pkixext; earlier versions verify it
// with crypto/x509 and refuse it.
func TestSLHDSATLSCAs(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := issueExtTestCert(t, compositeCATemplate("ecdsa-ca"), nil, caKey.Public(), caKey)
	signerKey := newECDSAKey(t)
	leaf := issueExtTestCert(t, compositeLeafTemplate("ecdsa-identity"), ca, signerKey.Public(), caKey)

	tlsRootKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	tlsRoot := issueExtTestCert(t, compositeCATemplate("slhdsa-tlsroot"), nil, tlsRootKey.PublicKey(), tlsRootKey)
	tlsInterKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	tlsInter := issueExtTestCert(t, compositeCATemplate("slhdsa-tlsinter"), tlsRoot, tlsInterKey.PublicKey(), tlsRootKey)
	otherKey := newSLHDSAKey(t, slhdsa.SHA2_128f)
	strayInter := issueExtTestCert(t, compositeCATemplate("slhdsa-stray"), tlsRoot, tlsInterKey.PublicKey(), otherKey)

	writeDir := func(t *testing.T, inter *x509.Certificate) string {
		dir := writeExtMSPDir(t, ca, nil, leaf, signerKey)
		writePEM(t, filepath.Join(dir, "tlscacerts", "tlsroot.pem"), "CERTIFICATE", tlsRoot.Raw)
		writePEM(t, filepath.Join(dir, "tlsintermediatecerts", "tlsinter.pem"), "CERTIFICATE", inter.Raw)
		return dir
	}

	t.Run("accepted with V3_0", func(t *testing.T) {
		thisMSP := getLocalMSPWithVersion(t, writeDir(t, tlsInter), MSPv3_0)
		require.Len(t, thisMSP.GetTLSIntermediateCerts(), 1)
	})
	t.Run("intermediate not signed by the root", func(t *testing.T) {
		_, err := getLocalMSPWithVersionAndError(t, writeDir(t, strayInter), MSPv3_0)
		require.ErrorContains(t, err, "CA Certificate is not valid")
	})
	t.Run("refused before V3_0", func(t *testing.T) {
		_, err := getLocalMSPWithVersionAndError(t, writeDir(t, tlsInter), MSPv1_4_3)
		require.ErrorContains(t, err, "CA Certificate is not valid")
	})
}
