/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var compositeTestSerial int64 = 100

type compositeOuter struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

func newCompositeKey(t *testing.T, level int) *composite.PrivateKey {
	t.Helper()
	alg, err := composite.AlgorithmForLevel(level)
	require.NoError(t, err)
	key, err := composite.GenerateKey(alg)
	require.NoError(t, err)
	return key
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func compositeCATemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte(name),
	}
}

func compositeLeafTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, SubjectKeyId: []byte(name),
	}
}

// issueCompositeTestCert emite tpl com a chave pública subject, assinado por signer em nome de parent
// (nil para autoassinado). A chave e a assinatura podem ser composite ou ECDSA. O TBS é montado com uma
// chave descartável, e o SPKI e a assinatura são trocados depois.
func issueCompositeTestCert(t *testing.T, tpl, parent *x509.Certificate, subject crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	compositeTestSerial++
	tpl.SerialNumber = big.NewInt(compositeTestSerial)
	tpl.NotBefore = time.Now().Add(-time.Hour)
	tpl.NotAfter = time.Now().Add(24 * time.Hour)
	if parent == nil {
		parent = tpl
	}
	throwaway := newECDSAKey(t)
	goSubject, goSigner := subject, signer
	if _, ok := subject.(*composite.PublicKey); ok {
		goSubject = throwaway.Public()
	}
	if _, ok := signer.(*composite.PrivateKey); ok {
		goSigner = throwaway
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, goSubject, goSigner)
	require.NoError(t, err)
	pub, compositeSubject := subject.(*composite.PublicKey)
	key, compositeSigner := signer.(*composite.PrivateKey)
	if !compositeSubject && !compositeSigner {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	var outer compositeOuter
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	fields := splitSequence(t, outer.TBS.FullBytes)
	// version [0], serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
	if compositeSubject {
		fields[6], err = composite.MarshalPKIXPublicKey(pub)
		require.NoError(t, err)
	}
	if compositeSigner {
		fields[2], err = composite.AlgorithmIdentifier(key.PublicKey().Algorithm)
		require.NoError(t, err)
		outer.SignatureAlgorithm = asn1.RawValue{FullBytes: fields[2]}
	}
	tbs := joinSequence(t, fields)
	var signature []byte
	if compositeSigner {
		signature, err = key.Sign(rand.Reader, tbs, nil)
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

// compositeTestCRL gera com o CreateCRL uma CRL assinada por uma chave descartável e troca o
// algoritmo e a assinatura pelos de signer.
func compositeTestCRL(t *testing.T, issuer *x509.Certificate, signer *composite.PrivateKey, revoked ...*big.Int) []byte {
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
	// version, signature, issuer, thisUpdate, nextUpdate, revokedCertificates, crlExtensions
	fields[1], err = composite.AlgorithmIdentifier(signer.PublicKey().Algorithm)
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

func splitSequence(t *testing.T, der []byte) [][]byte {
	t.Helper()
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(der, &seq)
	require.NoError(t, err)
	var fields [][]byte
	for rest := seq.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		require.NoError(t, err)
		fields = append(fields, field.FullBytes)
	}
	return fields
}

func joinSequence(t *testing.T, fields [][]byte) []byte {
	t.Helper()
	var content []byte
	for _, field := range fields {
		content = append(content, field...)
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	require.NoError(t, err)
	return der
}

// writeCompositeMSPDir grava um MSP local com a raiz, as intermediárias, a identidade, a chave dela e as CRLs
func writeCompositeMSPDir(t *testing.T, root *x509.Certificate, intermediates []*x509.Certificate, leaf *x509.Certificate, leafKey crypto.Signer, crls ...[]byte) string {
	t.Helper()
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "cacerts", "cacert.pem"), "CERTIFICATE", root.Raw)
	for i, cert := range intermediates {
		writePEM(t, filepath.Join(dir, "intermediatecerts", big.NewInt(int64(i)).String()+".pem"), "CERTIFICATE", cert.Raw)
	}
	writePEM(t, filepath.Join(dir, "signcerts", "cert.pem"), "CERTIFICATE", leaf.Raw)
	writePEM(t, filepath.Join(dir, "admincerts", "admincert.pem"), "CERTIFICATE", leaf.Raw)
	for i, crl := range crls {
		writePEM(t, filepath.Join(dir, "crls", big.NewInt(int64(i)).String()+".pem"), "X509 CRL", crl)
	}
	var keyDER []byte
	var err error
	if key, ok := leafKey.(*composite.PrivateKey); ok {
		keyDER, err = composite.MarshalPKCS8PrivateKey(key)
	} else {
		keyDER, err = x509.MarshalPKCS8PrivateKey(leafKey)
	}
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "keystore", "key.pem"), "PRIVATE KEY", keyDER)
	return dir
}

// TestCompositeIdentity cobre um MSP com o material que um fabric-ca em modo composite emite: a CA
// assina em composite, e a identidade tem chave composite, que precisa assinar a mensagem inteira.
func TestCompositeIdentity(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		t.Run(big.NewInt(int64(level)).String(), func(t *testing.T) {
			caKey := newCompositeKey(t, level)
			ca := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, caKey.PublicKey(), caKey)
			signerKey := newCompositeKey(t, level)
			leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), ca, signerKey.PublicKey(), caKey)

			thisMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, ca, nil, leaf, signerKey), MSPv3_0)
			id, err := thisMSP.GetDefaultSigningIdentity()
			require.NoError(t, err, "a composite identity must be usable")
			require.NoError(t, thisMSP.Validate(id.GetPublicVersion()), "the algorithm gate must admit composite")

			msg := []byte("a message signed by a composite identity")
			sig, err := id.Sign(msg)
			require.NoError(t, err)
			assert.NoError(t, id.Verify(msg, sig))
			assert.Error(t, id.Verify([]byte("another message"), sig))

			assert.NoError(t, composite.Verify(signerKey.PublicKey(), msg, sig, nil), "composite must sign the full message")
			digest := sha256.Sum256(msg)
			assert.Error(t, composite.Verify(signerKey.PublicKey(), digest[:], sig, nil))
		})
	}
}

// TestCompositeIdentityRejectedBeforeV3 fixa que admitir composite é comportamento do MSP v3
func TestCompositeIdentityRejectedBeforeV3(t *testing.T) {
	caKey := newCompositeKey(t, 44)
	ca := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newCompositeKey(t, 44)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), ca, signerKey.PublicKey(), caKey)

	_, err := getLocalMSPWithVersionAndError(t, writeCompositeMSPDir(t, ca, nil, leaf, signerKey), MSPv1_4_3)
	require.ErrorContains(t, err, "is not supported", "MSPv1_4_3 must not admit composite")

	ecKey := newECDSAKey(t)
	ecLeaf := issueCompositeTestCert(t, compositeLeafTemplate("ecdsa-identity"), ca, ecKey.Public(), caKey)
	_, err = getLocalMSPWithVersionAndError(t, writeCompositeMSPDir(t, ca, nil, ecLeaf, ecKey), MSPv1_4_3)
	require.ErrorContains(t, err, "unknown authority")
}

// TestCompositeChainIgnoredForTLS fixa que a validação composite vale só para as cadeias de identidade.
// Uma intermediária de TLS assinada em composite é recusada, mesmo sob a raiz composite que o MSP aceita
// para identidades.
func TestCompositeChainIgnoredForTLS(t *testing.T) {
	caKey := newCompositeKey(t, 65)
	ca := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newCompositeKey(t, 65)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), ca, signerKey.PublicKey(), caKey)
	dir := writeCompositeMSPDir(t, ca, nil, leaf, signerKey)

	tlsInter := issueCompositeTestCert(t, compositeCATemplate("tls-intermediate"), ca, newECDSAKey(t).Public(), caKey)
	writePEM(t, filepath.Join(dir, "tlscacerts", "tlsroot.pem"), "CERTIFICATE", ca.Raw)
	writePEM(t, filepath.Join(dir, "tlsintermediatecerts", "tlsinter.pem"), "CERTIFICATE", tlsInter.Raw)

	_, err := getLocalMSPWithVersionAndError(t, dir, MSPv3_0)
	require.ErrorContains(t, err, "x509: certificate signed by unknown authority")
}

// TestCompositeChainUsesSanitizedRoot fixa que a validação composite usa os certificados depois do
// sanitizeCert: uma raiz ECDSA com assinatura high-S é regravada em low-S no setup, e a cadeia de uma
// identidade composite abaixo dela termina na raiz regravada.
func TestCompositeChainUsesSanitizedRoot(t *testing.T) {
	rootKey := newECDSAKey(t)
	root := issueCompositeTestCert(t, compositeCATemplate("ecdsa-root"), nil, rootKey.Public(), rootKey)
	highS := withHighS(t, root)

	interKey := newCompositeKey(t, 44)
	inter := issueCompositeTestCert(t, compositeCATemplate("composite-intermediate"), root, interKey.PublicKey(), rootKey)
	signerKey := newCompositeKey(t, 44)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), inter, signerKey.PublicKey(), interKey)

	thisMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, highS, []*x509.Certificate{inter}, leaf, signerKey), MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))

	sanitized := thisMSP.(*bccspmsp).rootCerts[0].(*identity).cert
	require.False(t, sanitized.Equal(highS), "the setup must rewrite the root in low-S")
	chain, err := thisMSP.(*bccspmsp).getCertificationChain(id.GetPublicVersion())
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.True(t, chain[2].Equal(sanitized))
}

// withHighS devolve cert com assinatura ECDSA high-S: (r, s) vira (r, N-s) quando s é low-S. As duas são válidas.
func withHighS(t *testing.T, cert *x509.Certificate) *x509.Certificate {
	t.Helper()
	var sig struct{ R, S *big.Int }
	_, err := asn1.Unmarshal(cert.Signature, &sig)
	require.NoError(t, err)
	n := elliptic.P256().Params().N
	if sig.S.Cmp(new(big.Int).Rsh(n, 1)) <= 0 {
		sig.S = new(big.Int).Sub(n, sig.S)
	}
	require.Positive(t, sig.S.Cmp(new(big.Int).Rsh(n, 1)))
	value, err := asn1.Marshal(sig)
	require.NoError(t, err)
	var outer compositeOuter
	_, err = asn1.Unmarshal(cert.Raw, &outer)
	require.NoError(t, err)
	outer.Signature = asn1.BitString{Bytes: value, BitLength: 8 * len(value)}
	der, err := asn1.Marshal(outer)
	require.NoError(t, err)
	out, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.NoError(t, out.CheckSignatureFrom(out))
	return out
}

// TestCompositeMixedChain cobre uma raiz composite com uma intermediária ECDSA, que assina a identidade
// em ECDSA: o sanitizeCert da identidade valida a cadeia até a raiz composite.
func TestCompositeMixedChain(t *testing.T) {
	rootKey := newCompositeKey(t, 65)
	root := issueCompositeTestCert(t, compositeCATemplate("composite-root"), nil, rootKey.PublicKey(), rootKey)
	interKey := newECDSAKey(t)
	inter := issueCompositeTestCert(t, compositeCATemplate("ecdsa-intermediate"), root, interKey.Public(), rootKey)
	signerKey := newECDSAKey(t)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("ecdsa-identity"), inter, signerKey.Public(), interKey)

	thisMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, root, []*x509.Certificate{inter}, leaf, signerKey), MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))

	chain, err := thisMSP.(*bccspmsp).getCertificationChain(id.GetPublicVersion())
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.True(t, chain[1].Equal(inter))
	assert.True(t, chain[2].Equal(root))

	msg := []byte("a message signed by an ECDSA identity under a composite root")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	assert.NoError(t, id.Verify(msg, sig))
}

// TestCompositeIntermediateCA cobre raiz e intermediária composite, com as identidades emitidas pela
// intermediária. Uma identidade emitida direto pela raiz é recusada.
func TestCompositeIntermediateCA(t *testing.T) {
	rootKey := newCompositeKey(t, 65)
	root := issueCompositeTestCert(t, compositeCATemplate("composite-root"), nil, rootKey.PublicKey(), rootKey)
	interKey := newCompositeKey(t, 65)
	inter := issueCompositeTestCert(t, compositeCATemplate("composite-intermediate"), root, interKey.PublicKey(), rootKey)
	signerKey := newCompositeKey(t, 44)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), inter, signerKey.PublicKey(), interKey)

	thisMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, root, []*x509.Certificate{inter}, leaf, signerKey), MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))

	chain, err := thisMSP.(*bccspmsp).getCertificationChain(id.GetPublicVersion())
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.True(t, chain[1].Equal(inter))
	assert.True(t, chain[2].Equal(root))

	msg := []byte("a message signed by an identity of a composite intermediate CA")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	assert.NoError(t, id.Verify(msg, sig))
	assert.NoError(t, composite.Verify(signerKey.PublicKey(), msg, sig, nil))

	fromRoot := issueCompositeTestCert(t, compositeLeafTemplate("issued-by-root"), root, newCompositeKey(t, 44).PublicKey(), rootKey)
	serialized, err := proto.Marshal(&m.SerializedIdentity{
		Mspid:   "SampleOrg",
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fromRoot.Raw}),
	})
	require.NoError(t, err)
	rootIssued, err := thisMSP.DeserializeIdentity(serialized)
	require.NoError(t, err)
	require.ErrorContains(t, thisMSP.Validate(rootIssued), "should be a leaf of the certification tree")
}

// TestCompositeIntermediateNodeOUs cobre o NodeOUs apontando para a intermediária composite.
func TestCompositeIntermediateNodeOUs(t *testing.T) {
	rootKey := newCompositeKey(t, 65)
	root := issueCompositeTestCert(t, compositeCATemplate("composite-root"), nil, rootKey.PublicKey(), rootKey)
	interKey := newCompositeKey(t, 65)
	inter := issueCompositeTestCert(t, compositeCATemplate("composite-intermediate"), root, interKey.PublicKey(), rootKey)
	signerKey := newCompositeKey(t, 65)
	tpl := compositeLeafTemplate("composite-client")
	tpl.Subject.OrganizationalUnit = []string{"client"}
	leaf := issueCompositeTestCert(t, tpl, inter, signerKey.PublicKey(), interKey)

	dir := writeCompositeMSPDir(t, root, []*x509.Certificate{inter}, leaf, signerKey)
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "admincerts")))
	nodeOUs := "NodeOUs:\n  Enable: true\n"
	for _, role := range []string{"Client", "Peer", "Admin", "Orderer"} {
		nodeOUs += fmt.Sprintf("  %sOUIdentifier:\n    Certificate: intermediatecerts/0.pem\n    OrganizationalUnitIdentifier: %s\n",
			role, strings.ToLower(role))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(nodeOUs), 0o600))

	thisMSP := getLocalMSPWithVersion(t, dir, MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))
	require.NoError(t, thisMSP.SatisfiesPrincipal(id.GetPublicVersion(), &m.MSPPrincipal{
		PrincipalClassification: m.MSPPrincipal_ROLE,
		Principal:               mustMarshal(t, &m.MSPRole{MspIdentifier: "SampleOrg", Role: m.MSPRole_CLIENT}),
	}))
	require.Error(t, thisMSP.SatisfiesPrincipal(id.GetPublicVersion(), &m.MSPPrincipal{
		PrincipalClassification: m.MSPPrincipal_ROLE,
		Principal:               mustMarshal(t, &m.MSPRole{MspIdentifier: "SampleOrg", Role: m.MSPRole_PEER}),
	}))
}

func mustMarshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	require.NoError(t, err)
	return raw
}

// TestCompositeIdentityFromOtherCA fixa que uma identidade composite de outra CA é recusada
func TestCompositeIdentityFromOtherCA(t *testing.T) {
	caKey := newCompositeKey(t, 65)
	ca := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newCompositeKey(t, 65)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), ca, signerKey.PublicKey(), caKey)
	thisMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, ca, nil, leaf, signerKey), MSPv3_0)

	otherKey := newCompositeKey(t, 65)
	other := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, otherKey.PublicKey(), otherKey)
	outsider := issueCompositeTestCert(t, compositeLeafTemplate("outsider"), other, newCompositeKey(t, 65).PublicKey(), otherKey)

	serialized, err := proto.Marshal(&m.SerializedIdentity{
		Mspid:   "SampleOrg",
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: outsider.Raw}),
	})
	require.NoError(t, err)
	id, err := thisMSP.DeserializeIdentity(serialized)
	require.NoError(t, err)
	require.ErrorContains(t, thisMSP.Validate(id), "unknown authority")
}

// TestCompositeRevocation cobre a CRL composite: a da CA revoga a identidade, e uma assinada por outra
// chave é ignorada.
func TestCompositeRevocation(t *testing.T) {
	caKey := newCompositeKey(t, 65)
	ca := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, caKey.PublicKey(), caKey)
	signerKey := newCompositeKey(t, 65)
	leaf := issueCompositeTestCert(t, compositeLeafTemplate("composite-identity"), ca, signerKey.PublicKey(), caKey)
	other := issueCompositeTestCert(t, compositeLeafTemplate("other-identity"), ca, newCompositeKey(t, 65).PublicKey(), caKey)

	crl := compositeTestCRL(t, ca, caKey, other.SerialNumber)
	thisMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, ca, nil, leaf, signerKey, crl), MSPv3_0)
	deserialize := func(cert *x509.Certificate) Identity {
		serialized, err := proto.Marshal(&m.SerializedIdentity{
			Mspid:   "SampleOrg",
			IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		})
		require.NoError(t, err)
		id, err := thisMSP.DeserializeIdentity(serialized)
		require.NoError(t, err)
		return id
	}
	require.NoError(t, thisMSP.Validate(deserialize(leaf)))
	require.ErrorContains(t, thisMSP.Validate(deserialize(other)), "revoked")

	forged := compositeTestCRL(t, ca, newCompositeKey(t, 65), other.SerialNumber)
	forgedMSP := getLocalMSPWithVersion(t, writeCompositeMSPDir(t, ca, nil, leaf, signerKey, forged), MSPv3_0)
	serialized, err := proto.Marshal(&m.SerializedIdentity{
		Mspid:   "SampleOrg",
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw}),
	})
	require.NoError(t, err)
	id, err := forgedMSP.DeserializeIdentity(serialized)
	require.NoError(t, err)
	require.NoError(t, forgedMSP.Validate(id))
}

func TestCompositeSignsFullMessage(t *testing.T) {
	caKey := newCompositeKey(t, 44)
	ca := issueCompositeTestCert(t, compositeCATemplate("composite-ca"), nil, caKey.PublicKey(), caKey)
	assert.True(t, signsFullMessage(ca))

	ecKey := newECDSAKey(t)
	ec := issueCompositeTestCert(t, compositeCATemplate("ecdsa-ca"), nil, ecKey.Public(), ecKey)
	assert.False(t, signsFullMessage(ec))
}
