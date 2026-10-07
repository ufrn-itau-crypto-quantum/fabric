/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// chainTestPKI is one root shared by two organizations, each with its own intermediate CA, and
// one leaf per intermediate. It is the layout of the evolving-topo chain scenarios.
type chainTestPKI struct {
	root                  *x509.Certificate
	intermediateA         *x509.Certificate
	intermediateB         *x509.Certificate
	leafA, leafB          *x509.Certificate
	leafAKey              crypto.Signer
	strippedLeafAIfHybrid *x509.Certificate
}

// TestMSPWithSharedRootAndIntermediate sets up an MSP holding the shared root in cacerts and only
// its own intermediate in intermediatecerts. The leaf of its own organization must validate over
// three certificates, and the leaf issued by the sibling intermediate must not, even though both
// chain to the same root.
func TestMSPWithSharedRootAndIntermediate(t *testing.T) {
	for name, build := range map[string]func(t *testing.T) chainTestPKI{
		"ML-DSA":        newPureMLDSAChainPKI,
		"hybrid ML-DSA": newHybridChainPKI,
	} {
		t.Run(name, func(t *testing.T) {
			pki := build(t)
			dir := t.TempDir()
			writePEM(t, filepath.Join(dir, "cacerts", "root.pem"), "CERTIFICATE", pki.root.Raw)
			writePEM(t, filepath.Join(dir, "intermediatecerts", "ica.pem"), "CERTIFICATE", pki.intermediateA.Raw)
			writePEM(t, filepath.Join(dir, "signcerts", "cert.pem"), "CERTIFICATE", pki.leafA.Raw)
			writePEM(t, filepath.Join(dir, "admincerts", "admincert.pem"), "CERTIFICATE", pki.leafA.Raw)
			keyDER, err := x509.MarshalPKCS8PrivateKey(pki.leafAKey)
			require.NoError(t, err)
			writePEM(t, filepath.Join(dir, "keystore", "key.pem"), "PRIVATE KEY", keyDER)

			thisMSP := getLocalMSPWithVersion(t, dir, MSPv3_0)

			own, err := thisMSP.DeserializeIdentity(serializeForChainTest(pki.leafA))
			require.NoError(t, err)
			assert.NoError(t, thisMSP.Validate(own), "the leaf of the MSP's own intermediate must validate")

			chain, err := thisMSP.(*bccspmsp).getCertificationChain(own)
			require.NoError(t, err)
			assert.Len(t, chain, 3, "the certification chain holds the leaf, the intermediate and the root")

			assert.Error(t, deserializeAndValidate(thisMSP, pki.leafB),
				"a leaf of the sibling intermediate must not validate, even under the same root")

			if pki.strippedLeafAIfHybrid != nil {
				assert.Error(t, deserializeAndValidate(thisMSP, pki.strippedLeafAIfHybrid),
					"a leaf without the alternative signature must not validate under a hybrid root")
			}
		})
	}
}

func newHybridChainPKI(t *testing.T) chainTestPKI {
	root := newAltTestCA(t, mldsa.MLDSA44())
	intermediateA := newAltIntermediate(t, root)
	intermediateB := newAltIntermediate(t, root)

	leafA, leafAKey := issueHybridLeaf(t, intermediateA, "peer0.bankA")
	leafB, _ := issueHybridLeaf(t, intermediateB, "peer0.bankB")

	// Conventionally signed by the right intermediate, but without the alternative signature
	// extensions: exactly what an attacker holding only a broken classical key would present.
	classical, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "peer0.bankA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, intermediateA.cert, leafAKey.Public(), intermediateA.classical)
	require.NoError(t, err)
	stripped, err := x509.ParseCertificate(classical)
	require.NoError(t, err)

	return chainTestPKI{
		root:                  root.cert,
		intermediateA:         intermediateA.cert,
		intermediateB:         intermediateB.cert,
		leafA:                 leafA,
		leafB:                 leafB,
		leafAKey:              leafAKey,
		strippedLeafAIfHybrid: stripped,
	}
}

func issueHybridLeaf(t *testing.T, issuer *altTestCA, commonName string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alt, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	subject := &altTestCA{classical: key, alt: alt}
	cert := subject.issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, key.Public(), issuer)
	return cert, key
}

func newPureMLDSAChainPKI(t *testing.T) chainTestPKI {
	rootKey := newMLDSAKey(t)
	root := createChainTestCert(t, "root", true, rootKey.PublicKey(), nil, rootKey)
	icaAKey, icaBKey := newMLDSAKey(t), newMLDSAKey(t)
	intermediateA := createChainTestCert(t, "ica-bankA", true, icaAKey.PublicKey(), root, rootKey)
	intermediateB := createChainTestCert(t, "ica-bankB", true, icaBKey.PublicKey(), root, rootKey)
	leafAKey, leafBKey := newMLDSAKey(t), newMLDSAKey(t)

	return chainTestPKI{
		root:          root,
		intermediateA: intermediateA,
		intermediateB: intermediateB,
		leafA:         createChainTestCert(t, "peer0.bankA", false, leafAKey.PublicKey(), intermediateA, icaAKey),
		leafB:         createChainTestCert(t, "peer0.bankB", false, leafBKey.PublicKey(), intermediateB, icaBKey),
		leafAKey:      leafAKey,
	}
}

func newMLDSAKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	return key
}

// createChainTestCert issues a certificate for pub, signed by issuerKey. A nil issuer makes it
// self-signed.
func createChainTestCert(t *testing.T, commonName string, isCA bool, pub any, issuer *x509.Certificate, issuerKey crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if issuer == nil {
		issuer = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// deserializeAndValidate returns the first error of the two steps. Which step refuses a foreign
// certificate depends on the algorithm: the ECDSA sanitization already builds the chain during
// deserialization, while an ML-DSA certificate is only checked on Validate.
func deserializeAndValidate(thisMSP MSP, cert *x509.Certificate) error {
	id, err := thisMSP.DeserializeIdentity(serializeForChainTest(cert))
	if err != nil {
		return err
	}
	return thisMSP.Validate(id)
}

func serializeForChainTest(cert *x509.Certificate) []byte {
	raw, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   "SampleOrg",
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	})
	if err != nil {
		panic(err)
	}
	return raw
}
