/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hybridMSPDir is an MSP directory whose identity chains to a hybrid root through an
// intermediate, with the classical and the alternative private keys of the identity.
type hybridMSPDir struct {
	dir    string
	pki    chainTestPKI
	altPub *mldsa.PublicKey
}

// writeHybridMSPDir lays out the MSP directory of newHybridChainPKI's leafA. withAltKey false
// leaves the ML-DSA private key out of the keystore.
func writeHybridMSPDir(t *testing.T, withAltKey bool) hybridMSPDir {
	t.Helper()
	pki := newHybridChainPKI(t)
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "cacerts", "root.pem"), "CERTIFICATE", pki.root.Raw)
	writePEM(t, filepath.Join(dir, "intermediatecerts", "ica.pem"), "CERTIFICATE", pki.intermediateA.Raw)
	writePEM(t, filepath.Join(dir, "signcerts", "cert.pem"), "CERTIFICATE", pki.leafA.Raw)
	writePEM(t, filepath.Join(dir, "admincerts", "admincert.pem"), "CERTIFICATE", pki.leafA.Raw)

	keyDER, err := x509.MarshalPKCS8PrivateKey(pki.leafAKey)
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "keystore", "key.pem"), "PRIVATE KEY", keyDER)
	if withAltKey {
		altDER, err := x509.MarshalPKCS8PrivateKey(pki.leafAAltKey)
		require.NoError(t, err)
		writePEM(t, filepath.Join(dir, "keystore", "altkey.pem"), "PRIVATE KEY", altDER)
	}

	return hybridMSPDir{dir: dir, pki: pki, altPub: pki.leafAAltKey.PublicKey()}
}

// TestHybridIdentitySignsWithTheAlternativeKey pins that under hybrid signatures a hybrid
// identity signs the full message with its ML-DSA key, and that another instance of the MSP,
// standing for a remote verifier, accepts the signature.
func TestHybridIdentitySignsWithTheAlternativeKey(t *testing.T) {
	h := writeHybridMSPDir(t, true)
	thisMSP := getLocalMSPWithVersion(t, h.dir, MSPv3_0Hybrid)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))

	msg := []byte("a transaction signed by a hybrid identity")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	assert.Len(t, sig, mldsa.MLDSA44().SignatureSize())
	assert.NoError(t, mldsa.Verify(h.altPub, msg, sig, nil))
	assert.NoError(t, id.Verify(msg, sig))
	assert.Error(t, id.Verify([]byte("another transaction"), sig))

	verifier := getLocalMSPWithVersion(t, h.dir, MSPv3_0Hybrid)
	remote, err := verifier.DeserializeIdentity(serializeForChainTest(h.pki.leafA))
	require.NoError(t, err)
	assert.NoError(t, remote.Verify(msg, sig))
}

// TestHybridIdentityRejectsAClassicalSignature pins the downgrade protection: a valid ECDSA
// signature by the classical key of a hybrid identity is refused.
func TestHybridIdentityRejectsAClassicalSignature(t *testing.T) {
	h := writeHybridMSPDir(t, true)
	thisMSP := getLocalMSPWithVersion(t, h.dir, MSPv3_0Hybrid)
	id, err := thisMSP.DeserializeIdentity(serializeForChainTest(h.pki.leafA))
	require.NoError(t, err)

	msg := []byte("a transaction signed with the classical key")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, h.pki.leafAKey.(*ecdsa.PrivateKey), digest[:])
	require.NoError(t, err)

	assert.Error(t, id.Verify(msg, sig))
}

// TestHybridIdentityRejectsASignatureOverTheDigest pins that an ML-DSA signature over the
// SHA-256 digest, which is what signing with the certificate's algorithm would produce, is
// refused.
func TestHybridIdentityRejectsASignatureOverTheDigest(t *testing.T) {
	h := writeHybridMSPDir(t, true)
	thisMSP := getLocalMSPWithVersion(t, h.dir, MSPv3_0Hybrid)
	id, err := thisMSP.DeserializeIdentity(serializeForChainTest(h.pki.leafA))
	require.NoError(t, err)

	msg := []byte("a transaction whose digest was signed")
	digest := sha256.Sum256(msg)
	sig, err := h.pki.leafAAltKey.Sign(rand.Reader, digest[:], nil)
	require.NoError(t, err)

	assert.Error(t, id.Verify(msg, sig))
}

// TestHybridRootRequiresHybridSignatures pins that an MSP rooted at a hybrid CA fails at setup
// without hybrid signatures, instead of failing later on every signature.
func TestHybridRootRequiresHybridSignatures(t *testing.T) {
	h := writeHybridMSPDir(t, true)
	_, err := getLocalMSPWithVersionAndError(t, h.dir, MSPv3_0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "V3_0_HYBRID")
}

// TestHybridIdentityRequiresTheAlternativePrivateKey pins that a hybrid signing identity
// without its ML-DSA private key fails at setup rather than signing with the classical key.
func TestHybridIdentityRequiresTheAlternativePrivateKey(t *testing.T) {
	h := writeHybridMSPDir(t, false)
	_, err := getLocalMSPWithVersionAndError(t, h.dir, MSPv3_0Hybrid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ML-DSA private key")
}

// TestNonHybridIdentitiesUnderHybridSignatures pins that ECDSA and pure ML-DSA identities keep
// signing with the key of their SubjectPublicKeyInfo under hybrid signatures.
func TestNonHybridIdentitiesUnderHybridSignatures(t *testing.T) {
	ecdsaCA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsaCA, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	mldsaSigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	for name, write := range map[string]func(dir string){
		"ECDSA": func(dir string) {
			writeMSPDir(t, dir, ecdsaCA, &ecdsaCA.PublicKey, ecdsaSigner, &ecdsaSigner.PublicKey, nil)
		},
		"ML-DSA": func(dir string) {
			writeMSPDir(t, dir, mldsaCA, mldsaCA.PublicKey(), mldsaSigner, mldsaSigner.PublicKey(), nil)
		},
		"hybrid leaf under a classical root": func(dir string) {
			writeMSPDir(t, dir, ecdsaCA, &ecdsaCA.PublicKey, ecdsaSigner, &ecdsaSigner.PublicKey,
				[]pkix.Extension{altExtension(t, mldsaSigner.PublicKey())})
			altDER, err := x509.MarshalPKCS8PrivateKey(mldsaSigner)
			require.NoError(t, err)
			writePEM(t, filepath.Join(dir, "keystore", "altkey.pem"), "PRIVATE KEY", altDER)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(dir)
			thisMSP := getLocalMSPWithVersion(t, dir, MSPv3_0Hybrid)
			id, err := thisMSP.GetDefaultSigningIdentity()
			require.NoError(t, err)

			msg := []byte("a transaction under hybrid signatures")
			sig, err := id.Sign(msg)
			require.NoError(t, err)
			assert.NoError(t, id.Verify(msg, sig))
		})
	}
}
