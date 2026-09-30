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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLDSAIdentity covers an MSP set up with material a fabric-ca in "mldsa" mode issues:
// the SubjectPublicKeyInfo is an ML-DSA key, so the algorithm gate has to admit it and the
// signing path has to sign the message rather than a digest.
func TestMLDSAIdentity(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			dir := t.TempDir()
			caKey, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			signerKey, err := mldsa.GenerateKey(params)
			require.NoError(t, err)

			writeMSPDir(t, dir, caKey, caKey.PublicKey(), signerKey, signerKey.PublicKey(), nil)

			thisMSP := getLocalMSPWithVersion(t, dir, MSPv3_0)
			id, err := thisMSP.GetDefaultSigningIdentity()
			require.NoError(t, err, "an ML-DSA identity must be usable")

			require.NoError(t, thisMSP.Validate(id.GetPublicVersion()), "the algorithm gate must admit ML-DSA")

			msg := []byte("a message signed by an ML-DSA identity")
			sig, err := id.Sign(msg)
			require.NoError(t, err)
			assert.NoError(t, id.Verify(msg, sig))

			// The signature must be over the message itself. Verifying it directly with
			// crypto/mldsa is what pins that: a signature over a digest would not verify.
			assert.NoError(t, mldsa.Verify(signerKey.PublicKey(), msg, sig, nil),
				"ML-DSA must sign the full message, not a digest")

			assert.Error(t, id.Verify([]byte("another message"), sig))
		})
	}
}

// TestHybridIdentity covers the other fabric-ca mode: a classical SubjectPublicKeyInfo with
// the ML-DSA public key in the altSubjectPublicKeyInfo extension. It must be accepted, and the
// extension must be readable.
func TestHybridIdentity(t *testing.T) {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	signerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	altKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	altExt := altExtension(t, altKey.PublicKey())
	writeMSPDir(t, dir, caKey, &caKey.PublicKey, signerKey, &signerKey.PublicKey, []pkix.Extension{altExt})

	thisMSP := getLocalMSPWithVersion(t, dir, MSPv3_0)
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err, "a hybrid identity must be usable")
	require.NoError(t, thisMSP.Validate(id.GetPublicVersion()))

	// The identity still authenticates with the classical key.
	msg := []byte("a message signed by a hybrid identity")
	sig, err := id.Sign(msg)
	require.NoError(t, err)
	assert.NoError(t, id.Verify(msg, sig))

	// And the post-quantum key is reachable from the certificate.
	cert := id.(*signingidentity).identity.cert
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
	pub, found, err := altPublicKeyFromCert(cert)
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, altKey.PublicKey().Equal(pub))
}

// TestHybridIdentityRejectsMalformedAltKey pins that a certificate carrying an unusable
// alternative public key is refused rather than silently treated as classical.
func TestHybridIdentityRejectsMalformedAltKey(t *testing.T) {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	signerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	badExt := pkix.Extension{Id: oidAltSubjectPublicKeyInfo, Value: []byte("not a SubjectPublicKeyInfo")}
	writeMSPDir(t, dir, caKey, &caKey.PublicKey, signerKey, &signerKey.PublicKey, []pkix.Extension{badExt})

	_, err = getLocalMSPWithVersionAndError(t, dir, MSPv3_0)
	require.Error(t, err, "a malformed alternative public key must be rejected")
	assert.Contains(t, err.Error(), "alternative public key")
}

// TestMLDSAIdentityRejectedBeforeV3 pins that admitting ML-DSA is a v3 behaviour, like
// Ed25519 before it.
func TestMLDSAIdentityRejectedBeforeV3(t *testing.T) {
	dir := t.TempDir()
	caKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	signerKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	writeMSPDir(t, dir, caKey, caKey.PublicKey(), signerKey, signerKey.PublicKey(), nil)

	thisMSP, err := getLocalMSPWithVersionAndError(t, dir, MSPv1_4_3)
	if err != nil {
		return // rejected at setup, which is also an acceptable outcome
	}
	id, err := thisMSP.GetDefaultSigningIdentity()
	require.NoError(t, err)
	assert.Error(t, thisMSP.Validate(id.GetPublicVersion()), "MSPv1_4_3 must not admit ML-DSA")
}

func altExtension(t *testing.T, pub *mldsa.PublicKey) pkix.Extension {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pkix.Extension{Id: oidAltSubjectPublicKeyInfo, Value: spki}
}

// writeMSPDir lays out a minimal local MSP: a self-signed CA, one signing identity issued by
// it, and the identity's private key in the keystore.
func writeMSPDir(t *testing.T, dir string, caPriv crypto.Signer, caPub any, signerPriv crypto.Signer, signerPub any, exts []pkix.Extension) {
	t.Helper()

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mldsa-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "mldsa-test-identity"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, signerPub, caPriv)
	require.NoError(t, err)

	writePEM(t, filepath.Join(dir, "cacerts", "cacert.pem"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(dir, "signcerts", "cert.pem"), "CERTIFICATE", leafDER)
	// Without NodeOUs an MSP must declare its administrators explicitly.
	writePEM(t, filepath.Join(dir, "admincerts", "admincert.pem"), "CERTIFICATE", leafDER)

	keyDER, err := x509.MarshalPKCS8PrivateKey(signerPriv)
	require.NoError(t, err)
	writePEM(t, filepath.Join(dir, "keystore", "key.pem"), "PRIVATE KEY", keyDER)
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
}
