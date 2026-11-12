/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
)

// slhdsaOptions maps a BCCSP SignerOpts onto *slhdsa.SignerOpts. An *slhdsa.SignerOpts is passed
// through, so a caller can supply a context string; anything else becomes pure SLH-DSA with an
// empty context.
//
// A hash option such as crypto.SHA256 must not reach slhdsa.PrivateKey.Sign, which rejects
// a non-zero HashFunc: every signature from a BCCSP caller would fail.
func slhdsaOptions(opts bccsp.SignerOpts) *slhdsa.SignerOpts {
	if o, ok := opts.(*slhdsa.SignerOpts); ok && o != nil {
		return o
	}
	return &slhdsa.SignerOpts{}
}

func signSLHDSA(k *slhdsa.PrivateKey, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.Sign(rand.Reader, msg, slhdsaOptions(opts))
}

func verifySLHDSA(k *slhdsa.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	if err := slhdsa.Verify(k, msg, signature, slhdsaOptions(opts).Context); err != nil {
		return false, nil
	}
	return true, nil
}

type slhdsaSigner struct{}

func (s *slhdsaSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signSLHDSA(k.(*slhdsaPrivateKey).privKey, msg, opts)
}

type slhdsaPrivateKeyVerifier struct{}

func (v *slhdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySLHDSA(k.(*slhdsaPrivateKey).privKey.PublicKey(), signature, msg, opts)
}

type slhdsaPublicKeyVerifier struct{}

func (v *slhdsaPublicKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySLHDSA(k.(*slhdsaPublicKey).pubKey, signature, msg, opts)
}

type slhdsaKeyGenerator struct{}

func (kg *slhdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	o, ok := opts.(*bccsp.SLHDSAKeyGenOpts)
	if !ok || o == nil {
		return nil, errors.New("Invalid opts. Expected *bccsp.SLHDSAKeyGenOpts.")
	}
	ps, err := slhdsa.ParameterSetByOID(o.OID)
	if err != nil {
		return nil, err
	}
	privKey, err := slhdsa.GenerateKey(ps)
	if err != nil {
		return nil, fmt.Errorf("Failed generating %s key: [%s]", ps.Name, err)
	}
	return &slhdsaPrivateKey{privKey}, nil
}

type slhdsaPrivateKeyImportOptsKeyImporter struct{}

func (*slhdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SLHDSAPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}
	if len(der) == 0 {
		return nil, errors.New("[SLHDSAPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}
	privKey, err := slhdsa.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKCS#8 to SLH-DSA private key [%s]", err)
	}
	return &slhdsaPrivateKey{privKey}, nil
}

type slhdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*slhdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SLHDSAPKIXPublicKeyImportOpts] Invalid raw material. Expected byte array.")
	}
	if len(der) == 0 {
		return nil, errors.New("[SLHDSAPKIXPublicKeyImportOpts] Invalid raw. It must not be nil.")
	}
	pubKey, err := slhdsa.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SLH-DSA public key [%s]", err)
	}
	return &slhdsaPublicKey{pubKey}, nil
}

type slhdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*slhdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	pubKey, ok := raw.(*slhdsa.PublicKey)
	if !ok || pubKey == nil {
		return nil, errors.New("Invalid raw material. Expected *slhdsa.PublicKey.")
	}
	return &slhdsaPublicKey{pubKey}, nil
}
