/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/mldsa"
	"crypto/rand"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

// mldsaOptions maps a BCCSP SignerOpts onto the options crypto/mldsa expects. An
// *mldsa.Options is passed through untouched, so a caller can supply a context string.
//
// A hash option such as &bccsp.SHA256Opts{} is mapped to pure ML-DSA: mldsa.PrivateKey.Sign
// rejects any SignerOpts whose HashFunc is not zero, which would otherwise fail every
// signature from a BCCSP caller.
func mldsaOptions(opts bccsp.SignerOpts) *mldsa.Options {
	if mlopts, ok := opts.(*mldsa.Options); ok {
		return mlopts
	}
	return &mldsa.Options{}
}

func signMLDSA(k *mldsa.PrivateKey, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.Sign(rand.Reader, msg, mldsaOptions(opts))
}

func verifyMLDSA(k *mldsa.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	if err := mldsa.Verify(k, msg, signature, mldsaOptions(opts)); err != nil {
		return false, nil
	}
	return true, nil
}

type mldsaSigner struct{}

func (s *mldsaSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signMLDSA(k.(*mldsaPrivateKey).privKey, msg, opts)
}

type mldsaPrivateKeyVerifier struct{}

func (v *mldsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyMLDSA(k.(*mldsaPrivateKey).privKey.PublicKey(), signature, msg, opts)
}

type mldsaPublicKeyKeyVerifier struct{}

func (v *mldsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyMLDSA(k.(*mldsaPublicKey).pubKey, signature, msg, opts)
}
