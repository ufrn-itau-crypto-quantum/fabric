/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
)

type slhdsaPrivateKey struct {
	privKey *slhdsa.PrivateKey
}

// Bytes returns an error: the private key is not exported.
func (k *slhdsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

func (k *slhdsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	return slhdsaSKI(k.privKey.PublicKey())
}

func (k *slhdsaPrivateKey) Symmetric() bool {
	return false
}

func (k *slhdsaPrivateKey) Private() bool {
	return true
}

func (k *slhdsaPrivateKey) PublicKey() (bccsp.Key, error) {
	if k.privKey == nil {
		return nil, errors.New("Error casting SLH-DSA public key")
	}
	return &slhdsaPublicKey{k.privKey.PublicKey()}, nil
}

type slhdsaPublicKey struct {
	pubKey *slhdsa.PublicKey
}

// Bytes returns the SubjectPublicKeyInfo DER.
func (k *slhdsaPublicKey) Bytes() ([]byte, error) {
	return slhdsa.MarshalPKIXPublicKey(k.pubKey)
}

func (k *slhdsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	return slhdsaSKI(k.pubKey)
}

func (k *slhdsaPublicKey) Symmetric() bool {
	return false
}

func (k *slhdsaPublicKey) Private() bool {
	return false
}

func (k *slhdsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

// slhdsaSKI hashes the raw public key with SHA-256. Private and public keys must share this value:
// the keystore finds a private key through the SKI of the public key in a certificate.
func slhdsaSKI(pub *slhdsa.PublicKey) []byte {
	raw, err := pub.Bytes()
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}
