/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

// A single pair of types covers all three parameter sets: crypto/mldsa carries the security
// category in the key itself, reachable through PublicKey.Parameters().

type mldsaPrivateKey struct {
	privKey *mldsa.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
// In the mldsa case, it isn't allowed because the Bytes function returns the seed, and not it bytes
func (k *mldsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
//
// It hashes the public key, so that a private key and its public key share the same SKI: the
// keystore relies on that to find a private key from the public key in a certificate.
func (k *mldsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	raw := k.privKey.PublicKey().Bytes()

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *mldsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *mldsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mldsaPrivateKey) PublicKey() (bccsp.Key, error) {
	if k.privKey == nil {
		return nil, errors.New("Error casting ML-DSA public key")
	}
	return &mldsaPublicKey{k.privKey.PublicKey()}, nil
}

type mldsaPublicKey struct {
	pubKey *mldsa.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *mldsaPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *mldsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	raw := k.pubKey.Bytes()

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *mldsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *mldsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mldsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
