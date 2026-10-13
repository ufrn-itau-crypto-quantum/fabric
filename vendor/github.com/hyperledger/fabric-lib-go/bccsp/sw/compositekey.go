/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
)

type compositePrivateKey struct {
	privKey *composite.PrivateKey
}

// Bytes devolve erro, porque a chave privada não é exportada.
func (k *compositePrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI devolve o identificador da chave, calculado a partir da chave pública.
func (k *compositePrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	return compositeSKI(k.privKey.PublicKey())
}

func (k *compositePrivateKey) Symmetric() bool {
	return false
}

func (k *compositePrivateKey) Private() bool {
	return true
}

func (k *compositePrivateKey) PublicKey() (bccsp.Key, error) {
	if k.privKey == nil {
		return nil, errors.New("Error casting Composite ML-DSA public key")
	}
	return &compositePublicKey{k.privKey.PublicKey()}, nil
}

type compositePublicKey struct {
	pubKey *composite.PublicKey
}

// Bytes devolve o SubjectPublicKeyInfo DER.
func (k *compositePublicKey) Bytes() ([]byte, error) {
	return composite.MarshalPKIXPublicKey(k.pubKey)
}

func (k *compositePublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	return compositeSKI(k.pubKey)
}

func (k *compositePublicKey) Symmetric() bool {
	return false
}

func (k *compositePublicKey) Private() bool {
	return false
}

func (k *compositePublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

// compositeSKI calcula o SHA-256 da chave pública composta bruta.
func compositeSKI(pub *composite.PublicKey) []byte {
	raw, err := pub.Bytes()
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}
