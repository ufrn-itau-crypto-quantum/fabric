/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto"
	"encoding/asn1"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

func init() {
	pkixext.Register(scheme{})
}

// scheme is the Composite ML-DSA entry of the pkixext registry. The name is lowercase because it
// fills messages such as "the key of issuer 'X' is not composite".
type scheme struct{}

func (scheme) Name() string {
	return "composite"
}

func (scheme) OIDs() []asn1.ObjectIdentifier {
	oids := make([]asn1.ObjectIdentifier, 0, len(algorithms))
	for _, alg := range algorithms {
		oids = append(oids, alg.OID)
	}
	return oids
}

func (scheme) ParsePKIXPublicKey(spki []byte) (crypto.PublicKey, error) {
	return ParsePKIXPublicKey(spki)
}

func (scheme) MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	pk, err := publicKeyOf(pub)
	if err != nil {
		return nil, err
	}
	return MarshalPKIXPublicKey(pk)
}

func (scheme) ParsePKCS8PrivateKey(der []byte) (crypto.Signer, error) {
	return ParsePKCS8PrivateKey(der)
}

// Verify uses the empty context of certificates and CRLs.
func (scheme) Verify(pub crypto.PublicKey, message, signature []byte) error {
	pk, err := publicKeyOf(pub)
	if err != nil {
		return err
	}
	return Verify(pk, message, signature, nil)
}

func (scheme) AlgorithmIdentifier(pub crypto.PublicKey) ([]byte, error) {
	pk, err := publicKeyOf(pub)
	if err != nil {
		return nil, err
	}
	return AlgorithmIdentifier(pk.Algorithm)
}

func (scheme) SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	pk, err := publicKeyOf(pub)
	if err != nil {
		return nil, err
	}
	return SubjectKeyID(pk)
}

func publicKeyOf(pub crypto.PublicKey) (*PublicKey, error) {
	pk, ok := pub.(*PublicKey)
	if !ok || pk == nil {
		return nil, errors.Errorf("%T is not a Composite ML-DSA public key", pub)
	}
	return pk, nil
}
