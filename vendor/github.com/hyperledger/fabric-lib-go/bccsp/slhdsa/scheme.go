/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

func init() {
	pkixext.Register(scheme{})
}

// scheme is the pure SLH-DSA entry of the pkixext registry.
type scheme struct{}

func (scheme) Name() string {
	return "SLH-DSA"
}

func (scheme) OIDs() []asn1.ObjectIdentifier {
	oids := make([]asn1.ObjectIdentifier, 0, len(parameterSets))
	for _, ps := range parameterSets {
		oids = append(oids, ps.OID)
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

// Verify uses the empty context that RFC 9909 requires for certificates and CRLs.
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
	return AlgorithmIdentifier(pk.ParameterSet)
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
		return nil, errors.Errorf("%T is not an SLH-DSA public key", pub)
	}
	return pk, nil
}

// AlgorithmIdentifier returns the DER AlgorithmIdentifier of the set, with parameters absent as
// RFC 9909 requires.
func AlgorithmIdentifier(ps ParameterSet) ([]byte, error) {
	return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: ps.OID})
}

// SubjectKeyID is the SHA-1 of the raw public key, method 1 of RFC 5280, section 4.2.1.2.
func SubjectKeyID(pub *PublicKey) ([]byte, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(raw)
	return sum[:], nil
}
