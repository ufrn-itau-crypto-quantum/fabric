/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
)

// ErrNotComposite indica um SPKI ou PKCS#8 cujo OID não é de um par composite desta tabela.
var ErrNotComposite = errors.New("not a Composite ML-DSA key")

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkcs8PrivateKey é o OneAsymmetricKey versão 0 da RFC 5958; o privateKey leva o sk bruto da seção 4.2.
type pkcs8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func MarshalPKIXPublicKey(pk *PublicKey) ([]byte, error) {
	raw, err := pk.Bytes()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: pk.Algorithm.OID},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
}

// ParsePKIXPublicKey devolve ErrNotComposite quando o OID não é composite.
func ParsePKIXPublicKey(der []byte) (*PublicKey, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to decode the SubjectPublicKeyInfo")
	}
	if len(rest) != 0 {
		return nil, errors.New("Trailing data after the SubjectPublicKeyInfo")
	}
	alg, err := algorithmFromIdentifier(spki.Algorithm)
	if err != nil {
		return nil, err
	}
	if spki.PublicKey.BitLength != len(spki.PublicKey.Bytes)*8 {
		return nil, errors.New("Composite ML-DSA public key is not a whole number of bytes")
	}
	return ParsePublicKey(alg, spki.PublicKey.Bytes)
}

// IsPKIXPublicKey informa se o SPKI traz um OID composite desta tabela, sem validar a chave.
func IsPKIXPublicKey(der []byte) bool {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return false
	}
	_, err := AlgorithmByOID(spki.Algorithm.Algorithm)
	return err == nil
}

func MarshalPKCS8PrivateKey(sk *PrivateKey) ([]byte, error) {
	raw, err := sk.Bytes()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pkcs8PrivateKey{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: sk.Algorithm.OID},
		PrivateKey: raw,
	})
}

// ParsePKCS8PrivateKey devolve ErrNotComposite quando o OID não é composite.
func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var key pkcs8PrivateKey
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to decode the PKCS#8 private key")
	}
	if len(rest) != 0 {
		return nil, errors.New("Trailing data after the PKCS#8 private key")
	}
	alg, err := algorithmFromIdentifier(key.Algorithm)
	if err != nil {
		return nil, err
	}
	if key.Version != 0 {
		return nil, errors.Errorf("Unsupported PKCS#8 version %d for a Composite ML-DSA key", key.Version)
	}
	return ParsePrivateKey(alg, key.PrivateKey)
}

// algorithmFromIdentifier devolve o par do OID e recusa o campo parameters presente.
func algorithmFromIdentifier(ai pkix.AlgorithmIdentifier) (Algorithm, error) {
	alg, err := AlgorithmByOID(ai.Algorithm)
	if err != nil {
		return Algorithm{}, ErrNotComposite
	}
	if len(ai.Parameters.FullBytes) != 0 {
		return Algorithm{}, errors.Errorf("Composite ML-DSA algorithm identifier %s must not carry parameters", ai.Algorithm)
	}
	return alg, nil
}
