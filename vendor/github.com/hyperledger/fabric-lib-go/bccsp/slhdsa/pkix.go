/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package slhdsa

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
)

// ErrNotSLHDSA reports an SPKI or PKCS#8 whose OID is not a pure SLH-DSA OID of this table.
var ErrNotSLHDSA = errors.New("not an SLH-DSA key")

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkcs8PrivateKey is the RFC 5958 OneAsymmetricKey written by this package: version 0, with the
// raw 4n-byte key directly in privateKey and no publicKey field.
type pkcs8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// oneAsymmetricKey is the full RFC 5958 structure accepted on parsing.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue  `asn1:"optional,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,tag:1"`
}

func MarshalPKIXPublicKey(pk *PublicKey) ([]byte, error) {
	raw, err := pk.Bytes()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: pk.ParameterSet.OID},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
}

// ParsePKIXPublicKey returns ErrNotSLHDSA when the OID is not a pure SLH-DSA OID.
func ParsePKIXPublicKey(der []byte) (*PublicKey, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to decode the SubjectPublicKeyInfo")
	}
	if len(rest) != 0 {
		return nil, errors.New("Trailing data after the SubjectPublicKeyInfo")
	}
	ps, err := parameterSetFromIdentifier(spki.Algorithm)
	if err != nil {
		return nil, err
	}
	if spki.PublicKey.BitLength != len(spki.PublicKey.Bytes)*8 {
		return nil, errors.New("SLH-DSA public key is not a whole number of bytes")
	}
	return ParsePublicKey(ps, spki.PublicKey.Bytes)
}

// IsPKIXPublicKey reports whether the SPKI carries a pure SLH-DSA OID, without validating the key.
func IsPKIXPublicKey(der []byte) bool {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return false
	}
	_, err := ParameterSetByOID(spki.Algorithm.Algorithm)
	return err == nil
}

func MarshalPKCS8PrivateKey(sk *PrivateKey) ([]byte, error) {
	raw, err := sk.Bytes()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pkcs8PrivateKey{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: sk.ParameterSet.OID},
		PrivateKey: raw,
	})
}

// ParsePKCS8PrivateKey returns ErrNotSLHDSA when the OID is not a pure SLH-DSA OID.
//
// Both versions of OneAsymmetricKey are accepted. When the optional publicKey field is present it
// must match the PK.seed || PK.root embedded in the private key.
func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var key oneAsymmetricKey
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to decode the PKCS#8 private key")
	}
	if len(rest) != 0 {
		return nil, errors.New("Trailing data after the PKCS#8 private key")
	}
	ps, err := parameterSetFromIdentifier(key.Algorithm)
	if err != nil {
		return nil, err
	}
	if key.Version != 0 && key.Version != 1 {
		return nil, errors.Errorf("Unsupported PKCS#8 version %d for an SLH-DSA key", key.Version)
	}
	sk, err := ParsePrivateKey(ps, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(key.PublicKey.Bytes) != 0 {
		pub, err := sk.PublicKey().Bytes()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pub, key.PublicKey.Bytes) {
			return nil, errors.New("PKCS#8 publicKey does not match the SLH-DSA private key")
		}
	}
	return sk, nil
}

// parameterSetFromIdentifier rejects an AlgorithmIdentifier with parameters present, as RFC 9909
// requires them to be absent.
func parameterSetFromIdentifier(ai pkix.AlgorithmIdentifier) (ParameterSet, error) {
	ps, err := ParameterSetByOID(ai.Algorithm)
	if err != nil {
		return ParameterSet{}, ErrNotSLHDSA
	}
	if len(ai.Parameters.FullBytes) != 0 {
		return ParameterSet{}, errors.Errorf("SLH-DSA algorithm identifier %s must not carry parameters", ai.Algorithm)
	}
	return ps, nil
}
